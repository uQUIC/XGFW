package udp

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/uQUIC/XGFW/analyzer"
	"github.com/uQUIC/XGFW/analyzer/internal"
	"github.com/uQUIC/XGFW/analyzer/udp/internal/quic"
	"github.com/uQUIC/XGFW/analyzer/utils"
)

// 常量定义
const (
	invalidCountThreshold = 4
	minDataSize           = 41

	testPortCount      = 10
	serverPortMin      = 20000
	serverPortMax      = 50000
	highBandwidthBps   = 100_000_000 // 100 Mbps in bits per second
	twentyMinutes      = 20 * time.Minute
	dnsServer           = "1.1.1.1:53"
	dnsTimeout          = 5 * time.Second
	portRequestTimeout  = 1 * time.Second
	maxConcurrentPorts  = 100 // 防止端口选择过于集中
)

// 确保接口实现
var (
	_ analyzer.UDPAnalyzer = (*Hysteria2Analyzer)(nil)
	_ analyzer.UDPStream   = (*hysteria2Stream)(nil)
)

// Hysteria2Analyzer 实现 analyzer.UDPAnalyzer 接口
type Hysteria2Analyzer struct{}

// Name 返回分析器名称
func (a *Hysteria2Analyzer) Name() string {
	return "hysteria2-detector"
}

// Limit 返回连接限制，0表示无限制
func (a *Hysteria2Analyzer) Limit() int {
	return 0
}

// NewUDP 创建新的 UDP 流
func (a *Hysteria2Analyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return &hysteria2Stream{
		logger:     logger,
		startTime:  time.Now(),
		serverAddr: info.ServerAddr,
	}
}

// hysteria2Stream 实现 analyzer.UDPStream 接口
type hysteria2Stream struct {
	logger      analyzer.Logger
	packetCount int
	totalBytes  int
	startTime   time.Time

	sni           string
	sniExtracted  bool
	sniChanged    bool
	initialSNI    string
	serverIP      string
	serverAddr    net.Addr
	mutex         sync.Mutex
	closeOnce     sync.Once
	closeComplete chan struct{}
}

// Feed 处理每个UDP包
func (s *hysteria2Stream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.packetCount++
	s.totalBytes += len(data)

	if rev {
		// 不支持服务器方向的流量，计数无效包
		return nil, false
	}

	// 解析 QUIC ClientHello 以获取 SNI
	pl, err := quic.ReadCryptoPayload(data)
	if err != nil || len(pl) < 4 {
		return nil, false
	}

	// 判断是否 ClientHello 类型
	if pl[0] != internal.TypeClientHello {
		return nil, false
	}

	chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
	if chLen < minDataSize {
		return nil, false
	}

	m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
	if m == nil {
		return nil, false
	}

	// 提取 SNI
	currentSNI := m.ServerName
	if !s.sniExtracted {
		s.initialSNI = currentSNI
		s.sniExtracted = true
		// 提取服务器IP
		host, _, err := net.SplitHostPort(s.serverAddr.String())
		if err == nil {
			ips, err := net.LookupIP(host)
			if err == nil && len(ips) > 0 {
				s.serverIP = ips[0].String()
			}
		}
	} else {
		if s.initialSNI != currentSNI {
			s.sniChanged = true
		}
	}
	s.sni = currentSNI

	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateMerge,
		M:    analyzer.PropMap{"req": m},
	}, true
}

// Close 在连接结束时进行判断和封锁
func (s *hysteria2Stream) Close(limited bool) *analyzer.PropUpdate {
	s.closeOnce.Do(func() {
		close(s.closeComplete)
	})

	s.mutex.Lock()
	defer s.mutex.Unlock()

	elapsed := time.Since(s.startTime)
	if elapsed >= twentyMinutes && s.totalBytes > 0 {
		// 计算带宽（bps）
		bandwidthBps := float64(s.totalBytes*8) / elapsed.Seconds()
		if bandwidthBps > float64(highBandwidthBps) && !s.sniChanged && s.sni != "" && s.serverIP != "" {
			// 执行服务器响应内容分析
			returnSingle, err := checkServerResponses(s.serverIP)
			if err != nil {
				s.logger.Errorf("Server response check failed: %v", err)
			} else if returnSingle {
				// 发起DNS请求
				dnsIPs, err := resolveDNS(s.sni)
				if err != nil {
					s.logger.Errorf("DNS resolution failed: %v", err)
				} else {
					if !contains(dnsIPs, s.serverIP) {
						// 判定为Hysteria2，封锁
						s.logger.Infof("Hysteria2 detected for SNI: %s, IP: %s", s.sni, s.serverIP)
						// 返回封锁信息
						u = &analyzer.PropUpdate{
							Type: analyzer.PropUpdateReplace,
							M: analyzer.PropMap{
								"blocked":        true,
								"reason":         "hysteria-detected",
								"packetCount":    s.packetCount,
								"totalBytes":     s.totalBytes,
								"elapsedSeconds": elapsed.Seconds(),
								"sni":            s.sni,
							},
						}
						return
					}
				}
			}
		}
	}

	// 未触发封锁条件
	u = &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M: analyzer.PropMap{
			"packetCount":    s.packetCount,
			"totalBytes":     s.totalBytes,
			"elapsedSeconds": elapsed.Seconds(),
			"sni":            s.sni,
			"blocked":        false,
		},
	}

	return u
}

// checkServerResponses 检查服务器20000-50000端口中任意10个端口的响应内容是否返回单一
func checkServerResponses(ip string) (bool, error) {
	ports, err := selectRandomPorts(serverPortMin, serverPortMax, testPortCount)
	if err != nil {
		return false, err
	}

	responses := make([]string, 0, testPortCount)
	var wg sync.WaitGroup
	responseChan := make(chan string, testPortCount)
	errChan := make(chan error, testPortCount)

	// 并发发送UDP请求
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			resp, err := sendUDPRequest(ip, p, []byte("test"))
			if err != nil {
				errChan <- err
				return
			}
			responseChan <- resp
		}(port)
	}

	wg.Wait()
	close(responseChan)
	close(errChan)

	// 收集响应
	for resp := range responseChan {
		responses = append(responses, resp)
	}

	// 检查是否有 >=7 个相同的响应
	counts := make(map[string]int)
	for _, r := range responses {
		counts[r]++
	}

	for _, count := range counts {
		if count >= 7 {
			return true, nil
		}
	}

	return false, nil
}

// selectRandomPorts 随机选择指定范围内的n个端口
func selectRandomPorts(min, max, n int) ([]int, error) {
	if max < min || n <= 0 || max-min+1 < n {
		return nil, errors.New("invalid port range or count")
	}

	ports := make(map[int]struct{})
	rand.Seed(time.Now().UnixNano())
	for len(ports) < n {
		p := rand.Intn(max-min+1) + min
		ports[p] = struct{}{}
	}

	selected := make([]int, 0, n)
	for p := range ports {
		selected = append(selected, p)
	}

	return selected, nil
}

// sendUDPRequest 向指定IP和端口发送UDP请求并等待响应
func sendUDPRequest(ip string, port int, message []byte) (string, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", addr, portRequestTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// 设置写入超时
	conn.SetWriteDeadline(time.Now().Add(portRequestTimeout))
	_, err = conn.Write(message)
	if err != nil {
		return "", err
	}

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(portRequestTimeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}

	return string(buf[:n]), nil
}

// resolveDNS 向1.1.1.1发起DNS请求，解析SNI域名
func resolveDNS(sni string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: dnsTimeout,
			}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	ips, err := r.LookupHost(ctx, sni)
	if err != nil {
		return nil, err
	}

	return ips, nil
}

// contains 检查slice中是否包含指定元素
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.TrimSpace(s) == strings.TrimSpace(item) {
			return true
		}
	}
	return false
}
