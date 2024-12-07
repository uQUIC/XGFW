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

// 假设的阈值和参数
const (
	invalidCountThreshold = 4
	minDataSize           = 41

	testPortCount     = 10
	serverPortMin     = 20000
	serverPortMax     = 50000
	highBandwidthBps  = 100_000_000 // 100 Mbps
	twentyMinutes      = 20 * time.Minute
	dnsServer          = "1.1.1.1:53"
	dnsTimeout         = 5 * time.Second
	portRequestTimeout = 1 * time.Second
)

// 假设 internal.ParseTLSClientHelloMsgData 返回的结构，其中含有 ServerName 字段
// 实际需根据 internal 包的定义进行相应调整
// 此处仅作示意：
/*
package internal
type ClientHelloMsg struct {
	ServerName string
	// ...其他字段
}
*/

// 确保接口实现
var (
	_ analyzer.UDPAnalyzer = (*Hysteria2Analyzer)(nil)
	_ analyzer.UDPStream   = (*hysteria2Stream)(nil)
)

type Hysteria2Analyzer struct{}

func (a *Hysteria2Analyzer) Name() string {
	return "hysteria2-detector"
}

func (a *Hysteria2Analyzer) Limit() int {
	return 0
}

func (a *Hysteria2Analyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	// 从 info 中获取服务器 IP 和 端口（假设 info 有 DstIP, DstPort）
	serverIP := info.DstIP.String()
	serverPort := info.DstPort

	return &hysteria2Stream{
		logger:     logger,
		startTime:  time.Now(),
		serverIP:   serverIP,
		serverPort: serverPort,
	}
}

type hysteria2Stream struct {
	logger       analyzer.Logger
	packetCount  int
	totalBytes   int
	startTime    time.Time
	sni          string
	sniExtracted bool
	sniChanged   bool
	initialSNI   string

	serverIP   string
	serverPort int

	mutex sync.Mutex
}

// Feed 处理每个UDP包
func (s *hysteria2Stream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.packetCount++
	s.totalBytes += len(data)

	if rev {
		// 如果不分析服务器方向的包，可以忽略或统计无效包
		return nil, false
	}

	// 尝试解析 QUIC ClientHello 以获取 SNI
	pl, err := quic.ReadCryptoPayload(data)
	if err != nil || len(pl) < 4 {
		return nil, false
	}

	// 检查是否为 ClientHello 类型
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

	serverName := m.ServerName
	if !s.sniExtracted {
		s.initialSNI = serverName
		s.sniExtracted = true
	} else {
		if s.initialSNI != serverName {
			s.sniChanged = true
		}
	}
	s.sni = serverName

	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateMerge,
		M:    analyzer.PropMap{"req": m},
	}, true
}

// Close 在连接结束时进行判断和可能的封锁
func (s *hysteria2Stream) Close(limited bool) *analyzer.PropUpdate {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	elapsed := time.Since(s.startTime)
	// 判断条件：连接 >20分钟, 带宽 >100Mbps, SNI未变化
	if elapsed >= twentyMinutes && s.totalBytes > 0 && !s.sniChanged && s.sni != "" && s.serverIP != "" {
		// 计算带宽 bps
		bandwidthBps := float64(s.totalBytes*8) / elapsed.Seconds()
		if bandwidthBps > highBandwidthBps {
			// 检查服务器响应内容
			returnSingle, err := checkServerResponses(s.serverIP)
			if err == nil && returnSingle {
				// DNS查询 SNI
				dnsIPs, err := resolveDNS(s.sni)
				if err == nil {
					// 若DNS结果不包含 serverIP，则判断为Hysteria2
					if !contains(dnsIPs, s.serverIP) {
						s.logger.Infof("Hysteria2 detected for SNI: %s, IP: %s", s.sni, s.serverIP)
						return &analyzer.PropUpdate{
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
					}
				}
			}
		}
	}

	// 未触发封锁条件
	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M: analyzer.PropMap{
			"packetCount":    s.packetCount,
			"totalBytes":     s.totalBytes,
			"elapsedSeconds": elapsed.Seconds(),
			"sni":            s.sni,
			"blocked":        false,
		},
	}
}

// checkServerResponses 检查服务器 20000-50000 端口中任意10个端口的响应内容是否返回单一
func checkServerResponses(ip string) (bool, error) {
	ports, err := selectRandomPorts(serverPortMin, serverPortMax, testPortCount)
	if err != nil {
		return false, err
	}

	var wg sync.WaitGroup
	responseChan := make(chan string, testPortCount)
	errChan := make(chan error, testPortCount)

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
	responses := make([]string, 0, testPortCount)
	for resp := range responseChan {
		responses = append(responses, resp)
	}

	// 统计出现次数
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

// selectRandomPorts 随机选择指定范围内的n个不同端口
func selectRandomPorts(min, max, n int) ([]int, error) {
	if max < min || n <= 0 || (max-min+1) < n {
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

	conn.SetWriteDeadline(time.Now().Add(portRequestTimeout))
	if _, err = conn.Write(message); err != nil {
		return "", err
	}

	conn.SetReadDeadline(time.Now().Add(portRequestTimeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}

	return string(buf[:n]), nil
}

// resolveDNS 使用指定的DNS服务器解析SNI
func resolveDNS(sni string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: dnsTimeout}
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

// contains 检查字符串切片中是否包含指定字符串
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.TrimSpace(s) == strings.TrimSpace(item) {
			return true
		}
	}
	return false
}
