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

	"github.com/uQUIC/XGFW/operation/protocol"
	"github.com/uQUIC/XGFW/operation/protocol/internal"
	"github.com/uQUIC/XGFW/operation/protocol/udp/internal/quic"
	"github.com/uQUIC/XGFW/operation/protocol/utils"
)

// 常量定义
const (
	minDataSize           = 41

	testPortCount      = 10
	serverPortMin      = 20000
	serverPortMax      = 50000
	highTrafficBytes   = 500 * 1024 * 1024 / 8 // 500 Mb = 62.5 MB
	tenMinutes         = 10 * time.Minute
	dnsServer          = "1.1.1.1:53"
	dnsTimeout         = 5 * time.Second
	portRequestTimeout = 1 * time.Second
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
	// 从 info 中获取服务器 IP 和端口（假设 info 有 DstIP, DstPort）
	serverIP := info.DstIP.String()
	serverPort := int(info.DstPort) // 将 uint16 转换为 int

	return &hysteria2Stream{
		logger:        logger,
		startTime:     time.Now(),
		serverIP:      serverIP,
		serverPort:    serverPort,
		closeComplete: make(chan struct{}),
		randGen:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// hysteria2Stream 实现 analyzer.UDPStream 接口
type hysteria2Stream struct {
	logger      analyzer.Logger
	packetCount int
	totalBytes  int
	startTime   time.Time
	sni         string

	serverIP   string
	serverPort int

	mutex          sync.Mutex
	blocked        bool
	randGen        *rand.Rand
	closeOnce      sync.Once
	closeComplete chan struct{}
}

// Feed 处理每个UDP包
func (s *hysteria2Stream) Feed(rev bool, data []byte) (*analyzer.PropUpdate, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 如果已经封锁，立即返回封锁状态
	if s.blocked {
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"blocked": true,
				"reason":  "hysteria-detected",
			},
		}, true
	}

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

	// 提取 SNI
	// 假设 m 是 analyzer.PropMap，且包含 "ServerName" 键
	serverNameRaw, ok := m["ServerName"]
	if !ok {
		return nil, false
	}

	serverName, ok := serverNameRaw.(string)
	if !ok {
		return nil, false
	}

	s.sni = serverName

	// 检查是否需要进行封锁
	go s.checkAndBlockIfNecessary()

	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateMerge,
		M:    analyzer.PropMap{"req": m},
	}, true
}

// Close 在连接结束时进行判断和可能的封锁
func (s *hysteria2Stream) Close(limited bool) *analyzer.PropUpdate {
	s.closeOnce.Do(func() {
		close(s.closeComplete)
	})

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.blocked {
		// 已封锁，无需额外处理
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"blocked": true,
				"reason":  "hysteria-detected",
			},
		}
	}

	// 未触发封锁条件，返回连接的统计信息
	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M: analyzer.PropMap{
			"packetCount":    s.packetCount,
			"totalBytes":     s.totalBytes,
			"elapsedSeconds": time.Since(s.startTime).Seconds(),
			"sni":            s.sni,
			"blocked":        false,
		},
	}
}

// checkAndBlockIfNecessary 检查连接是否满足封锁条件，并执行封锁
func (s *hysteria2Stream) checkAndBlockIfNecessary() {
	s.mutex.Lock()
	// 检查是否已封锁
	if s.blocked {
		s.mutex.Unlock()
		return
	}
	// 检查连接时长和总流量
	elapsed := time.Since(s.startTime)
	if elapsed < tenMinutes || s.totalBytes < highTrafficBytes {
		s.mutex.Unlock()
		return
	}
	s.mutex.Unlock()

	// 满足时间和流量条件，执行检测逻辑
	returnSingle, err := checkServerResponses(s.serverIP, s.randGen)
	if err != nil {
		s.logger.Errorf("Server response check failed: %v", err)
		return
	}

	if returnSingle {
		// 执行DNS查询
		dnsIPs, err := resolveDNS(s.sni)
		if err != nil {
			s.logger.Errorf("DNS resolution failed: %v", err)
			return
		}

		if !contains(dnsIPs, s.serverIP) {
			// 判定为Hysteria2，封锁连接
			s.mutex.Lock()
			if !s.blocked {
				s.blocked = true
			}
			s.mutex.Unlock()

			s.logger.Infof("Hysteria2 detected for SNI: %s, IP: %s", s.sni, s.serverIP)

			// 由于无法直接发送 PropUpdate，设置 blocked 标志以便在下一次 Feed 或 Close 时返回封锁状态
		}
	}
}

// checkServerResponses 检查服务器 20000-50000 端口中任意10个端口的响应内容是否返回单一
func checkServerResponses(ip string, randGen *rand.Rand) (bool, error) {
	ports, err := selectRandomPorts(serverPortMin, serverPortMax, testPortCount, randGen)
	if err != nil {
		return false, err
	}

	var wg sync.WaitGroup
	responseChan := make(chan string, testPortCount)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			resp, err := sendUDPRequest(ip, p, []byte("test"))
			if err != nil {
				// 忽略错误，因为某些端口可能不响应
				return
			}
			responseChan <- resp
		}(port)
	}

	wg.Wait()
	close(responseChan)

	// 收集响应
	responses := make([]string, 0, testPortCount)
	for resp := range responseChan {
		responses = append(responses, resp)
	}

	// 统计响应出现次数
	counts := make(map[string]int)
	for _, r := range responses {
		counts[r]++
	}

	// 检查是否有 >=7 个相同响应
	for _, count := range counts {
		if count >= 7 {
			return true, nil
		}
	}

	return false, nil
}

// selectRandomPorts 随机选择指定范围内的n个不同端口
func selectRandomPorts(min, max, n int, randGen *rand.Rand) ([]int, error) {
	if max < min || n <= 0 || (max-min+1) < n {
		return nil, errors.New("invalid port range or count")
	}

	ports := make(map[int]struct{})
	for len(ports) < n {
		p := randGen.Intn(max-min+1) + min
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

// resolveDNS 使用指定的DNS服务器解析SNI
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

// contains 检查字符串切片中是否包含指定字符串
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.TrimSpace(s) == strings.TrimSpace(item) {
			return true
		}
	}
	return false
}
