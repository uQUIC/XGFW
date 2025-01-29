package udp

import (
    "errors"
    "fmt"
    "math/rand"
    "net"
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
    portRequestTimeout = 1 * time.Second
)

// 确保接口实现
var (
    _ analyzer.UDPAnalyzer = (*Hysteria2Analyzer)(nil)
    _ analyzer.UDPStream   = (*hysteria2Stream)(nil)
)

// Hysteria2Analyzer 实现 analyzer.UDPAnalyzer 接口
type Hysteria2Analyzer struct{}

func (a *Hysteria2Analyzer) Name() string {
    return "hysteria2-detector"
}

func (a *Hysteria2Analyzer) Limit() int {
    return 0
}

func (a *Hysteria2Analyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
    serverIP := info.DstIP.String()
    serverPort := int(info.DstPort)

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
    logger       analyzer.Logger
    packetCount  int
    totalBytes   int
    startTime    time.Time
    sni          string
    serverIP     string
    serverPort   int
    mutex        sync.Mutex
    blocked      bool
    randGen      *rand.Rand
    closeOnce    sync.Once
    closeComplete chan struct{}
}

// Feed 处理每个UDP包
func (s *hysteria2Stream) Feed(rev bool, data []byte) (*analyzer.PropUpdate, bool) {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    // 如果已经封锁，立刻返回封锁属性
    if s.blocked {
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "blocked": true,
                "reason":  "hysteria-detected",
            },
        }, true
    }

    // --------------------------
    // 1) 调用 QUIC 检测函数
    // --------------------------
    if !s.isQUIC(data) {
        // 如果不是 QUIC 流量，直接返回
        return nil, false
    }

    // 统计包数和流量
    s.packetCount++
    s.totalBytes += len(data)

    // 不分析服务端->客户端方向可以跳过
    if rev {
        return nil, false
    }

    // --------------------------
    // 2) 解析 QUIC ClientHello
    // --------------------------
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
    serverNameRaw, ok := m["ServerName"]
    if ok {
        if sn, ok2 := serverNameRaw.(string); ok2 {
            s.sni = sn
        }
    }

    // --------------------------
    // 3) 立即检查是否满足封锁条件
    // --------------------------
    //   （和原代码不同：我们在此同步调用，而非goroutine）
    blockedNow := s.checkAndBlockIfNecessary()
    if blockedNow {
        // 如果此刻判断为要封锁，立刻返回对应属性
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "blocked": true,
                "reason":  "hysteria-detected",
            },
        }, true
    }

    // --------------------------
    // 4) 如果还没 block，则把解析到的 ClientHello 内容合并上报
    // --------------------------
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateMerge,
        M:    analyzer.PropMap{"req": m}, // 仅供其他规则或日志使用
    }, true
}

// isQUIC 检测流量是否为 QUIC 流量
func (s *hysteria2Stream) isQUIC(data []byte) bool {
    const quicInvalidCountThreshold = 4
    invalidCount := 0

    pl, err := quic.ReadCryptoPayload(data)
    if err != nil || len(pl) < 4 {
        invalidCount++
        return invalidCount < quicInvalidCountThreshold
    }

    if pl[0] != internal.TypeClientHello {
        invalidCount++
        return invalidCount < quicInvalidCountThreshold
    }

    chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
    if chLen < minDataSize {
        invalidCount++
        return invalidCount < quicInvalidCountThreshold
    }

    m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
    if m == nil {
        invalidCount++
        return invalidCount < quicInvalidCountThreshold
    }

    return true
}

// Close 在流结束时再返回统计信息或者已封锁信息
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

    // 未被封锁，返回统计信息
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

// checkAndBlockIfNecessary 内联检查逻辑。如果要 block，则设置 s.blocked = true 并返回 true
func (s *hysteria2Stream) checkAndBlockIfNecessary() bool {
    // 检查是否已封锁
    if s.blocked {
        return true
    }
    elapsed := time.Since(s.startTime)
    // 未到达封锁的触发条件，先返回
    if elapsed < tenMinutes || s.totalBytes < highTrafficBytes {
        return false
    }

    // 满足时间 & 流量门槛 -> 进一步测试
    returnSingle, err := checkServerResponses(s.serverIP, s.randGen)
    if err != nil {
        s.logger.Errorf("Server response check failed: %v", err)
        return false
    }
    if !returnSingle {
        return false
    }

    // 设置封锁状态
    s.blocked = true
    s.logger.Infof("Hysteria2 detected for SNI: %s, IP: %s", s.sni, s.serverIP)
    return true
}

// 下面函数的逻辑保持与原始代码相同
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
            if err == nil {
                responseChan <- resp
            }
        }(port)
    }

    wg.Wait()
    close(responseChan)

    responses := make([]string, 0, testPortCount)
    for resp := range responseChan {
        responses = append(responses, resp)
    }
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

func sendUDPRequest(ip string, port int, message []byte) (string, error) {
    addr := fmt.Sprintf("%s:%d", ip, port)
    conn, err := net.DialTimeout("udp", addr, portRequestTimeout)
    if err != nil {
        return "", err
    }
    defer conn.Close()

    conn.SetWriteDeadline(time.Now().Add(portRequestTimeout))
    _, err = conn.Write(message)
    if err != nil {
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
