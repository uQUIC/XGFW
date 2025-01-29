package tcp

import (
    "bytes"
    "crypto/sha256"
    "fmt"
    "log"
    "net"
    "sync"
    "time"

    // XGFW 的 analyzer 接口，与 Trojan 示例相同
    "github.com/uQUIC/XGFW/operation/protocol"
)

// ==================== 原先的数据结构、字段、逻辑保留 ==================== //

// PacketFeatures 存储数据包特征
type PacketFeatures struct {
    Size        uint16
    PayloadHash [32]byte
    Timestamp   time.Time
    Direction   uint8  // 0: outbound, 1: inbound
    Protocol    uint8  // 0: TCP, 1: UDP
}

// ConnectionState 存储连接状态和特征
type ConnectionState struct {
    SrcIP            net.IP
    DstIP            net.IP
    SrcPort          uint16
    DstPort          uint16
    StartTime        time.Time
    LastSeen         time.Time
    PacketCount      uint32
    BytesTransferred uint64
    Features         []PacketFeatures
    PayloadPattern   []byte
    TLSFingerprint   string
    IsBlocked        bool
    mu               sync.Mutex
}

// SkypeDetector 主结构体（去掉对 pcap/gopacket 的依赖）
type SkypeDetector struct {
    connState       *ConnectionState
    patternDB       map[string][]byte
    tlsFingerprints map[string]bool
}

// 初始化已知的Skype流量模式数据库
func initializePatternDB() map[string][]byte {
    return map[string][]byte{
        "header_pattern": {0x02, 0x01, 0x47, 0x49},
        "keepalive":      {0x02, 0x00},
        "audio_pattern":  {0x02, 0x0D},
        "video_pattern":  {0x02, 0x0E},
    }
}

// 初始化已知的Skype TLS指纹
func initializeTLSFingerprints() map[string]bool {
    return map[string]bool{
        "1603010200010001fc0303": true, // Skype TLS 1.2
        "1603010200010001fc0304": true, // Skype TLS 1.3
    }
}

// 特征提取——改造为直接从 data + rev 得出 PacketFeatures
func (sd *SkypeDetector) extractFeatures(data []byte, rev bool) *PacketFeatures {
    // 只保留核心：长度、方向、hash、时间戳；Protocol = 0 (TCP)
    f := &PacketFeatures{
        Size:      uint16(len(data)),
        Timestamp: time.Now(),
        Protocol:  0, // 只检测 TCP
    }
    if rev {
        f.Direction = 1 // inbound
    } else {
        f.Direction = 0 // outbound
    }
    if len(data) > 0 {
        f.PayloadHash = sha256.Sum256(data)
    }
    return f
}

// 深度包检测
func (sd *SkypeDetector) deepPacketInspection(features *PacketFeatures) bool {
    sd.connState.mu.Lock()
    defer sd.connState.mu.Unlock()

    // 更新连接状态
    sd.connState.PacketCount++
    sd.connState.BytesTransferred += uint64(features.Size)
    sd.connState.Features = append(sd.connState.Features, *features)
    sd.connState.LastSeen = features.Timestamp

    // 执行特征分析
    return sd.analyzeFeatures()
}

// analyzeFeatures 与原始逻辑保持一致
func (sd *SkypeDetector) analyzeFeatures() bool {
    if len(sd.connState.Features) < 10 {
        return false
    }

    // 1. 包大小分布分析
    var smallPackets, mediumPackets, largePackets int
    for _, f := range sd.connState.Features {
        switch {
        case f.Size < 100:
            smallPackets++
        case f.Size < 500:
            mediumPackets++
        default:
            largePackets++
        }
    }

    // 2. 流量模式分析
    patterns := sd.analyzeTrafficPatterns()
    if !patterns {
        return false
    }

    // 3. 时间间隔分析
    intervals := sd.analyzeTimeIntervals()
    if !intervals {
        return false
    }

    // 4. 负载特征分析
    payloadMatch := sd.analyzePayloadPatterns()
    if !payloadMatch {
        return false
    }

    // 综合判断
    skypeScore := 0
    if float64(smallPackets)/float64(len(sd.connState.Features)) > 0.6 {
        skypeScore += 2
    }
    if sd.connState.PacketCount > 20 && sd.connState.BytesTransferred > 1000 {
        skypeScore += 2
    }
    if patterns {
        skypeScore += 3
    }
    if intervals {
        skypeScore += 2
    }
    if payloadMatch {
        skypeScore += 3
    }

    return skypeScore >= 8
}

// analyzeTrafficPatterns 与原逻辑保持一致
func (sd *SkypeDetector) analyzeTrafficPatterns() bool {
    if len(sd.connState.Features) < 10 {
        return false
    }

    // 分析最近10个包的方向模式
    var pattern uint16
    startIdx := len(sd.connState.Features) - 10
    for i := startIdx; i < len(sd.connState.Features); i++ {
        pattern = (pattern << 1) | uint16(sd.connState.Features[i].Direction)
    }

    // 检查是否符合Skype的典型双向模式
    return pattern&0x0F0F == 0x0505 || pattern&0x0F0F == 0x0A0A
}

// analyzeTimeIntervals 与原逻辑保持一致
func (sd *SkypeDetector) analyzeTimeIntervals() bool {
    if len(sd.connState.Features) < 3 {
        return false
    }

    var intervals []time.Duration
    for i := 1; i < len(sd.connState.Features); i++ {
        interval := sd.connState.Features[i].Timestamp.Sub(sd.connState.Features[i-1].Timestamp)
        intervals = append(intervals, interval)
    }

    // 检查是否存在典型的心跳包间隔（20-30ms）
    var heartbeatCount int
    for _, interval := range intervals {
        if interval >= 20*time.Millisecond && interval <= 30*time.Millisecond {
            heartbeatCount++
        }
    }
    return heartbeatCount >= len(intervals)/3
}

// analyzePayloadPatterns 与原逻辑保持一致
func (sd *SkypeDetector) analyzePayloadPatterns() bool {
    var matches int
    for _, feature := range sd.connState.Features {
        for _, pattern := range sd.patternDB {
            if bytes.Contains(feature.PayloadHash[:], pattern) {
                matches++
                break
            }
        }
    }
    return matches >= 3
}

// 阻断连接
func (sd *SkypeDetector) blockConnection() error {
    sd.connState.mu.Lock()
    defer sd.connState.mu.Unlock()

    if sd.connState.IsBlocked {
        return nil
    }

    // 构建阻断规则
    rules := []string{
        fmt.Sprintf("-A INPUT -s %s -j DROP", sd.connState.SrcIP),
        fmt.Sprintf("-A OUTPUT -d %s -j DROP", sd.connState.DstIP),
    }

    for _, rule := range rules {
        cmd := fmt.Sprintf("iptables %s", rule)
        log.Printf("Applying blocking rule: %s", cmd)
        // 这里可真正执行 iptables 命令，示例中仅打印。
    }

    sd.connState.IsBlocked = true
    return nil
}

// ==================== (XGFW) Analyzer 实现：SkypeAnalyzer ==================== //

// 确保实现了 analyzer.TCPAnalyzer 接口
var _ analyzer.TCPAnalyzer = (*SkypeAnalyzer)(nil)

// SkypeAnalyzer 用于在 XGFW 中注册名称 "skypeAnalyzer"
type SkypeAnalyzer struct{}

// Name 返回该 Analyzer 的名称，用于 XGFW 配置引用
func (a *SkypeAnalyzer) Name() string {
    return "skypeAnalyzer"
}

// Limit 返回需要从连接读取的最大字节数
func (a *SkypeAnalyzer) Limit() int {
    return 512000 // 可根据需要调整
}

// NewTCP 当有新的 TCP 连接时，XGFW 调用此方法
func (a *SkypeAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    // 初始化 ConnectionState
    state := &ConnectionState{
        SrcIP:     net.ParseIP(info.Src.String()),
        DstIP:     net.ParseIP(info.Dst.String()),
        SrcPort:   uint16(info.SrcPort),
        DstPort:   uint16(info.DstPort),
        StartTime: time.Now(),
        Features:  make([]PacketFeatures, 0, 1000),
    }

    det := &SkypeDetector{
        connState:       state,
        patternDB:       initializePatternDB(),
        tlsFingerprints: initializeTLSFingerprints(),
    }

    return &skypeStream{
        logger:    logger,
        detector:  det,
        blocked:   false,
    }
}

// ==================== (XGFW) TCPStream 实现：skypeStream ==================== //

type skypeStream struct {
    logger   analyzer.Logger
    detector *SkypeDetector
    blocked  bool
}

// Feed 每次有数据流入（客户端->服务器 或 服务器->客户端）时被调用
func (s *skypeStream) Feed(rev, start, end bool, skip int, data []byte) (*analyzer.PropUpdate, bool) {
    if skip != 0 {
        return nil, true // XGFW 要求跳过该段，不再分析
    }
    if len(data) == 0 {
        return nil, false // 没有数据，不进行分析
    }

    // 使用原逻辑: 构造 PacketFeatures
    features := s.detector.extractFeatures(data, rev)
    // 调用 deepPacketInspection
    foundSkype := s.detector.deepPacketInspection(features)
    if foundSkype && !s.blocked {
        // 执行阻断
        if err := s.detector.blockConnection(); err != nil {
            s.logger.Warn("Skype blockConnection error: ", err)
        }
        s.blocked = true
        // 返回给 XGFW 一个属性 "yes" 标记为 true
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{"yes": true},
        }, true // done=true，不再分析后续数据
    }

    // 如果还没到达检测阈值或未判定为Skype，则继续
    return nil, false
}

// Close 当连接结束或超出 Limit() 时被调用，可做收尾
func (s *skypeStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}
