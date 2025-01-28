package tcp

import (
    "crypto/sha256"
    "encoding/binary"
    "fmt"
    "log"
    "sync"
    "time"
    "net"
    "bytes"

    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"

    "github.com/uQUIC/XGFW/operation/protocol"
	"github.com/uQUIC/XGFW/operation/protocol/utils"
)

// =================== 原始检测代码（保持原状，包名改为 tcp） =================== //

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

// SkypeDetector 主结构体
type SkypeDetector struct {
    handle          *pcap.Handle
    connState       *ConnectionState
    iface           string
    patternDB       map[string][]byte
    tlsFingerprints map[string]bool
    blockRules      []string
}

// 创建新的检测器实例
func NewSkypeDetector(iface string) (*SkypeDetector, error) {
    handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
    if err != nil {
        return nil, fmt.Errorf("error opening interface %s: %v", iface, err)
    }

    // 设置更复杂的BPF过滤器
    filter := "tcp portrange 32000-33000 or tcp port 443 or udp portrange 32000-33000"
    if err := handle.SetBPFFilter(filter); err != nil {
        handle.Close()
        return nil, fmt.Errorf("error setting BPF filter: %v", err)
    }

    return &SkypeDetector{
        handle: handle,
        connState: &ConnectionState{
            Features:  make([]PacketFeatures, 0, 1000),
            StartTime: time.Now(),
        },
        iface: iface,
        patternDB: initializePatternDB(),
        tlsFingerprints: initializeTLSFingerprints(),
    }, nil
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
        "1603010200010001fc0303": true,  // Skype TLS 1.2
        "1603010200010001fc0304": true,  // Skype TLS 1.3
    }
}

// 特征提取和分析
func (sd *SkypeDetector) extractFeatures(packet gopacket.Packet) *PacketFeatures {
    features := &PacketFeatures{
        Timestamp: time.Now(),
    }

    // 分析IP层
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer == nil {
        return nil
    }
    ip, _ := ipLayer.(*layers.IPv4)
    features.Size = uint16(ip.Length)

    // 分析传输层
    if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
        tcp, _ := tcpLayer.(*layers.TCP)
        features.Protocol = 0

        // 分析TCP负载
        payload := tcp.LayerPayload()
        if len(payload) > 0 {
            features.PayloadHash = sha256.Sum256(payload)
            features.Direction = sd.determineDirection(ip.SrcIP)
        }
    } else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
        udp, _ := udpLayer.(*layers.UDP)
        features.Protocol = 1

        // 分析UDP负载
        payload := udp.LayerPayload()
        if len(payload) > 0 {
            features.PayloadHash = sha256.Sum256(payload)
            features.Direction = sd.determineDirection(ip.SrcIP)
        }
    }

    return features
}

// 确定数据包方向
func (sd *SkypeDetector) determineDirection(srcIP net.IP) uint8 {
    sd.connState.mu.Lock()
    defer sd.connState.mu.Unlock()

    if sd.connState.SrcIP != nil && srcIP.Equal(sd.connState.SrcIP) {
        return 0 // outbound
    }
    return 1 // inbound
}

// 深度包检测
func (sd *SkypeDetector) deepPacketInspection(packet gopacket.Packet) bool {
    sd.connState.mu.Lock()
    defer sd.connState.mu.Unlock()

    // 提取特征
    features := sd.extractFeatures(packet)
    if features == nil {
        return false
    }

    // 更新连接状态
    sd.connState.PacketCount++
    sd.connState.BytesTransferred += uint64(features.Size)
    sd.connState.Features = append(sd.connState.Features, *features)
    sd.connState.LastSeen = features.Timestamp

    // 特征分析
    return sd.analyzeFeatures()
}

// 特征分析
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

// 分析流量模式
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

// 分析数据包时间间隔
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

// 分析负载模式
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

    // 应用阻断规则（实际生产环境下，需要执行iptables命令）
    for _, rule := range rules {
        cmd := fmt.Sprintf("iptables %s", rule)
        log.Printf("Applying blocking rule: %s", cmd)
        // 这里应该执行实际的iptables命令，而不是只日志
    }

    sd.connState.IsBlocked = true
    return nil
}

// 原先的 main 函数，为避免与库冲突，这里重命名为 OriginalMain。
// 如果单独运行此文件，也可执行 OriginalMain() 进行抓包检测。
func OriginalMain() {
    // 获取网络接口列表
    devices, err := pcap.FindAllDevs()
    if err != nil {
        log.Fatal(err)
    }

    if len(devices) == 0 {
        log.Fatal("No network interfaces found")
    }

    // 使用第一个有效接口
    iface := devices[0].Name
    detector, err := NewSkypeDetector(iface)
    if err != nil {
        log.Fatal(err)
    }
    defer detector.handle.Close()

    fmt.Printf("Starting enhanced Skype detection on interface: %s\n", iface)

    packetSource := gopacket.NewPacketSource(detector.handle, detector.handle.LinkType())
    for packet := range packetSource.Packets() {
        if detector.deepPacketInspection(packet) {
            fmt.Println("Skype traffic detected with high confidence! Blocking connection...")
            if err := detector.blockConnection(); err != nil {
                log.Printf("Error blocking connection: %v", err)
            }
            break
        }
    }
}

// =================== 以上是原逻辑完整保留 =================== //

// ================== 以下为 XGFW 的适配部分 ================== //

// skypeAnalyzer 实现 analyzer.TCPAnalyzer
type skypeAnalyzer struct{}

// Name 在 XGFW 配置中引用的名称
func (a *skypeAnalyzer) Name() string {
    return "skypeAnalyzer"
}

// Limit 表示本分析器需要读取的最大数据字节数
func (a *skypeAnalyzer) Limit() int {
    return 65536
}

// NewTCP 当 XGFW 遇到新的 TCP 连接时，会调用此方法
func (a *skypeAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    // 初始化一个 SkypeDetector 结构来追踪此连接
    det := &SkypeDetector{
        connState: &ConnectionState{
            SrcIP:     net.ParseIP(info.Src.String()),
            DstIP:     net.ParseIP(info.Dst.String()),
            SrcPort:   uint16(info.SrcPort),
            DstPort:   uint16(info.DstPort),
            StartTime: time.Now(),
            Features:  make([]PacketFeatures, 0, 1000),
        },
        patternDB:       initializePatternDB(),
        tlsFingerprints: initializeTLSFingerprints(),
    }
    return &skypeAnalyzerStream{
        logger:   logger,
        detector: det,
    }
}

// 确保 skypeAnalyzer 实现 analyzer.TCPAnalyzer 接口
var _ analyzer.TCPAnalyzer = (*skypeAnalyzer)(nil)

// skypeAnalyzerStream 实现 analyzer.TCPStream，用于跟踪某条 TCP 连接
type skypeAnalyzerStream struct {
    logger   analyzer.Logger
    detector *SkypeDetector
    blocked  bool
}

// Feed 每当有 TCP 数据段到达时，XGFW 会调用此方法
// rev=true 表示服务器->客户端方向，rev=false 表示客户端->服务器方向
func (s *skypeAnalyzerStream) Feed(rev, start, end bool, skip int, data []byte) (*analyzer.PropUpdate, bool) {
    // 如果 skip != 0，则表示我们不需要分析这段数据
    if skip != 0 || len(data) == 0 {
        return nil, false
    }

    // 为了让原逻辑“深度包检测”正常工作，我们需要构造一个最简的 gopacket.Packet
    // 包含 IPv4 层 + TCP 层，并将 data 作为 TCP 负载。
    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{}

    // IPv4 层
    ip := &layers.IPv4{
        SrcIP:    s.detector.connState.SrcIP,
        DstIP:    s.detector.connState.DstIP,
        Protocol: layers.IPProtocolTCP,
        Version:  4,
        IHL:      5,
    }
    // TCP 层
    tcp := &layers.TCP{
        SrcPort: layers.TCPPort(s.detector.connState.SrcPort),
        DstPort: layers.TCPPort(s.detector.connState.DstPort),
    }
    // 如果是服务器->客户端方向，交换 src/dst
    if rev {
        ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
        tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
    }
    // payload
    payload := gopacket.Payload(data)

    // 序列化
    err := gopacket.SerializeLayers(buf, opts, ip, tcp, payload)
    if err != nil {
        s.logger.Warn("skypeAnalyzer: failed to serialize layers: ", err)
        return nil, false
    }

    // 解析出一个 Packet 供原逻辑使用
    pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
    if s.detector.deepPacketInspection(pkt) {
        // 一旦检测到 Skype，可以尝试阻断
        if !s.blocked {
            blockErr := s.detector.blockConnection()
            if blockErr != nil {
                s.logger.Warn("skypeAnalyzer: blockConnection error: ", blockErr)
            }
            s.blocked = true
        }

        // 返回给 XGFW 一个属性：block=true
        // XGFW 在配置中即可使用 expr: skypeAnalyzer.block == true 来匹配进行封锁
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{"block": true},
        }, true
    }

    // 如果没有检测到，就继续处理
    return nil, false
}

// Close 在连接结束或超出 Limit 时被调用
func (s *skypeAnalyzerStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}

// 确保 skypeAnalyzerStream 实现 analyzer.TCPStream 接口
var _ analyzer.TCPStream = (*skypeAnalyzerStream)(nil)
