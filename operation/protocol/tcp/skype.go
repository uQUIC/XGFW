package main

import (
    "bytes"
    "crypto/sha256"
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "os/exec"
    "sync"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/packet"
)

// ================== (1) 原先的数据结构、字段、逻辑，保留 ================== //

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
    // 由于不再使用 pcap，这里去掉 handle, iface 等字段
    // handle          *pcap.Handle
    // iface           string
    connState       *ConnectionState
    patternDB       map[string][]byte
    tlsFingerprints map[string]bool
    blockRules      []string
}

// ================== (2) 初始化数据库，原逻辑保留 ================== //

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

// ================== (3) 检测器的核心逻辑，保留 ================== //

// 特征提取和分析
func (sd *SkypeDetector) extractFeatures(pkt gopacket.Packet) *PacketFeatures {
    features := &PacketFeatures{
        Timestamp: time.Now(),
    }

    // 分析IP层
    ipLayer := pkt.Layer(layers.LayerTypeIPv4)
    if ipLayer == nil {
        return nil
    }
    ip, _ := ipLayer.(*layers.IPv4)
    features.Size = uint16(ip.Length)

    // 分析传输层
    if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
        tcp, _ := tcpLayer.(*layers.TCP)
        features.Protocol = 0

        // 分析TCP负载
        payload := tcp.LayerPayload()
        if len(payload) > 0 {
            features.PayloadHash = sha256.Sum256(payload)
            features.Direction = sd.determineDirection(ip.SrcIP)
        }
    } else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
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
func (sd *SkypeDetector) deepPacketInspection(pkt gopacket.Packet) bool {
    sd.connState.mu.Lock()
    defer sd.connState.mu.Unlock()

    // 提取特征
    features := sd.extractFeatures(pkt)
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

    // 应用阻断规则（生产环境下需真正调用iptables；此处仅打印命令示意）
    for _, rule := range rules {
        cmdLine := fmt.Sprintf("iptables %s", rule)
        log.Printf("Applying blocking rule: %s", cmdLine)

        // 若要真正执行，可用 exec.Command:
        // cmd := exec.Command("iptables", strings.Split(rule, " ")...)
        // err := cmd.Run()
        // if err != nil {
        //     log.Printf("Error running iptables: %v", err)
        // }
    }

    sd.connState.IsBlocked = true
    return nil
}

// ================== (4) 去掉对 pcap 的依赖，新增 ProcessPacket ================== //

// NewSkypeDetector 创建一个无需 pcap 的“检测器”
func NewSkypeDetector(srcIP, dstIP net.IP, srcPort, dstPort uint16) *SkypeDetector {
    return &SkypeDetector{
        connState: &ConnectionState{
            SrcIP:     srcIP,
            DstIP:     dstIP,
            SrcPort:   srcPort,
            DstPort:   dstPort,
            StartTime: time.Now(),
            Features:  make([]PacketFeatures, 0, 1000),
        },
        patternDB:       initializePatternDB(),
        tlsFingerprints: initializeTLSFingerprints(),
    }
}

// ProcessPacket 封装 data + (TCP/UDP) + IPv4 头为 gopacket.Packet，调用原有 deepPacketInspection。
//   - isTCP: true 则视为 TCP，false 则 UDP。
//   - directionOutbound: true 表示此 data 来自客户端 -> 服务器；false 表示服务器 -> 客户端。
func (sd *SkypeDetector) ProcessPacket(data []byte, isTCP bool, directionOutbound bool) (bool, error) {
    // 伪造一层 IPv4
    ip := &layers.IPv4{
        SrcIP:    sd.connState.SrcIP,
        DstIP:    sd.connState.DstIP,
        Version:  4,
        IHL:      5,
        Protocol: layers.IPProtocolTCP, // 默认TCP
    }
    // 如果方向相反，则交换 IP
    if !directionOutbound {
        ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
    }

    var (
        tcp  *layers.TCP
        udp  *layers.UDP
        prot gopacket.SerializableLayer
    )
    if isTCP {
        tcp = &layers.TCP{
            SrcPort: layers.TCPPort(sd.connState.SrcPort),
            DstPort: layers.TCPPort(sd.connState.DstPort),
        }
        // 如果方向相反，就交换端口
        if !directionOutbound {
            tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
        }
        prot = tcp
    } else {
        ip.Protocol = layers.IPProtocolUDP
        udp = &layers.UDP{
            SrcPort: layers.UDPPort(sd.connState.SrcPort),
            DstPort: layers.UDPPort(sd.connState.DstPort),
        }
        if !directionOutbound {
            udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort
        }
        prot = udp
    }

    payload := gopacket.Payload(data)

    // 序列化
    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{}
    err := gopacket.SerializeLayers(buf, opts, ip, prot, payload)
    if err != nil {
        return false, fmt.Errorf("SerializeLayers error: %v", err)
    }

    // 构建 Packet
    pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
    if pkt.ErrorLayer() != nil {
        return false, fmt.Errorf("decode packet error: %v", pkt.ErrorLayer().Error())
    }

    // 调用原有检测逻辑
    foundSkype := sd.deepPacketInspection(pkt)
    if foundSkype {
        // 如果判定为Skype流量，执行阻断
        if err := sd.blockConnection(); err != nil {
            log.Printf("Error blocking connection: %v", err)
        }
    }
    return foundSkype, nil
}

// ================== (5) 示例 main 函数，展示如何调用 ================== //

// 演示如何使用本代码进行检测（不再需要 pcap）。
func main() {
    // 假设我们要检测来自 192.168.1.100:52000 -> 10.0.0.1:443 的流量
    srcIP := net.ParseIP("192.168.1.100")
    dstIP := net.ParseIP("10.0.0.1")
    srcPort := uint16(52000)
    dstPort := uint16(443)

    // 初始化一个检测器
    detector := NewSkypeDetector(srcIP, dstIP, srcPort, dstPort)

    // 假设我们有 2 个数据包：packet1, packet2
    // 在真实场景中，这些数据可以来自 net.Conn 读取、从文件读取，或其他方式。
    // 这里仅做演示：
    packet1 := []byte{0x01, 0x02, 0x03} // 假设一些负载
    packet2 := []byte{0x02, 0x0D, 0x00} // 带有 "audio_pattern" 的负载示例

    // 处理包1：视为 客户端->服务器 的 TCP 包
    isSkype1, _ := detector.ProcessPacket(packet1, true, true)
    log.Printf("packet1 => foundSkype = %v\n", isSkype1)

    // 处理包2：视为 客户端->服务器 的 TCP 包
    isSkype2, _ := detector.ProcessPacket(packet2, true, true)
    log.Printf("packet2 => foundSkype = %v\n", isSkype2)

    // ...
    // 你可以多次调用 detector.ProcessPacket(...) 来喂入更多包。
    // 当累计到一定阈值后，内部判定为Skype就会输出阻断操作。
}
