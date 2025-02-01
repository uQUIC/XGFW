package tcp

import (
    "math/rand"
    "strconv"
    "strings"
    "time"

    "github.com/uQUIC/XGFW/operation/protocol"
    "github.com/uQUIC/XGFW/ruleset/builtins/tor"
)

// TorQoSAnalyzer 实现带QoS的Tor分析器
type TorQoSAnalyzer struct {
    directory tor.TorDirectory
    dropRate  float64 // 丢包率 0.0-1.0
}

// NewTorQoSAnalyzer 创建新的QoS分析器
// expr格式: "drop_rate=X" 其中X为0-100的整数,表示丢包百分比
func NewTorQoSAnalyzer(expr string) (*TorQoSAnalyzer, error) {
    dropRate := 0.10 // 默认10%丢包率
    
    if expr != "" {
        parts := strings.Split(expr, "=")
        if len(parts) == 2 && parts[0] == "drop_rate" {
            if rate, err := strconv.Atoi(parts[1]); err == nil {
                if rate >= 0 && rate <= 100 {
                    dropRate = float64(rate) / 100.0
                }
            }
        }
    }

    return &TorQoSAnalyzer{
        dropRate: dropRate,
    }, nil
}

func (a *TorQoSAnalyzer) Init() error {
    var err error
    a.directory, err = tor.GetOnionooDirectory()
    return err
}

func (a *TorQoSAnalyzer) Name() string {
    return "tor-qos"
}

func (a *TorQoSAnalyzer) Limit() int {
    return 1 // 保持与原Tor分析器相同的限制
}

func (a *TorQoSAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    isRelay := a.directory.Query(info.DstIP, info.DstPort)
    return &torQoSStream{
        logger:    logger,
        dropRate:  a.dropRate,
        rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
        isRelay:   isRelay,
    }
}

type torQoSStream struct {
    logger      analyzer.Logger
    dropRate    float64
    rng         *rand.Rand
    isRelay     bool    // Tor中继标识
    
    packetCount  int
    droppedCount int
    totalBytes   int
    firstPacket  bool   // 标记是否为第一个包
}

func (s *torQoSStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
    if skip != 0 {
        return nil, true
    }
    if len(data) == 0 {
        return nil, false
    }

    s.packetCount++
    s.totalBytes += len(data)

    // 如果是Tor中继连接，执行QoS丢包
    if s.isRelay {
        // 根据配置的丢包率随机丢包
        if s.rng.Float64() < s.dropRate {
            s.droppedCount++
            return &analyzer.PropUpdate{
                Type: analyzer.PropUpdateMerge,
                M: analyzer.PropMap{
                    "drop":     true,
                    "reason":   "tor-qos",
                    "is_relay": true,
                },
            }, false
        }
    }

    // 如果是第一个包，返回检测结果
    if !s.firstPacket {
        s.firstPacket = true
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "is_relay":    s.isRelay,
                "packetCount": s.packetCount,
                "totalBytes":  s.totalBytes,
                "droppedCount": s.droppedCount,
                "dropRate":    s.dropRate,
            },
        }, true
    }

    return nil, false
}

func (s *torQoSStream) Close(limited bool) *analyzer.PropUpdate {
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M: analyzer.PropMap{
            "is_relay":    s.isRelay,
            "packetCount": s.packetCount,
            "totalBytes":  s.totalBytes,
            "droppedCount": s.droppedCount,
            "dropRate":    s.dropRate,
        },
    }
}
