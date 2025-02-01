package udp

import (
    "math/rand"
    "strconv"
    "strings"
    "time"

    "github.com/uQUIC/XGFW/operation/protocol"
)

// BrutalQoSAnalyzer 实现带 QoS 的分析器
type BrutalQoSAnalyzer struct {
    dropRate float64 // 丢包率 0.0-1.0
}

// NewBrutalQoSAnalyzer 创建新的QoS分析器
// expr格式: "drop_rate=X" 其中X为0-100的整数,表示丢包百分比
func NewBrutalQoSAnalyzer(expr string) (*BrutalQoSAnalyzer, error) {
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

    return &BrutalQoSAnalyzer{
        dropRate: dropRate,
    }, nil
}

func (a *BrutalQoSAnalyzer) Name() string {
    return "brutal-qos"
}

func (a *BrutalQoSAnalyzer) Limit() int {
    return 0
}

func (a *BrutalQoSAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
    return &brutalQoSStream{
        logger:    logger,
        dropRate:  a.dropRate,
        rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
        // 复用原有的brutal检测逻辑
        brutalDetector: &brutalStream{
            logger: logger,
            score:  0,
        },
    }
}

type brutalQoSStream struct {
    logger         analyzer.Logger
    dropRate       float64
    rng            *rand.Rand
    brutalDetector *brutalStream // 用于复用brutal的检测逻辑
    
    packetCount    int
    droppedCount   int
    totalBytes     int
    isBrutal       bool // 标记是否检测为brutal流量
}

func (s *brutalQoSStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
    s.packetCount++
    s.totalBytes += len(data)

    // 使用原brutal检测逻辑判断是否为brutal流量
    brutalUpdate, _ := s.brutalDetector.Feed(rev, data)
    if brutalUpdate != nil {
        if score, ok := brutalUpdate.M["score"].(int); ok && score > blockThreshold {
            s.isBrutal = true
        }
    }

    // 如果确认是brutal流量，执行QoS丢包
    if s.isBrutal {
        // 根据配置的丢包率随机丢包
        if s.rng.Float64() < s.dropRate {
            s.droppedCount++
            return &analyzer.PropUpdate{
                Type: analyzer.PropUpdateMerge,
                M: analyzer.PropMap{
                    "drop":     true,
                    "reason":   "brutal-qos",
                    "is_brutal": true,
                },
            }, false
        }
    }

    return nil, false
}

func (s *brutalQoSStream) Close(limited bool) *analyzer.PropUpdate {
    brutalUpdate := s.brutalDetector.Close(limited)
    
    // 合并brutal检测结果和QoS统计信息
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M: analyzer.PropMap{
            "packetCount":  s.packetCount,
            "totalBytes":   s.totalBytes,
            "droppedCount": s.droppedCount,
            "dropRate":     s.dropRate,
            "is_brutal":    s.isBrutal,
            "brutal_score": brutalUpdate.M["score"],
        },
    }
}
