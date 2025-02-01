package tcp

import (
    "math/rand"
    "strconv"
    "strings"
    "time"

    "github.com/uQUIC/XGFW/operation/protocol"
)

// TrojanQoSAnalyzer 实现带QoS的Trojan分析器
type TrojanQoSAnalyzer struct {
    dropRate float64 // 丢包率 0.0-1.0
}

// NewTrojanQoSAnalyzer 创建新的QoS分析器
// expr格式: "drop_rate=X" 其中X为0-100的整数,表示丢包百分比
func NewTrojanQoSAnalyzer(expr string) (*TrojanQoSAnalyzer, error) {
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

    return &TrojanQoSAnalyzer{
        dropRate: dropRate,
    }, nil
}

func (a *TrojanQoSAnalyzer) Name() string {
    return "trojan-qos"
}

func (a *TrojanQoSAnalyzer) Limit() int {
    return 512000 // 保持与原Trojan分析器相同的限制
}

func (a *TrojanQoSAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    return &trojanQoSStream{
        logger:         logger,
        dropRate:       a.dropRate,
        rng:           rand.New(rand.NewSource(time.Now().UnixNano())),
        trojanDetector: newTrojanStream(logger), // 复用原有的Trojan检测逻辑
    }
}

type trojanQoSStream struct {
    logger         analyzer.Logger
    dropRate       float64
    rng            *rand.Rand
    trojanDetector *trojanStream // 用于复用Trojan的检测逻辑
    
    packetCount    int
    droppedCount   int
    totalBytes     int
    isTrojan       bool    // 标记是否检测为Trojan流量
    
    // 保存检测结果
    detectedSeq    [4]int
}

func (s *trojanQoSStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
    if skip != 0 {
        return nil, true
    }
    if len(data) == 0 {
        return nil, false
    }

    s.packetCount++
    s.totalBytes += len(data)

    // 使用原Trojan检测逻辑进行检测
    update, trojanDone := s.trojanDetector.Feed(rev, start, end, skip, data)
    
    if update != nil {
        // 保存检测序列
        if seq, ok := update.M["seq"].([4]int); ok {
            s.detectedSeq = seq
        }
        // 判断是否为Trojan流量
        if yes, ok := update.M["yes"].(bool); ok && yes {
            s.isTrojan = true
        }
    }

    // 如果确认是Trojan流量，执行QoS丢包
    if s.isTrojan {
        // 根据配置的丢包率随机丢包
        if s.rng.Float64() < s.dropRate {
            s.droppedCount++
            return &analyzer.PropUpdate{
                Type: analyzer.PropUpdateMerge,
                M: analyzer.PropMap{
                    "drop":      true,
                    "reason":    "trojan-qos",
                    "is_trojan": true,
                },
            }, false
        }
    }

    // 如果Trojan检测完成，返回最终结果
    if trojanDone {
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "is_trojan":    s.isTrojan,
                "seq":          s.detectedSeq,
                "packetCount":  s.packetCount,
                "totalBytes":   s.totalBytes,
                "droppedCount": s.droppedCount,
                "dropRate":     s.dropRate,
            },
        }, true
    }

    return nil, false
}

func (s *trojanQoSStream) Close(limited bool) *analyzer.PropUpdate {
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M: analyzer.PropMap{
            "is_trojan":    s.isTrojan,
            "seq":          s.detectedSeq,
            "packetCount":  s.packetCount,
            "totalBytes":   s.totalBytes,
            "droppedCount": s.droppedCount,
            "dropRate":     s.dropRate,
        },
    }
}
