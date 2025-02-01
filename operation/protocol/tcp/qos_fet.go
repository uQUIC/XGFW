package tcp

import (
    "math/rand"
    "strconv"
    "strings"
    "time"

    "github.com/uQUIC/XGFW/operation/protocol"
)

// FETQoSAnalyzer 实现带QoS的全加密流量分析器
type FETQoSAnalyzer struct {
    dropRate float64 // 丢包率 0.0-1.0
}

// NewFETQoSAnalyzer 创建新的QoS分析器
// expr格式: "drop_rate=X" 其中X为0-100的整数,表示丢包百分比
func NewFETQoSAnalyzer(expr string) (*FETQoSAnalyzer, error) {
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

    return &FETQoSAnalyzer{
        dropRate: dropRate,
    }, nil
}

func (a *FETQoSAnalyzer) Name() string {
    return "fet-qos"
}

func (a *FETQoSAnalyzer) Limit() int {
    return 8192 // 保持与原FET分析器相同的限制
}

func (a *FETQoSAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    return &fetQoSStream{
        logger:      logger,
        dropRate:    a.dropRate,
        rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
        fetDetector: newFETStream(logger), // 复用原有的FET检测逻辑
    }
}

type fetQoSStream struct {
    logger      analyzer.Logger
    dropRate    float64
    rng         *rand.Rand
    fetDetector *fetStream // 用于复用FET的检测逻辑
    
    packetCount  int
    droppedCount int
    totalBytes   int
    isFET        bool    // 标记是否检测为全加密流量
    
    // 保存FET指标
    metrics struct {
        ex1 float32  // 平均popcount
        ex2 bool     // 前6字节是否可打印
        ex3 float32  // 可打印字符百分比
        ex4 int      // 最长连续可打印序列长度
        ex5 bool     // 是否为TLS/HTTP
    }
}

func (s *fetQoSStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
    if skip != 0 {
        return nil, true
    }
    if len(data) == 0 {
        return nil, false
    }

    s.packetCount++
    s.totalBytes += len(data)

    // 使用原FET检测逻辑进行检测
    update, fetDone := s.fetDetector.Feed(rev, start, end, skip, data)
    
    if update != nil {
        // 保存FET指标
        if ex1, ok := update.M["ex1"].(float32); ok {
            s.metrics.ex1 = ex1
        }
        if ex2, ok := update.M["ex2"].(bool); ok {
            s.metrics.ex2 = ex2
        }
        if ex3, ok := update.M["ex3"].(float32); ok {
            s.metrics.ex3 = ex3
        }
        if ex4, ok := update.M["ex4"].(int); ok {
            s.metrics.ex4 = ex4
        }
        if ex5, ok := update.M["ex5"].(bool); ok {
            s.metrics.ex5 = ex5
        }
        // 判断是否为全加密流量
        if yes, ok := update.M["yes"].(bool); ok && yes {
            s.isFET = true
        }
    }

    // 如果确认是全加密流量，执行QoS丢包
    if s.isFET {
        // 根据配置的丢包率随机丢包
        if s.rng.Float64() < s.dropRate {
            s.droppedCount++
            return &analyzer.PropUpdate{
                Type: analyzer.PropUpdateMerge,
                M: analyzer.PropMap{
                    "drop":     true,
                    "reason":   "fet-qos",
                    "is_fet":   true,
                },
            }, false
        }
    }

    // 如果FET检测完成，返回最终结果
    if fetDone {
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "is_fet":      s.isFET,
                "ex1":         s.metrics.ex1,
                "ex2":         s.metrics.ex2,
                "ex3":         s.metrics.ex3,
                "ex4":         s.metrics.ex4,
                "ex5":         s.metrics.ex5,
                "packetCount": s.packetCount,
                "totalBytes":  s.totalBytes,
                "droppedCount": s.droppedCount,
                "dropRate":    s.dropRate,
            },
        }, true
    }

    return nil, false
}

func (s *fetQoSStream) Close(limited bool) *analyzer.PropUpdate {
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M: analyzer.PropMap{
            "is_fet":      s.isFET,
            "ex1":         s.metrics.ex1,
            "ex2":         s.metrics.ex2,
            "ex3":         s.metrics.ex3,
            "ex4":         s.metrics.ex4,
            "ex5":         s.metrics.ex5,
            "packetCount": s.packetCount,
            "totalBytes":  s.totalBytes,
            "droppedCount": s.droppedCount,
            "dropRate":    s.dropRate,
        },
    }
}
