package udp

import (
    "math/rand"
    "time"

    "github.com/uQUIC/XGFW/operation/protocol"
    "github.com/uQUIC/XGFW/operation/protocol/internal"
    "github.com/uQUIC/XGFW/operation/protocol/udp/internal/quic"
    "github.com/uQUIC/XGFW/operation/protocol/utils"
)

// 常量
const (
    brutalInvalidCountThreshold = 4

    positiveScoreIncrement = 2  // 阳性时加分
    negativeScoreDecrement = 1  // 阴性时减分，不可减至负数
    blockThreshold         = 20 // 分数大于此值则封锁

    intervalCount      = 5                       // 需要收集的区间数量
    intervalDuration   = 10 * time.Millisecond   // 每个区间持续时间
    intervalStartChance = 0.01                   // 每次 Feed 启动区间的随机概率
)

// 确保实现接口
var (
    _ analyzer.UDPAnalyzer = (*BrutalAnalyzer)(nil)
    _ analyzer.UDPStream   = (*brutalStream)(nil)
)

// BrutalAnalyzer 实现 analyzer.UDPAnalyzer
type BrutalAnalyzer struct{}

func (a *BrutalAnalyzer) Name() string {
    return "brutal"
}

func (a *BrutalAnalyzer) Limit() int {
    return 0
}

func (a *BrutalAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
    return &brutalStream{
        logger: logger,
        score:  0,
    }
}

// intervalData 用于记录一个区间内的字节数
type intervalData struct {
    byteCount int
    startTime time.Time
    endTime   time.Time
}

// brutalStream 实现 analyzer.UDPStream
type brutalStream struct {
    logger       analyzer.Logger
    invalidCount int
    packetCount  int
    totalBytes   int

    score            int             // 当前得分
    intervals        []intervalData  // 已结束的区间
    currentInterval  *intervalData   // 正在进行的区间
    intervalsDone    int             // 已完成的区间计数
    allIntervalsDone bool            // 是否已完成5个区间的数据收集

    blocked bool // 是否已经触发阻断
}

// Feed 每次接收 UDP 包时调用
func (s *brutalStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
    // 先做基础统计
    s.packetCount++
    s.totalBytes += len(data)

    // 更新当前区间的字节数
    s.updateIntervalStats(len(data))

    // 处理区间 (收集5个区间的数据)
    now := time.Now()
    s.handleIntervals(now)

    // 如果已经被阻断，直接返回
    if s.blocked {
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "blocked": true,
                "reason":  "brutal-threshold-exceed",
                "score":   s.score,
            },
        }, true
    }

    // 首先检测流量是否为QUIC流量
    if !s.isQUIC(data) {
        return nil, false
    }

    // 以下是对服务器->客户端方向包、或加密数据完整性的检查
    // 如果是服务器方向的流量 (rev == true)，这里不做深入分析
    if rev {
        s.invalidCount++
        // 若无效包过多，直接结束
        if s.invalidCount >= brutalInvalidCountThreshold {
            return nil, true
        }
        return nil, false
    }

    // 尝试解析 QUIC ClientHello
    const minDataSize = 41
    pl, err := quic.ReadCryptoPayload(data)
    if err != nil || len(pl) < 4 {
        s.invalidCount++
        return nil, s.invalidCount >= brutalInvalidCountThreshold
    }
    if pl[0] != internal.TypeClientHello {
        s.invalidCount++
        return nil, s.invalidCount >= brutalInvalidCountThreshold
    }

    chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
    if chLen < minDataSize {
        s.invalidCount++
        return nil, s.invalidCount >= brutalInvalidCountThreshold
    }

    // 解析客户端握手消息
    m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
    if m == nil {
        s.invalidCount++
        return nil, s.invalidCount >= brutalInvalidCountThreshold
    }

    // 再次检查: 在解析后，也看看是否在这次处理里已经被 block
    if s.blocked {
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "blocked": true,
                "reason":  "brutal-threshold-exceed",
                "score":   s.score,
            },
        }, true
    }

    // 正常合并属性
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateMerge,
        M:    analyzer.PropMap{"req": m},
    }, true
}

// 检测流量是否为 QUIC 流量
func (s *brutalStream) isQUIC(data []byte) bool {
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
    if chLen < 41 {
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

// updateIntervalStats 更新当前正在进行的区间的字节数
func (s *brutalStream) updateIntervalStats(byteCount int) {
    if s.currentInterval == nil {
        return
    }
    s.currentInterval.byteCount += byteCount
}

// handleIntervals 处理区间逻辑：随机启动区间、在区间超过10ms后结束并统计
func (s *brutalStream) handleIntervals(now time.Time) {
    if s.allIntervalsDone {
        return
    }

    // 如果当前没有正在进行的区间，并且还没收集到5个区间
    if s.currentInterval == nil && s.intervalsDone < intervalCount {
        // 用一定概率启动新区间
        if rand.Float64() < intervalStartChance {
            s.currentInterval = &intervalData{
                startTime: now,
            }
        }
    } else if s.currentInterval != nil {
        // 如果已到达区间持续时间，则结束该区间
        if now.Sub(s.currentInterval.startTime) >= intervalDuration {
            s.currentInterval.endTime = now
            s.intervals = append(s.intervals, *s.currentInterval)
            s.currentInterval = nil
            s.intervalsDone++

            // 若已经收集满5个区间，进行评估
            if s.intervalsDone == intervalCount {
                s.allIntervalsDone = true
                s.evaluateIntervals()

                // 若评估完分数超过阈值，立刻阻断
                if s.score > blockThreshold {
                    s.blocked = true
                }
            }
        }
    }
}

// evaluateIntervals 对 5 个区间进行评估并更新分数
func (s *brutalStream) evaluateIntervals() {
    if len(s.intervals) < intervalCount {
        return
    }

    // 收集每个区间的字节数
    vals := make([]float64, 0, intervalCount)
    for _, iv := range s.intervals {
        vals = append(vals, float64(iv.byteCount))
    }
    if len(vals) == 0 {
        return
    }

    // 计算 max, min, avg
    maxVal := vals[0]
    minVal := vals[0]
    sum := 0.0
    for _, v := range vals {
        if v > maxVal {
            maxVal = v
        }
        if v < minVal {
            minVal = v
        }
        sum += v
    }
    avg := sum / float64(len(vals))

    rangeVal := maxVal - minVal

    // 如果极差 < 平均数的5%，视为“阳性” => 加分
    if avg > 0 && rangeVal < avg*0.05 {
        s.score += positiveScoreIncrement
    } else {
        // 否则阴性 => 减分（分数不低于0）
        s.score -= negativeScoreDecrement
        if s.score < 0 {
            s.score = 0
        }
    }
}

// Close 在流结束时返回统计信息，如 blocked 与否、score 等
func (s *brutalStream) Close(limited bool) *analyzer.PropUpdate {
    // 如果尚未标记 blocked，则再做一次终止判断
    blocked := s.blocked || (s.score > blockThreshold)
    if blocked {
        s.blocked = true
    }

    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M: analyzer.PropMap{
            "packetCount": s.packetCount,
            "totalBytes":  s.totalBytes,
            "score":       s.score,
            "blocked":     s.blocked,
        },
    }
}
