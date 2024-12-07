package udp

import (
    "github.com/uQUIC/XGFW/analyzer"
    "github.com/uQUIC/XGFW/analyzer/internal"
    "github.com/uQUIC/XGFW/analyzer/udp/internal/quic"
    "github.com/uQUIC/XGFW/analyzer/utils"
    "math/rand"
    "time"
)

const (
    brutalInvalidCountThreshold = 4
    brutalMaxPacketLossRate     = 0.02 // 最大丢包率 2%
    
    // 新增常量
    positiveScore   = 2
    negativeScore   = -1
    blockThreshold   = 20
    sampleSize       = 5
    segmentDuration  = 10 * time.Millisecond
)

var (
    _ analyzer.UDPAnalyzer = (*BrutalAnalyzer)(nil)
    _ analyzer.UDPStream   = (*brutalStream)(nil)
)

type BrutalAnalyzer struct{}

func (a *BrutalAnalyzer) Name() string {
    return "brutal"
}

func (a *BrutalAnalyzer) Limit() int {
    return 0
}

func (a *BrutalAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
    return &brutalStream{
        logger:          logger,
        segments:        make([]segment, 0, 100),
        score:           0,
        random:          rand.New(rand.NewSource(time.Now().UnixNano())),
        lastSegmentTime: time.Now(),
    }
}

type brutalStream struct {
    logger          analyzer.Logger
    invalidCount    int
    packetCount     int
    lossCount       int
    lastTime        time.Time
    lastPacketSize  int
    isBrutal        bool
    
    // 新增字段
    segments         []segment
    score            int
    random           *rand.Rand
    lastSegmentTime  time.Time
}

type segment struct {
    byteRate float64
    lossRate float64
}

// 模拟丢包和速率分析
func (s *brutalStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
    now := time.Now()
    elapsed := now.Sub(s.lastTime).Seconds()

    // 丢包模拟：根据最大丢包率控制丢包概率
    if rand.Float64() < brutalMaxPacketLossRate {
        s.lossCount++
        return nil, false // 丢弃当前数据包
    }
    s.packetCount++

    // 计算传输速率（假设每个数据包大小是固定的，这里简化为1）
    if elapsed > 0 {
        packetRate := float64(s.packetCount) / elapsed
        lossRate := float64(s.lossCount) / float64(s.packetCount)

        // 判断流量是否符合 brutal 特征：速率与丢包率的反比关系
        if lossRate > 0.1 && packetRate > 0.5 {
            s.isBrutal = true
        }
    }

    s.lastTime = now

    // 记录段信息
    segmentElapsed := now.Sub(s.lastSegmentTime)
    if segmentElapsed >= segmentDuration {
        byteRate := float64(s.packetCount) / segmentElapsed.Seconds()
        lossRate := float64(s.lossCount) / float64(s.packetCount)
        s.segments = append(s.segments, segment{byteRate: byteRate, lossRate: lossRate})
        if len(s.segments) > 100 { // 保持segments长度不超过100
            s.segments = s.segments[1:]
        }
        s.lastSegmentTime = now
    }

    // 每当有新的段记录时，随机选择sampleSize个段进行评估
    if len(s.segments) >= sampleSize {
        selected := make([]segment, 0, sampleSize)
        indices := s.random.Perm(len(s.segments))[:sampleSize]
        for _, idx := range indices {
            selected = append(selected, s.segments[idx])
        }

        values := make([]float64, 0, sampleSize)
        for _, seg := range selected {
            values = append(values, seg.byteRate*(1.0-seg.lossRate))
        }

        // 计算极差和平均数
        maxVal, minVal := values[0], values[0]
        sum := 0.0
        for _, v := range values {
            if v > maxVal {
                maxVal = v
            }
            if v < minVal {
                minVal = v
            }
            sum += v
        }
        avg := sum / float64(sampleSize)
        rangeVal := maxVal - minVal

        if rangeVal < 0.5*avg {
            s.score += positiveScore // 阳性
        } else {
            s.score += negativeScore // 阴性
            if s.score < 0 {
                s.score = 0
            }
        }

        // 检查是否需要封锁
        if s.score > blockThreshold {
            return nil, true // 封锁连接
        }
    }

    // 最小数据包大小: 协议版本 (2 字节) + 随机数 (32 字节) + 会话ID (1 字节) + 密码套件 (4 字节) + 压缩方法 (2 字节) + 无扩展
    const minDataSize = 41

    if rev {
        // 不支持服务器方向的流量
        s.invalidCount++
        return nil, s.invalidCount >= brutalInvalidCountThreshold
    }

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

    // 返回数据流的更新，包括当前请求信息
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateMerge,
        M:    analyzer.PropMap{"req": m},
    }, true
}

func (s *brutalStream) Close(limited bool) *analyzer.PropUpdate {
    // 输出流量是否为 brutal 的判定结果
    propMap := analyzer.PropMap{
        "packetCount": s.packetCount,
        "lossCount":   s.lossCount,
        "lossRate":    float64(s.lossCount) / float64(s.packetCount),
        "score":       s.score,
    }

    if s.isBrutal {
        propMap["isBrutal"] = true
    }

    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M:    propMap,
    }
}
