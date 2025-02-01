package udp

import (
    "math/rand"
    "os"
    "strconv"
    "time"

    "github.com/uQUIC/XGFW/operation/protocol"
    "github.com/uQUIC/XGFW/operation/protocol/internal"
    "github.com/uQUIC/XGFW/operation/protocol/udp/internal/quic"
    "github.com/uQUIC/XGFW/operation/protocol/utils"
)

const (
    quicInvalidCountThreshold = 4
    defaultQoSDropRate       = 10 // 默认丢包率为10%
)

var _ analyzer.UDPAnalyzer = (*QUICQoSAnalyzer)(nil)

// QUICQoSAnalyzer 实现带QoS的QUIC分析器
type QUICQoSAnalyzer struct{}

func (a *QUICQoSAnalyzer) Name() string {
    return "quic-qos"
}

func (a *QUICQoSAnalyzer) Limit() int {
    return 0
}

func (a *QUICQoSAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
    dropRate := getQoSDropRate()
    return newQUICQoSStream(logger, dropRate)
}

type quicQoSStream struct {
    logger       analyzer.Logger
    invalidCount int
    dropRate     int    // 丢包率
    rand         *rand.Rand
    
    // 统计信息
    packetCount  int
    droppedCount int
    totalBytes   int
}

func newQUICQoSStream(logger analyzer.Logger, dropRate int) *quicQoSStream {
    return &quicQoSStream{
        logger:   logger,
        dropRate: dropRate,
        rand:     rand.New(rand.NewSource(time.Now().UnixNano())),
    }
}

func (s *quicQoSStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
    // 更新统计信息
    s.packetCount++
    s.totalBytes += len(data)

    // 根据丢包率决定是否丢弃数据包
    if s.rand.Float64()*100 < float64(s.dropRate) {
        s.droppedCount++
        return nil, false
    }

    // 最小数据大小要求
    const minDataSize = 41

    if rev {
        // 不支持服务器方向的流量
        s.invalidCount++
        return nil, s.invalidCount >= quicInvalidCountThreshold
    }

    // QUIC协议检测
    pl, err := quic.ReadCryptoPayload(data)
    if err != nil || len(pl) < 4 {
        s.invalidCount++
        return nil, s.invalidCount >= quicInvalidCountThreshold
    }

    if pl[0] != internal.TypeClientHello {
        s.invalidCount++
        return nil, s.invalidCount >= quicInvalidCountThreshold
    }

    chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
    if chLen < minDataSize {
        s.invalidCount++
        return nil, s.invalidCount >= quicInvalidCountThreshold
    }

    m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
    if m == nil {
        s.invalidCount++
        return nil, s.invalidCount >= quicInvalidCountThreshold
    }

    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateMerge,
        M: analyzer.PropMap{
            "req":   m,
            "stats": s.getStats(),
        },
    }, true
}

func (s *quicQoSStream) Close(limited bool) *analyzer.PropUpdate {
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M:    s.getStats(),
    }
}

// getStats 返回当前统计信息
func (s *quicQoSStream) getStats() analyzer.PropMap {
    return analyzer.PropMap{
        "packet_count":  s.packetCount,
        "total_bytes":   s.totalBytes,
        "dropped_count": s.droppedCount,
        "drop_rate":     s.dropRate,
    }
}

// getQoSDropRate 从环境变量中获取丢包率，默认值为10%
func getQoSDropRate() int {
    dropRateStr := os.Getenv("QUIC_DROP_RATE")
    if dropRateStr == "" {
        return defaultQoSDropRate
    }

    dropRate, err := strconv.Atoi(dropRateStr)
    if err != nil || dropRate < 0 || dropRate > 100 {
        return defaultQoSDropRate
    }

    return dropRate
}
