package qos_udp

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
    defaultDropRate           = 10 // 默认丢包率为10%
)

var (
    _ analyzer.UDPAnalyzer = (*QUICQoSAnalyzer)(nil)
    _ analyzer.UDPStream   = (*quicQoSStream)(nil)
)

// QUICQoSAnalyzer 实现 analyzer.UDPAnalyzer 接口
type QUICQoSAnalyzer struct{}

func (a *QUICQoSAnalyzer) Name() string {
    return "quic-qos"
}

func (a *QUICQoSAnalyzer) Limit() int {
    return 0
}

func (a *QUICQoSAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
    dropRate := getDropRate()
    return &quicQoSStream{
        logger:   logger,
        dropRate: dropRate,
        rand:     rand.New(rand.NewSource(time.Now().UnixNano())),
    }
}

// quicQoSStream 实现 analyzer.UDPStream 接口
type quicQoSStream struct {
    logger       analyzer.Logger
    invalidCount int
    dropRate     int // 丢包率
    rand         *rand.Rand
}

func (s *quicQoSStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
    // minimal data size: protocol version (2 bytes) + random (32 bytes) +
    //   + session ID (1 byte) + cipher suites (4 bytes) +
    //   + compression methods (2 bytes) + no extensions
    const minDataSize = 41

    // 根据丢包率决定是否丢弃数据包
    if s.rand.Float64()*100 < float64(s.dropRate) {
        return nil, false
    }

    if rev {
        // We don't support server direction for now
        s.invalidCount++
        return nil, s.invalidCount >= quicInvalidCountThreshold
    }

    pl, err := quic.ReadCryptoPayload(data)
    if err != nil || len(pl) < 4 { // FIXME: isn't length checked inside quic.ReadCryptoPayload? Also, what about error handling?
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
        M:    analyzer.PropMap{"req": m},
    }, true
}

func (s *quicQoSStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}

// getDropRate 从环境变量中获取丢包率，默认值为10%
func getDropRate() int {
    dropRateStr := os.Getenv("QUIC_DROP_RATE")
    if dropRateStr == "" {
        return defaultDropRate
    }

    dropRate, err := strconv.Atoi(dropRateStr)
    if err != nil || dropRate < 0 || dropRate > 100 {
        return defaultDropRate
    }

    return dropRate
}
