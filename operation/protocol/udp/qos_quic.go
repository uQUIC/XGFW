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
    quicInvalidCountThresholdQos = 4
    defaultDropRateQos           = 10 // 默认丢包率为10%
)

var (
    _ analyzer.UDPAnalyzer = (*QUICQoSAnalyzerQos)(nil)
    _ analyzer.UDPStream   = (*quicQoSStreamQos)(nil)
)

// QUICQoSAnalyzerQos 实现 analyzer.UDPAnalyzer 接口
type QUICQoSAnalyzerQos struct{}

func (a *QUICQoSAnalyzerQos) Name() string {
    return "quic-qos"
}

func (a *QUICQoSAnalyzerQos) Limit() int {
    return 0
}

func (a *QUICQoSAnalyzerQos) NewUDP(infoQos analyzer.UDPInfo, loggerQos analyzer.Logger) analyzer.UDPStream {
    dropRateQos := getDropRateQos()
    return &quicQoSStreamQos{
        loggerQos:   loggerQos,
        dropRateQos: dropRateQos,
        randQos:     rand.New(rand.NewSource(time.Now().UnixNano())),
    }
}

// quicQoSStreamQos 实现 analyzer.UDPStream 接口
type quicQoSStreamQos struct {
    loggerQos       analyzer.Logger
    invalidCountQos int
    dropRateQos     int // 丢包率
    randQos         *rand.Rand
}

func (s *quicQoSStreamQos) Feed(revQos bool, dataQos []byte) (uQos *analyzer.PropUpdate, doneQos bool) {
    // minimal data size: protocol version (2 bytes) + random (32 bytes) +
    //   + session ID (1 byte) + cipher suites (4 bytes) +
    //   + compression methods (2 bytes) + no extensions
    const minDataSizeQos = 41

    // 根据丢包率决定是否丢弃数据包
    if s.randQos.Float64()*100 < float64(s.dropRateQos) {
        return nil, false
    }

    if revQos {
        // We don't support server direction for now
        s.invalidCountQos++
        return nil, s.invalidCountQos >= quicInvalidCountThresholdQos
    }

    plQos, errQos := quic.ReadCryptoPayload(dataQos)
    if errQos != nil || len(plQos) < 4 {
        s.invalidCountQos++
        return nil, s.invalidCountQos >= quicInvalidCountThresholdQos
    }

    if plQos[0] != internal.TypeClientHello {
        s.invalidCountQos++
        return nil, s.invalidCountQos >= quicInvalidCountThresholdQos
    }

    chLenQos := int(plQos[1])<<16 | int(plQos[2])<<8 | int(plQos[3])
    if chLenQos < minDataSizeQos {
        s.invalidCountQos++
        return nil, s.invalidCountQos >= quicInvalidCountThresholdQos
    }

    mQos := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: plQos[4:]})
    if mQos == nil {
        s.invalidCountQos++
        return nil, s.invalidCountQos >= quicInvalidCountThresholdQos
    }

    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateMerge,
        M:    analyzer.PropMap{"req": mQos},
    }, true
}

func (s *quicQoSStreamQos) Close(limitedQos bool) *analyzer.PropUpdate {
    return nil
}

// getDropRateQos 从环境变量中获取丢包率，默认值为10%
func getDropRateQos() int {
    dropRateStrQos := os.Getenv("QUIC_DROP_RATE")
    if dropRateStrQos == "" {
        return defaultDropRateQos
    }

    dropRateQos, errQos := strconv.Atoi(dropRateStrQos)
    if errQos != nil || dropRateQos < 0 || dropRateQos > 100 {
        return defaultDropRateQos
    }

    return dropRateQos
}
