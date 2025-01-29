package udp

import (
    "github.com/uQUIC/XGFW/operation/protocol"
    "github.com/uQUIC/XGFW/operation/protocol/internal"
    "github.com/uQUIC/XGFW/operation/protocol/udp/internal/quic"
    "github.com/uQUIC/XGFW/operation/protocol/utils"
)

const (
    customQuicInvalidCountThreshold = 4
)

var (
    _ analyzer.UDPAnalyzer = (*CustomQUICAnalyzer)(nil)
    _ analyzer.UDPStream   = (*CustomQUICStream)(nil)
)

type CustomQUICAnalyzer struct{}

func (a *CustomQUICAnalyzer) Name() string {
    return "custom-quic"
}

func (a *CustomQUICAnalyzer) Limit() int {
    return 0
}

func (a *CustomQUICAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
    return &CustomQUICStream{customLogger: logger}
}

type CustomQUICStream struct {
    customLogger       analyzer.Logger
    customInvalidCount int
}

func (s *CustomQUICStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
    // minimal data size: protocol version (2 bytes) + random (32 bytes) +
    //   + session ID (1 byte) + cipher suites (4 bytes) +
    //   + compression methods (2 bytes) + no extensions
    const customMinDataSize = 41

    if rev {
        // We don't support server direction for now
        s.customInvalidCount++
        return nil, s.customInvalidCount >= customQuicInvalidCountThreshold
    }

    pl, err := quic.ReadCryptoPayload(data)
    if err != nil || len(pl) < 4 { // FIXME: isn't length checked inside quic.ReadCryptoPayload? Also, what about error handling?
        s.customInvalidCount++
        return nil, s.customInvalidCount >= customQuicInvalidCountThreshold
    }

    if pl[0] != internal.TypeClientHello {
        s.customInvalidCount++
        return nil, s.customInvalidCount >= customQuicInvalidCountThreshold
    }

    chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
    if chLen < customMinDataSize {
        s.customInvalidCount++
        return nil, s.customInvalidCount >= customQuicInvalidCountThreshold
    }

    m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
    if m == nil {
        s.customInvalidCount++
        return nil, s.customInvalidCount >= customQuicInvalidCountThreshold
    }

    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateMerge,
        M:    analyzer.PropMap{"req": m},
    }, true
}

func (s *CustomQUICStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}
