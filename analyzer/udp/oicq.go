package udp

import (
    "encoding/binary"
    "github.com/uQUIC/XGFW/operation/protocol"
    "bytes"
)

const (
    OICQPacketStartFlag = 0x02
    OICQPacketEndFlag   = 0x03
)

// OICQAnalyzer OICQ is an IM Software protocol, usually used by QQ
var _ analyzer.UDPAnalyzer = (*OICQAnalyzer)(nil)

type OICQAnalyzer struct{}

func (a *OICQAnalyzer) Name() string {
    return "oicq"
}

func (a *OICQAnalyzer) Limit() int {
    return 0
}

func (a *OICQAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
    return &OICQStream{logger: logger}
}

type OICQStream struct {
    logger analyzer.Logger
}

func (s *OICQStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
    m := parseOICQMessage(data)
    if m == nil {
        return nil, false // Continue analyzing further packets
    }
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M:    m,
    }, true // Stop analyzing after a successful detection
}

func (s *OICQStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}

func parseOICQMessage(data []byte) analyzer.PropMap {
    // OICQ packets can vary in length, but typically have a header and a payload
    if len(data) < 10 {
        return nil
    }

    // Check for the start flag at any position due to potential packet fragmentation
    startIndex := bytes.IndexByte(data, OICQPacketStartFlag)
    if startIndex == -1 || startIndex+1 >= len(data) {
        return nil
    }

    // Attempt to parse the packet starting from the start flag
    data = data[startIndex+1:]

    // Check if there's enough data for the header fields
    if len(data) < 9 {
        return nil
    }

    version := binary.BigEndian.Uint16(data[0:2])
    command := binary.BigEndian.Uint16(data[2:4])
    seq := binary.BigEndian.Uint16(data[4:6])
    number := binary.BigEndian.Uint32(data[6:10])

    // Additional validation to reduce false positives
    if version == 0 || command == 0 || number == 0 {
        return nil
    }

    // Optionally, check for known OICQ versions or commands
    knownVersions := map[uint16]bool{
        0x0001: true,
        0x0002: true,
        // Add more known versions
    }

    if !knownVersions[version] {
        return nil
    }

    // Check for the end flag
    if data[len(data)-1] != OICQPacketEndFlag {
        return nil
    }

    m := analyzer.PropMap{
        "protocol": "oicq",
        "version":  version,
        "command":  command,
        "seq":      seq,
        "number":   number,
    }

    return m
}
