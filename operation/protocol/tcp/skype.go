package tcp

import (
    "bytes"
    "crypto/sha256"
    "time"
)

var _ analyzer.TCPAnalyzer = (*SkypeAnalyzer)(nil)

// Skype pattern signatures
var (
    headerPattern = []byte{0x02, 0x01, 0x47, 0x49}
    keepAlive    = []byte{0x02, 0x00}
    audioPattern = []byte{0x02, 0x0D}
    videoPattern = []byte{0x02, 0x0E}
)

// SkypeAnalyzer detects Skype traffic using pattern matching and behavioral analysis.
// The detection is based on multiple factors including packet sizes, timing patterns,
// and protocol signatures.
type SkypeAnalyzer struct{}

func (a *SkypeAnalyzer) Name() string {
    return "skype"
}

func (a *SkypeAnalyzer) Limit() int {
    return 512000
}

func (a *SkypeAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    return newSkypeStream(logger)
}

type skypeStream struct {
    logger      analyzer.Logger
    features    []packetFeature
    first       bool
    count       bool
    blocked     bool
    bytesCount  uint64
    packetCount uint32
    lastSeen    time.Time
}

type packetFeature struct {
    size      uint16
    hash      [32]byte
    timestamp time.Time
    direction uint8 // 0: outbound, 1: inbound
}

func newSkypeStream(logger analyzer.Logger) *skypeStream {
    return &skypeStream{
        logger:   logger,
        features: make([]packetFeature, 0, 1000),
        first:    true,
        lastSeen: time.Now(),
    }
}

func (s *skypeStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
    if skip != 0 {
        return nil, true
    }
    if len(data) == 0 {
        return nil, false
    }

    // Extract features
    feature := packetFeature{
        size:      uint16(len(data)),
        timestamp: time.Now(),
    }
    if rev {
        feature.direction = 1
    }
    if len(data) > 0 {
        feature.hash = sha256.Sum256(data)
    }

    // Update state
    s.features = append(s.features, feature)
    s.bytesCount += uint64(len(data))
    s.packetCount++
    s.lastSeen = feature.timestamp

    // Analyze traffic
    if s.shouldAnalyze() {
        isSkype := s.analyzeTraffic()
        if isSkype {
            s.blocked = true
            return &analyzer.PropUpdate{
                Type: analyzer.PropUpdateReplace,
                M: analyzer.PropMap{
                    "yes": true,
                },
            }, true
        }
    }

    return nil, false
}

func (s *skypeStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}

func (s *skypeStream) shouldAnalyze() bool {
    return len(s.features) >= 10 && s.packetCount > 20 && s.bytesCount > 1000
}

func (s *skypeStream) analyzeTraffic() bool {
    // 1. Size distribution analysis
    var smallPackets, mediumPackets, largePackets int
    for _, f := range s.features {
        switch {
        case f.size < 100:
            smallPackets++
        case f.size < 500:
            mediumPackets++
        default:
            largePackets++
        }
    }

    // 2. Pattern analysis
    patterns := s.analyzePatterns()
    if !patterns {
        return false
    }

    // 3. Timing analysis
    intervals := s.analyzeIntervals()
    if !intervals {
        return false
    }

    // 4. Payload analysis
    payloadMatch := s.analyzePayload()
    if !payloadMatch {
        return false
    }

    // Final scoring
    score := 0
    if float64(smallPackets)/float64(len(s.features)) > 0.6 {
        score += 2
    }
    if patterns {
        score += 3
    }
    if intervals {
        score += 2
    }
    if payloadMatch {
        score += 3
    }

    return score >= 8
}

func (s *skypeStream) analyzePatterns() bool {
    var pattern uint16
    startIdx := len(s.features) - 10
    for i := startIdx; i < len(s.features); i++ {
        pattern = (pattern << 1) | uint16(s.features[i].direction)
    }

    return pattern&0x0F0F == 0x0505 || pattern&0x0F0F == 0x0A0A
}

func (s *skypeStream) analyzeIntervals() bool {
    if len(s.features) < 3 {
        return false
    }

    var heartbeatCount int
    for i := 1; i < len(s.features); i++ {
        interval := s.features[i].timestamp.Sub(s.features[i-1].timestamp)
        if interval >= 20*time.Millisecond && interval <= 30*time.Millisecond {
            heartbeatCount++
        }
    }

    return heartbeatCount >= (len(s.features)-1)/3
}

func (s *skypeStream) analyzePayload() bool {
    var matches int
    patterns := [][]byte{headerPattern, keepAlive, audioPattern, videoPattern}

    for _, f := range s.features {
        for _, pattern := range patterns {
            if bytes.Contains(f.hash[:], pattern) {
                matches++
                break
            }
        }
    }

    return matches >= 3
}
