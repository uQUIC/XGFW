package udp

import (
    "bytes"
    "crypto/sha256"
    "log"
    "time"

    "github.com/uQUIC/XGFW/operation/protocol"
)

var _ analyzer.UDPAnalyzer = (*SkypeMorphAnalyzer)(nil)

// SkypeMorphAnalyzer uses heuristics to detect SkypeMorph traffic based on
// its imitation of Skype protocols. The heuristics are based on known discrepancies
// in SkypeMorph's imitation of Skype traffic.
type SkypeMorphAnalyzer struct{}

func (a *SkypeMorphAnalyzer) Name() string {
    return "skypemorph"
}

func (a *SkypeMorphAnalyzer) Limit() int {
    return 512000
}

func (a *SkypeMorphAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
    return newSkypeMorphStream(logger)
}

type skypeMorphStream struct {
    logger   analyzer.Logger
    first    bool
    seq      [4]int
    seqIndex int
    features []PacketFeatures
}

// PacketFeatures stores packet-specific features
type PacketFeatures struct {
    Size        uint16
    PayloadHash [32]byte
    Timestamp   time.Time
    Direction   uint8 // 0: outbound, 1: inbound
}

func newSkypeMorphStream(logger analyzer.Logger) *skypeMorphStream {
    return &skypeMorphStream{
        logger:   logger,
        features: make([]PacketFeatures, 0, 1000),
        first:    true,
    }
}

func (s *skypeMorphStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
    if len(data) == 0 {
        return nil, false
    }

    // Extract features
    feature := PacketFeatures{
        Size:      uint16(len(data)),
        Timestamp: time.Now(),
    }
    if rev {
        feature.Direction = 1
    }
    if len(data) > 0 {
        feature.PayloadHash = sha256.Sum256(data)
    }

    // Update state
    s.features = append(s.features, feature)
    s.seq[s.seqIndex] += len(data)

    // Analyze traffic
    if s.shouldAnalyze() {
        isSkypeMorph := s.analyzeTraffic()
        if isSkypeMorph {
            log.Printf("INFO: Detected SkypeMorph traffic")
            return &analyzer.PropUpdate{
                Type: analyzer.PropUpdateReplace,
                M: analyzer.PropMap{
                    "yes":    true,
                    "result": "skypemorph",
                },
            }, true
        }
    }

    return nil, false
}

func (s *skypeMorphStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}

func (s *skypeMorphStream) shouldAnalyze() bool {
    return len(s.features) >= 10 && s.seqIndex >= 3
}

func (s *skypeMorphStream) analyzeTraffic() bool {
    // 1. Check for typical SkypeMorph packet pattern
    if s.seq[0] <= 100 && s.seq[1] <= 500 && s.seq[2] <= 1000 && s.seq[3] <= 1500 {
        return true
    }

    // 2. Check for SkypeMorph-specific payload patterns
    for _, f := range s.features {
        if bytes.Contains(f.PayloadHash[:], []byte{0x02, 0x01, 0x47, 0x49}) {
            return true
        }
    }

    // 3. Check for periodic message patterns
    var intervals []time.Duration
    for i := 1; i < len(s.features); i++ {
        interval := s.features[i].Timestamp.Sub(s.features[i-1].Timestamp)
        intervals = append(intervals, interval)
    }
    var heartbeatCount int
    for _, interval := range intervals {
        if interval >= 20*time.Millisecond && interval <= 30*time.Millisecond {
            heartbeatCount++
        }
    }
    return heartbeatCount >= len(intervals)/3
}
