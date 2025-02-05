package tcp

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "time"

    "github.com/uQUIC/XGFW/operation/protocol"
)

var _ analyzer.TCPAnalyzer = (*XTLSAnalyzer)(nil)

// CCS stands for "Change Cipher Spec"
var trojanClassicCCS = []byte{20, 3, 3, 0, 1, 1}

const (
    trojanClassicUpLB    = 650
    trojanClassicUpUB    = 1000
    trojanClassicDownLB1 = 170
    trojanClassicDownUB1 = 180
    trojanClassicDownLB2 = 3000
    trojanClassicDownUB2 = 7500

    // TLS record types
    recordTypeHandshake     = 22
    recordTypeAlert         = 21
    recordTypeApplication   = 23
    recordTypeChangeCipher  = 20

    // TLS versions
    TLS10 = 0x0301
    TLS11 = 0x0302
    TLS12 = 0x0303
    TLS13 = 0x0304

    // Alert related constants
    closeNotifyAlert    = 0
    warningAlertLevel   = 1
    fatalAlertLevel     = 2

    // Detection thresholds
    minTLS13RecordSize  = 31
    maxTLS13RecordSize  = 65535
    rttThreshold        = 10 * time.Millisecond

    // Scoring system
    alertPatternScore   = 5
    rttDiffScore        = 3
    versionMismatchScore = 4
    nonceExposureScore  = 3

    XTLSBlockThreshold  = 10  // Example value, adjust as necessary
)

// XTLSAnalyzer uses a very simple packet length based check to determine
// if a TLS connection is actually the Trojan proxy protocol.
// The algorithm is from the following project, with small modifications:
// https://github.com/XTLS/Trojan-killer
// Warning: Experimental only. This method is known to have significant false positives and false negatives.
type XTLSAnalyzer struct{}

func (a *XTLSAnalyzer) Name() string {
    return "XTLSAnalyzer"
}

func (a *XTLSAnalyzer) Limit() int {
    return 16384
}

func (a *XTLSAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    return newXTLSStream(logger)
}

type xtlsStream struct {
    logger    analyzer.Logger
    active    bool
    upCount   int
    downCount int
    stats     XTLSDetectionStats
}

func newXTLSStream(logger analyzer.Logger) *xtlsStream {
    return &xtlsStream{logger: logger}
}

func (s *xtlsStream) analyzeTLSRecord(data []byte) (*tlsRecordHeader, error) {
    if len(data) < 5 {
        return nil, fmt.Errorf("insufficient data for TLS record header")
    }

    header := &tlsRecordHeader{
        Type:    data[0],
        Version: binary.BigEndian.Uint16(data[1:3]),
        Length:  binary.BigEndian.Uint16(data[3:5]),
    }

    return header, nil
}

func (s *xtlsStream) detectXTLSPatterns(data []byte, rev bool) {
    now := time.Now()
    
    // 1. Alert Pattern Detection
    if !rev {
        if header, err := s.analyzeTLSRecord(data); err == nil {
            if header.Type == recordTypeAlert {
                s.stats.AlertRecordCount++
                s.stats.LastAlertSize = int(header.Length)
                s.stats.AlertTimings = append(s.stats.AlertTimings, time.Since(s.lastPacketTime))

                // 检查典型的 XTLS alert pattern
                if header.Length == 26 && len(data) >= 7 {
                    alertLevel := data[5]
                    alertDesc := data[6]
                    if alertLevel == warningAlertLevel && alertDesc == closeNotifyAlert {
                        s.stats.AlertPatternFound = true
                        s.stats.TotalScore += alertPatternScore
                    }
                }
            }
        }
    }

    // 2. RTT Analysis
    packetRTT := time.Since(s.lastPacketTime)
    if rev {
        s.stats.UpstreamRTTs = append(s.stats.UpstreamRTTs, packetRTT)
    } else {
        s.stats.LocalRTTs = append(s.stats.LocalRTTs, packetRTT)
    }

    // 计算 RTT 差异
    if len(s.stats.UpstreamRTTs) > 0 && len(s.stats.LocalRTTs) > 0 {
        avgUpstreamRTT := average(s.stats.UpstreamRTTs)
        avgLocalRTT := average(s.stats.LocalRTTs)
        s.stats.RTTDifferential = float64(avgUpstreamRTT - avgLocalRTT)
        
        if abs(s.stats.RTTDifferential) > float64(rttThreshold) {
            s.stats.TotalScore += rttDiffScore
        }
    }

    // 3. Version Detection
    if header, err := s.analyzeTLSRecord(data); err == nil {
        if s.stats.TLSVersion == 0 {
            s.stats.TLSVersion = header.Version
        } else if header.Version != s.stats.TLSVersion {
            s.stats.VersionMismatch = true
            s.stats.TotalScore += versionMismatchScore
        }

        // 4. Nonce Exposure Detection (TLS 1.2)
        if s.stats.TLSVersion == TLS12 {
            if len(data) >= 13 { // TLS 1.2 explicit nonce size
                seqNum := binary.BigEndian.Uint64(data[5:13])
                s.stats.SequenceNumbers = append(s.stats.SequenceNumbers, seqNum)
                if len(s.stats.SequenceNumbers) > 1 {
                    // Check if sequence numbers are predictable
                    if isSequential(s.stats.SequenceNumbers) {
                        s.stats.NonceExposed = true
                        s.stats.TotalScore += nonceExposureScore
                    }
                }
            }
        }
    }

    // Update timing information
    s.lastPacketTime = now
}

func (s *xtlsStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
    if skip != 0 {
        return nil, true
    }
    if len(data) == 0 {
        return nil, false
    }
    if !rev && !s.active && len(data) >= 6 && bytes.Equal(data[:6], trojanClassicCCS) {
        // Client CCS encountered, start counting
        s.active = true
    }
    if s.active {
        s.detectXTLSPatterns(data, rev)
        if rev {
            // Down direction
            s.downCount += len(data)
        } else {
            // Up direction
            if s.upCount >= trojanClassicUpLB && s.upCount <= trojanClassicUpUB &&
                ((s.downCount >= trojanClassicDownLB1 && s.downCount <= trojanClassicDownUB1) ||
                    (s.downCount >= trojanClassicDownLB2 && s.downCount <= trojanClassicDownUB2)) {
                return &analyzer.PropUpdate{
                    Type: analyzer.PropUpdateReplace,
                    M: analyzer.PropMap{
                        "up":   s.upCount,
                        "down": s.downCount,
                        "yes":  true,
                    },
                }, true
            }
            s.upCount += len(data)
        }
    }
    // Give up when either direction is over the limit
    return nil, s.upCount > trojanClassicUpUB || s.downCount > trojanClassicDownUB2
}

func (s *xtlsStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}

func average(durations []time.Duration) time.Duration {
    if len(durations) == 0 {
        return 0
    }
    var sum time.Duration
    for _, d := range durations {
        sum += d
    }
    return sum / time.Duration(len(durations))
}

func abs(x float64) float64 {
    if x < 0 {
        return -x
    }
    return x
}

func isSequential(numbers []uint64) bool {
    if len(numbers) < 2 {
        return false
    }
    diff := numbers[1] - numbers[0]
    for i := 2; i < len(numbers); i++ {
        if numbers[i]-numbers[i-1] != diff {
            return false
        }
    }
    return true
}
