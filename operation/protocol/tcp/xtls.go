package tcp

import (
    "encoding/binary"
    "fmt"
    "time"

    "github.com/uQUIC/XGFW/operation/protocol"
)

// XTLS 检测相关的常量定义
const (
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

    // Define the missing constant
    XTLSBlockThreshold  = 10  // Example value, adjust as necessary
)

// XTLSDetectionStats 存储单个连接的检测统计
type XTLSDetectionStats struct {
    // Alert pattern detection
    AlertPatternFound    bool
    AlertRecordCount     int
    LastAlertSize        int
    AlertTimings         []time.Duration

    // RTT analysis
    UpstreamRTTs         []time.Duration
    LocalRTTs            []time.Duration
    RTTDifferential      float64

    // Version detection
    TLSVersion           uint16
    VersionMismatch      bool
    
    // Nonce exposure (TLS 1.2)
    NonceExposed         bool
    SequenceNumbers      []uint64

    // Timing data
    FirstPacketTime      time.Time
    LastPacketTime       time.Time
    
    // Score calculation
    TotalScore           int
    DetectionConfidence  float64
}

// XTLSStream represents an analyzed TCP stream
type xtlsStream struct {
    logger         analyzer.Logger
    info           analyzer.TCPInfo
    stats          XTLSDetectionStats
    buffer         []byte
    lastPacketTime time.Time
    upstreamAddr   string
}

// TLS Record Header
type tlsRecordHeader struct {
    Type    byte
    Version uint16
    Length  uint16
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

// detectXTLSPatterns 检测 XTLS 的特征模式
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

// Feed processes incoming TCP data
func (s *xtlsStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
    if skip != 0 || len(data) == 0 {
        return nil, false
    }

    s.detectXTLSPatterns(data, rev)

    // 在连接结束时进行最终分析
    if end {
        s.calculateDetectionConfidence()
        
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "is_xtls":            s.stats.TotalScore >= XTLSBlockThreshold,
                "confidence":         s.stats.DetectionConfidence,
                "alert_pattern":      s.stats.AlertPatternFound,
                "rtt_differential":   s.stats.RTTDifferential,
                "version_mismatch":   s.stats.VersionMismatch,
                "nonce_exposed":      s.stats.NonceExposed,
                "total_score":        s.stats.TotalScore,
            },
        }, true
    }

    return nil, false
}

// calculateDetectionConfidence 计算检测置信度
func (s *xtlsStream) calculateDetectionConfidence() {
    // 基于多个特征的加权计算
    totalWeight := 0.0
    weightedScore := 0.0

    // Alert pattern weight (40%)
    if s.stats.AlertPatternFound {
        weightedScore += 40.0
    }
    totalWeight += 40.0

    // RTT differential weight (30%)
    if s.stats.RTTDifferential > float64(rttThreshold) {
        weightedScore += 30.0 * (s.stats.RTTDifferential / float64(rttThreshold))
    }
    totalWeight += 30.0

    // Version mismatch weight (15%)
    if s.stats.VersionMismatch {
        weightedScore += 15.0
    }
    totalWeight += 15.0

    // Nonce exposure weight (15%)
    if s.stats.NonceExposed {
        weightedScore += 15.0
    }
    totalWeight += 15.0

    s.stats.DetectionConfidence = (weightedScore / totalWeight) * 100.0
}

// Helper functions
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
