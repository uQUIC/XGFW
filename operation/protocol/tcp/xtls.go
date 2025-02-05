package tcp

// ... (保持原有的 imports)

// XTLS specific constants
const (
    // Alert patterns
    recordTypeAlert     = 21
    recordTypeHandshake = 22
    tlsVersion12       = 0x0303
    tlsVersion13       = 0x0304
    
    // Configuration for IP blocking
    XTLSResultFile    = "xtls_result.json"
    XTLSBlockFile     = "xtls_block.json"
    XTLSBasePath      = "/var/log/xgfw"
    
    // Scoring system
    AlertPatternScore    = 5
    VersionMismatchScore = 3
    NonceExposureScore   = 2
    BlockThreshold       = 20
)

// XTLSIPStats represents the statistics for a single IP
type XTLSIPStats struct {
    IP              string    `json:"ip"`
    Score           int       `json:"score"`
    FirstSeen       time.Time `json:"first_seen"`
    LastSeen        time.Time `json:"last_seen"`
    AlertCount      int       `json:"alert_count"`
    VersionMismatch int       `json:"version_mismatch"`
    NonceExposed    int       `json:"nonce_exposed"`
    TotalConnections int      `json:"total_connections"`
}

// XTLSResults holds all IP statistics
type XTLSResults struct {
    IPList []XTLSIPStats `json:"ip_list"`
    mu     sync.Mutex
}

// Global variables for XTLS detection
var (
    xtlsResults    *XTLSResults
    xtlsBlockedIPs map[string]struct{}
    xtlsMutex      sync.RWMutex
    xtlsInitialized bool
)

// xtlsStream represents a TCP stream being analyzed
type xtlsStream struct {
    logger        analyzer.Logger
    info          analyzer.TCPInfo
    buffer        []byte
    alertFound    bool
    versionSeen   uint16
    nonceExposed  bool
    streamStart   time.Time
    lastSeenAlert time.Time
    alertCount    int
    seqNumbers    []uint64
}

// Initialize XTLS statistics system
func initXTLSStats() error {
    if xtlsInitialized {
        return nil
    }
    xtlsMutex.Lock()
    defer xtlsMutex.Unlock()

    if xtlsInitialized {
        return nil
    }

    if err := os.MkdirAll(XTLSBasePath, 0755); err != nil {
        return fmt.Errorf("failed to create XTLS base directory: %w", err)
    }

    xtlsResults = &XTLSResults{
        IPList: make([]XTLSIPStats, 0),
    }
    xtlsBlockedIPs = make(map[string]struct{})

    // Load existing results
    if err := loadXTLSResults(); err != nil {
        return err
    }

    // Load blocked IPs
    if err := loadXTLSBlockList(); err != nil {
        return err
    }

    xtlsInitialized = true
    return nil
}

// Update XTLS IP statistics
func updateXTLSStats(ip string, stats *xtlsStream) error {
    if err := initXTLSStats(); err != nil {
        return err
    }

    xtlsResults.mu.Lock()
    defer xtlsResults.mu.Unlock()

    // Check if IP is already blocked
    if _, blocked := xtlsBlockedIPs[ip]; blocked {
        return nil
    }

    now := time.Now()
    var found bool
    
    // Calculate current detection score
    score := 0
    if stats.alertFound {
        score += AlertPatternScore
    }
    if stats.versionSeen == tlsVersion12 && stats.nonceExposed {
        score += NonceExposureScore
    }

    // Update existing IP stats
    for i := range xtlsResults.IPList {
        if xtlsResults.IPList[i].IP == ip {
            xtlsResults.IPList[i].LastSeen = now
            xtlsResults.IPList[i].TotalConnections++
            xtlsResults.IPList[i].Score += score
            
            if stats.alertFound {
                xtlsResults.IPList[i].AlertCount++
            }
            if stats.nonceExposed {
                xtlsResults.IPList[i].NonceExposed++
            }
            
            found = true

            // Check if score exceeds threshold
            if xtlsResults.IPList[i].Score >= BlockThreshold {
                if err := addToXTLSBlockList(ip); err != nil {
                    return fmt.Errorf("failed to add IP to XTLS block list: %w", err)
                }
            }
            break
        }
    }

    // Add new IP if not found
    if !found {
        xtlsResults.IPList = append(xtlsResults.IPList, XTLSIPStats{
            IP:               ip,
            Score:            score,
            FirstSeen:        now,
            LastSeen:         now,
            AlertCount:       stats.alertCount,
            NonceExposed:     boolToInt(stats.nonceExposed),
            TotalConnections: 1,
        })
    }

    return saveXTLSResults()
}

func (s *xtlsStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
    if skip != 0 || len(data) == 0 {
        return nil, false
    }

    // Focus on client -> server direction
    if !rev {
        s.buffer = append(s.buffer, data...)
        
        // Analyze TLS records in buffer
        offset := 0
        for offset < len(s.buffer) {
            if len(s.buffer[offset:]) < 5 {
                break
            }
            
            recordType := s.buffer[offset]
            version := binary.BigEndian.Uint16(s.buffer[offset+1:])
            length := binary.BigEndian.Uint16(s.buffer[offset+3:])
            
            if offset+5+int(length) > len(s.buffer) {
                break
            }

            // Original XTLS alert pattern detection
            if recordType == recordTypeAlert {
                if s := len(s.buffer) - 31; s >= 0 && s.buffer[s] == 21 {
                    if bytes.Equal(s.buffer[s:s+5], []byte{21, 3, 3, 0, 26}) {
                        s.alertFound = true
                        s.alertCount++
                        s.lastSeenAlert = time.Now()
                    }
                }
            }

            // Version tracking
            if s.versionSeen == 0 {
                s.versionSeen = version
            }

            // TLS 1.2 nonce exposure detection
            if version == tlsVersion12 && len(s.buffer[offset:]) >= 13 {
                seqNum := binary.BigEndian.Uint64(s.buffer[offset+5:offset+13])
                s.seqNumbers = append(s.seqNumbers, seqNum)
                if len(s.seqNumbers) >= 2 {
                    // Check for sequential numbers indicating exposure
                    if isSequentialNumbers(s.seqNumbers[len(s.seqNumbers)-2:]) {
                        s.nonceExposed = true
                    }
                }
            }

            offset += 5 + int(length)
        }

        // Maintain buffer size
        if len(s.buffer) > 65536 {
            s.buffer = s.buffer[len(s.buffer)-65536:]
        }
    }

    // Final analysis on connection end
    if end {
        dstIP := s.info.DstIP.String()
        
        // Check if IP is already blocked
        _, blocked := xtlsBlockedIPs[dstIP]
        if blocked {
            return &analyzer.PropUpdate{
                Type: analyzer.PropUpdateReplace,
                M: analyzer.PropMap{
                    "is_xtls": true,
                    "blocked": true,
                },
            }, true
        }

        // Update IP statistics
        if err := updateXTLSStats(dstIP, s); err != nil {
            s.logger.Errorf("Failed to update XTLS IP stats: %v", err)
        }

        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "is_xtls":        s.alertFound,
                "alert_count":    s.alertCount,
                "nonce_exposed":  s.nonceExposed,
                "version":        s.versionSeen,
            },
        }, true
    }

    return nil, false
}

// Helper functions

func isSequentialNumbers(numbers []uint64) bool {
    if len(numbers) < 2 {
        return false
    }
    diff := numbers[1] - numbers[0]
    return diff == 1
}

func boolToInt(b bool) int {
    if b {
        return 1
    }
    return 0
}

// Save XTLS results to file
func saveXTLSResults() error {
    data, err := json.MarshalIndent(xtlsResults.IPList, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal XTLS results: %w", err)
    }

    resultPath := filepath.Join(XTLSBasePath, XTLSResultFile)
    if err := os.WriteFile(resultPath, data, 0644); err != nil {
        return fmt.Errorf("failed to write XTLS results file: %w", err)
    }

    return nil
}

// Load XTLS results from file
func loadXTLSResults() error {
    resultPath := filepath.Join(XTLSBasePath, XTLSResultFile)
    data, err := os.ReadFile(resultPath)
    if err != nil {
        if os.IsNotExist(err) {
            return nil
        }
        return fmt.Errorf("failed to read XTLS results file: %w", err)
    }

    return json.Unmarshal(data, &xtlsResults.IPList)
}

// Add IP to XTLS block list
func addToXTLSBlockList(ip string) error {
    xtlsBlockedIPs[ip] = struct{}{}

    blockPath := filepath.Join(XTLSBasePath, XTLSBlockFile)
    var blockedList []string

    // Load existing blocked IPs
    if data, err := os.ReadFile(blockPath); err == nil {
        if err := json.Unmarshal(data, &blockedList); err != nil {
            return fmt.Errorf("failed to unmarshal XTLS blocked IPs: %w", err)
        }
    }

    // Add new IP if not already blocked
    if !contains(blockedList, ip) {
        blockedList = append(blockedList, ip)
    }

    // Save updated block list
    data, err := json.MarshalIndent(blockedList, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal XTLS blocked IPs: %w", err)
    }

    if err := os.WriteFile(blockPath, data, 0644); err != nil {
        return fmt.Errorf("failed to write XTLS block file: %w", err)
    }

    return nil
}

// Load XTLS block list from file
func loadXTLSBlockList() error {
    blockPath := filepath.Join(XTLSBasePath, XTLSBlockFile)
    data, err := os.ReadFile(blockPath)
    if err != nil {
        if os.IsNotExist(err) {
            return nil
        }
        return fmt.Errorf("failed to read XTLS block file: %w", err)
    }

    var blockedList []string
    if err := json.Unmarshal(data, &blockedList); err != nil {
        return fmt.Errorf("failed to unmarshal XTLS blocked IPs: %w", err)
    }

    for _, ip := range blockedList {
        xtlsBlockedIPs[ip] = struct{}{}
    }

    return nil
}
