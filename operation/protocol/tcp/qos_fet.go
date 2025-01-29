package tcp

import (
    "math/rand"
    "os"
    "strconv"
    "time"

    "github.com/uQUIC/XGFW/operation/protocol"
)

const (
    defaultDropRateQos = 10 // 默认丢包率为10%
)

var _ analyzer.TCPAnalyzer = (*FETAnalyzerQos)(nil)

// FETAnalyzerQos stands for "Fully Encrypted Traffic QoS" analyzer.
// It implements an algorithm to detect fully encrypted proxy protocols
// such as Shadowsocks, mentioned in the following paper:
// https://gfw.report/publications/usenixsecurity23/data/paper/paper.pdf
type FETAnalyzerQos struct{}

func (a *FETAnalyzerQos) Name() string {
    return "fet-qos"
}

func (a *FETAnalyzerQos) Limit() int {
    // We only really look at the first packet
    return 8192
}

func (a *FETAnalyzerQos) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    dropRate := getDropRateQos()
    return newFETStreamQos(logger, dropRate)
}

type fetStreamQos struct {
    logger   analyzer.Logger
    dropRate int    // 丢包率
    rand     *rand.Rand
}

func newFETStreamQos(logger analyzer.Logger, dropRate int) *fetStreamQos {
    return &fetStreamQos{
        logger:   logger,
        dropRate: dropRate,
        rand:     rand.New(rand.NewSource(time.Now().UnixNano())),
    }
}

func (s *fetStreamQos) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
    if skip != 0 {
        return nil, true
    }
    if len(data) == 0 {
        return nil, false
    }

    // 根据丢包率决定是否丢弃数据包
    if s.rand.Float64()*100 < float64(s.dropRate) {
        return nil, false
    }

    ex1 := averagePopCountQos(data)
    ex2 := isFirstSixPrintableQos(data)
    ex3 := printablePercentageQos(data)
    ex4 := contiguousPrintableQos(data)
    ex5 := isTLSorHTTPQos(data)
    exempt := (ex1 <= 3.4 || ex1 >= 4.6) || ex2 || ex3 > 0.5 || ex4 > 20 || ex5
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M: analyzer.PropMap{
            "ex1": ex1,
            "ex2": ex2,
            "ex3": ex3,
            "ex4": ex4,
            "ex5": ex5,
            "yes": !exempt,
        },
    }, true
}

func (s *fetStreamQos) Close(limited bool) *analyzer.PropUpdate {
    return nil
}

func popCountQos(b byte) int {
    count := 0
    for b != 0 {
        count += int(b & 1)
        b >>= 1
    }
    return count
}

// averagePopCountQos returns the average popcount of the given bytes.
// This is the "Ex1" metric in the paper.
func averagePopCountQos(bytes []byte) float32 {
    if len(bytes) == 0 {
        return 0
    }
    total := 0
    for _, b := range bytes {
        total += popCountQos(b)
    }
    return float32(total) / float32(len(bytes))
}

// isFirstSixPrintableQos returns true if the first six bytes are printable ASCII.
// This is the "Ex2" metric in the paper.
func isFirstSixPrintableQos(bytes []byte) bool {
    if len(bytes) < 6 {
        return false
    }
    for i := range bytes[:6] {
        if !isPrintableQos(bytes[i]) {
            return false
        }
    }
    return true
}

// printablePercentageQos returns the percentage of printable ASCII bytes.
// This is the "Ex3" metric in the paper.
func printablePercentageQos(bytes []byte) float32 {
    if len(bytes) == 0 {
        return 0
    }
    count := 0
    for i := range bytes {
        if isPrintableQos(bytes[i]) {
            count++
        }
    }
    return float32(count) / float32(len(bytes))
}

// contiguousPrintableQos returns the length of the longest contiguous sequence of
// printable ASCII bytes.
// This is the "Ex4" metric in the paper.
func contiguousPrintableQos(bytes []byte) int {
    if len(bytes) == 0 {
        return 0
    }
    maxCount := 0
    current := 0
    for i := range bytes {
        if isPrintableQos(bytes[i]) {
            current++
        } else {
            if current > maxCount {
                maxCount = current
            }
            current = 0
        }
    }
    if current > maxCount {
        maxCount = current
    }
    return maxCount
}

// isTLSorHTTPQos returns true if the given bytes look like TLS or HTTP.
// This is the "Ex5" metric in the paper.
func isTLSorHTTPQos(bytes []byte) bool {
    if len(bytes) < 3 {
        return false
    }
    // "We observe that the GFW exempts any connection whose first
    // three bytes match the following regular expression:
    // [\x16-\x17]\x03[\x00-\x09]" - from the paper in Section 4.3
    if bytes[0] >= 0x16 && bytes[0] <= 0x17 &&
        bytes[1] == 0x03 && bytes[2] <= 0x09 {
        return true
    }
    // HTTP request
    str := string(bytes[:3])
    return str == "GET" || str == "HEA" || str == "POS" ||
        str == "PUT" || str == "DEL" || str == "CON" ||
        str == "OPT" || str == "TRA" || str == "PAT"
}

func isPrintableQos(b byte) bool {
    return b >= 0x20 && b <= 0x7e
}

// getDropRateQos 从环境变量中获取丢包率，默认值为10%
func getDropRateQos() int {
    dropRateStr := os.Getenv("FET_DROP_RATE")
    if dropRateStr == "" {
        return defaultDropRateQos
    }

    dropRate, err := strconv.Atoi(dropRateStr)
    if err != nil || dropRate < 0 || dropRate > 100 {
        return defaultDropRateQos
    }

    return dropRate
}
