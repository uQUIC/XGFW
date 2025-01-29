package tcp

import (
    "math/rand"
    "os"
    "strconv"
    "time"

    "github.com/uQUIC/XGFW/operation/protocol"
    "github.com/uQUIC/XGFW/ruleset/builtins/tor"
)

const (
    defaultDropRate = 10 // 默认丢包率为10%
)

var _ analyzer.TCPAnalyzer = (*TorQoSAnalyzer)(nil)

type TorQoSAnalyzer struct {
    directory tor.TorDirectory
}

func (a *TorQoSAnalyzer) Init() error {
    var err error
    a.directory, err = tor.GetOnionooDirectory()
    return err
}

func (a *TorQoSAnalyzer) Name() string {
    return "tor-qos"
}

// For now only TCP metadata is needed
func (a *TorQoSAnalyzer) Limit() int {
    return 1
}

func (a *TorQoSAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    isRelay := a.directory.Query(info.DstIP, info.DstPort)
    dropRate := getDropRate()
    return newTorQoSStream(logger, isRelay, dropRate)
}

type torQoSStream struct {
    logger   analyzer.Logger
    isRelay  bool   // Public relay identifier
    dropRate int    // 丢包率
    rand     *rand.Rand
}

func newTorQoSStream(logger analyzer.Logger, isRelay bool, dropRate int) *torQoSStream {
    return &torQoSStream{
        logger:   logger,
        isRelay:  isRelay,
        dropRate: dropRate,
        rand:     rand.New(rand.NewSource(time.Now().UnixNano())),
    }
}

func (s *torQoSStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
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

    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M: analyzer.PropMap{
            "relay": s.isRelay,
        },
    }, true
}

func (s *torQoSStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}

// getDropRate 从环境变量中获取丢包率，默认值为10%
func getDropRate() int {
    dropRateStr := os.Getenv("TOR_DROP_RATE")
    if dropRateStr == "" {
        return defaultDropRate
    }

    dropRate, err := strconv.Atoi(dropRateStr)
    if err != nil || dropRate < 0 || dropRate > 100 {
        return defaultDropRate
    }

    return dropRate
}
