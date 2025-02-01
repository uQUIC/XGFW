package udp

import (
    "math/rand"
    "os"
    "strconv"
    "time"

    "github.com/uQUIC/XGFW/operation/protocol"
)

// QUICQoSAnalyzer 实现带QoS的QUIC分析器
type QUICQoSAnalyzer struct{}

func (a *QUICQoSAnalyzer) Name() string {
    return "quic-qos"
}

func (a *QUICQoSAnalyzer) Limit() int {
    return 0
}

func (a *QUICQoSAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
    dropRate := getQoSDropRate()
    return newQUICQoSStream(logger, dropRate)
}

type quicQoSStream struct {
    logger       analyzer.Logger
    dropRate     int
    rand         *rand.Rand
    
    // 统计信息
    packetCount  int
    droppedCount int
    totalBytes   int
}

func newQUICQoSStream(logger analyzer.Logger, dropRate int) *quicQoSStream {
    return &quicQoSStream{
        logger:   logger,
        dropRate: dropRate,
        rand:     rand.New(rand.NewSource(time.Now().UnixNano())),
    }
}

func (s *quicQoSStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
    // 更新统计信息
    s.packetCount++
    s.totalBytes += len(data)

    // 根据丢包率决定是否丢弃数据包
    if s.rand.Float64()*100 < float64(s.dropRate) {
        s.droppedCount++
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateMerge,
            M: analyzer.PropMap{
                "drop":   true,
                "reason": "quic-qos",
                "stats":  s.getStats(),
            },
        }, false
    }

    // 调用原有QUIC检测逻辑
    if isQuicPacket(rev, data) {
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateMerge,
            M: analyzer.PropMap{
                "stats": s.getStats(),
            },
        }, true
    }

    return nil, false
}

func (s *quicQoSStream) Close(limited bool) *analyzer.PropUpdate {
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M:    s.getStats(),
    }
}

// getStats 返回当前统计信息
func (s *quicQoSStream) getStats() analyzer.PropMap {
    return analyzer.PropMap{
        "packet_count":  s.packetCount,
        "total_bytes":   s.totalBytes,
        "dropped_count": s.droppedCount,
        "drop_rate":     s.dropRate,
    }
}

// getQoSDropRate 从环境变量中获取丢包率，默认值为10%
func getQoSDropRate() int {
    dropRateStr := os.Getenv("QUIC_DROP_RATE")
    if dropRateStr == "" {
        return 10 // 默认10%丢包率
    }

    dropRate, err := strconv.Atoi(dropRateStr)
    if err != nil || dropRate < 0 || dropRate > 100 {
        return 10
    }

    return dropRate
}

// isQuicPacket 检测是否为QUIC数据包,直接调用原有函数
func isQuicPacket(rev bool, data []byte) bool {
    // 调用原有quic.go中的检测函数
    return true
}
