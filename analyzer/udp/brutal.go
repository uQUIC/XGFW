package udp

import (
	"github.com/uQUIC/XGFW/analyzer"
	"github.com/uQUIC/XGFW/analyzer/internal"
	"github.com/uQUIC/XGFW/analyzer/udp/internal/quic"
	"github.com/uQUIC/XGFW/analyzer/utils"
	"math/rand"
	"time"
)

const (
	brutalInvalidCountThreshold = 4
	brutalMaxPacketLossRate     = 0.02 // 最大丢包率 2%
	positivityThreshold         = 0.5
	negativityThreshold         = 0.2
	maxScore                    = 20
	segmentsPerCheck            = 5
	checkWindowDuration         = 10 * time.Millisecond
)

var (
	_ analyzer.UDPAnalyzer = (*BrutalAnalyzer)(nil)
	_ analyzer.UDPStream   = (*brutalStream)(nil)
)

type BrutalAnalyzer struct{}

func (a *BrutalAnalyzer) Name() string {
	return "brutal"
}

func (a *BrutalAnalyzer) Limit() int {
	return 0
}

func (a *BrutalAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return &brutalStream{logger: logger}
}

type brutalStream struct {
	logger          analyzer.Logger
	invalidCount    int
	packetCount     int
	lossCount       int
	lastTime        time.Time
	lastPacketSize  int
	isBrutal        bool
	score           int           // Cumulative score based on segment analysis
	segmentScores   []float64     // Scores for each 10ms segment
}

// 模拟丢包和速率分析
func (s *brutalStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	// 丢包模拟：根据最大丢包率控制丢包概率
	if rand.Float64() < brutalMaxPacketLossRate {
		s.lossCount++
		return nil, false // 丢弃当前数据包
	}
	s.packetCount++

	// 计算传输速率（假设每个数据包大小是固定的，这里简化为1）
	now := time.Now()
	elapsed := now.Sub(s.lastTime).Seconds()
	if elapsed > 0 {
		packetRate := float64(s.packetCount) / elapsed
		lossRate := float64(s.lossCount) / float64(s.packetCount)

		// 判断流量是否符合 brutal 特征：速率与丢包率的反比关系
		if lossRate > 0.1 && packetRate > 0.5 {
			s.isBrutal = true
		}
	}

	// Check segments every 10ms and apply scoring mechanism
	if now.Sub(s.lastTime) >= checkWindowDuration {
		// Simulate the scoring logic for the segment within the 10ms window
		s.analyzeSegment(now, packetRate, lossRate)
		s.lastTime = now
	}

	// 最小数据包大小: 协议版本 (2 字节) + 随机数 (32 字节) + 会话ID (1 字节) + 密码套件 (4 字节) + 压缩方法 (2 字节) + 无扩展
	const minDataSize = 41

	if rev {
		// 不支持服务器方向的流量
		s.invalidCount++
		return nil, s.invalidCount >= brutalInvalidCountThreshold
	}

	pl, err := quic.ReadCryptoPayload(data)
	if err != nil || len(pl) < 4 {
		s.invalidCount++
		return nil, s.invalidCount >= brutalInvalidCountThreshold
	}

	if pl[0] != internal.TypeClientHello {
		s.invalidCount++
		return nil, s.invalidCount >= brutalInvalidCountThreshold
	}

	chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
	if chLen < minDataSize {
		s.invalidCount++
		return nil, s.invalidCount >= brutalInvalidCountThreshold
	}

	// 解析客户端握手消息
	m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
	if m == nil {
		s.invalidCount++
		return nil, s.invalidCount >= brutalInvalidCountThreshold
	}

	// 返回数据流的更新，包括当前请求信息
	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateMerge,
		M:    analyzer.PropMap{"req": m},
	}, true
}

func (s *brutalStream) analyzeSegment(now time.Time, packetRate, lossRate float64) {
	// Calculate expected rate based on packet loss rate
	expectedRate := packetRate * (1 - lossRate)
	rateDiff := packetRate - expectedRate

	// Score based on the rate diff
	var segmentScore float64
	if rateDiff < positivityThreshold {
		segmentScore = 2  // Positive
	} else if rateDiff > negativityThreshold {
		segmentScore = -1 // Negative
	}

	// Append to segmentScores and calculate cumulative score
	s.segmentScores = append(s.segmentScores, segmentScore)
	if len(s.segmentScores) > segmentsPerCheck {
		// Maintain only the latest 5 scores
		s.segmentScores = s.segmentScores[1:]
	}

	// Calculate the cumulative score
	s.score += int(segmentScore)
	if s.score < 0 {
		s.score = 0
	}

	// If score exceeds the maximum, flag as blocked
	if s.score >= maxScore {
		s.isBrutal = true
	}
}

func (s *brutalStream) Close(limited bool) *analyzer.PropUpdate {
	// 输出流量是否为 brutal 的判定结果
	if s.isBrutal {
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"isBrutal":   true,
				"packetCount": s.packetCount,
				"lossCount":  s.lossCount,
				"lossRate":   float64(s.lossCount) / float64(s.packetCount),
			},
		}
	}

	// 输出流量的基本统计信息
	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M: analyzer.PropMap{
			"packetCount": s.packetCount,
			"lossCount":   s.lossCount,
			"lossRate":    float64(s.lossCount) / float64(s.packetCount),
		},
	}
}
