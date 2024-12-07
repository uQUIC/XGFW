// udp/brutal_analyzer.go
package udp

import (
	"math/rand"
	"sync"
	"time"

	"github.com/uQUIC/XGFW/analyzer"
)

// 常量定义
const (
	brutalInvalidCountThreshold = 4
	brutalMaxPacketLossRate     = 0.02 // 最大丢包率 2%
)

// 评分参数和阈值
const (
	brutalPositiveIncrement = 2
	brutalNegativeDecrement = 1
	brutalScoreThreshold    = 20
)

// 确保实现接口
var (
	_ analyzer.UDPAnalyzer = (*BrutalAnalyzer)(nil)
	_ analyzer.UDPStream   = (*brutalStream)(nil)
)

// BrutalAnalyzer 是 UDP 流量分析器
type BrutalAnalyzer struct {
	PositiveScore              int
	NegativeScore              int
	ScoreThreshold             int
	DetectionWindowDuration    time.Duration
	DetectionWindowCount       int
	DirectionDetectionEnabled  bool

	mu sync.RWMutex
}

// NewBrutalAnalyzer 构造函数，允许自定义参数
func NewBrutalAnalyzer(
	positiveScore, negativeScore, scoreThreshold int,
	detectionWindowDuration time.Duration,
	detectionWindowCount int,
	directionDetectionEnabled bool,
) *BrutalAnalyzer {
	return &BrutalAnalyzer{
		PositiveScore:             positiveScore,
		NegativeScore:             negativeScore,
		ScoreThreshold:            scoreThreshold,
		DetectionWindowDuration:   detectionWindowDuration,
		DetectionWindowCount:      detectionWindowCount,
		DirectionDetectionEnabled: directionDetectionEnabled,
	}
}

// Name 返回分析器的名称
func (a *BrutalAnalyzer) Name() string {
	return "brutal"
}

// Limit 返回分析器的限制，这里设置为0表示无限制
func (a *BrutalAnalyzer) Limit() int {
	return 0
}

// NewUDP 创建并返回一个新的 brutalStream 实例
func (a *BrutalAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return &brutalStream{
		logger:                    logger,
		positiveScore:             a.PositiveScore,
		negativeScore:             a.NegativeScore,
		scoreThreshold:            a.ScoreThreshold,
		detectionWindowDuration:   a.DetectionWindowDuration,
		detectionWindowCount:      a.DetectionWindowCount,
		directionDetectionEnabled: a.DirectionDetectionEnabled,
		detectionWindows:          make(map[bool][]float64),
		windowStartTime:           make(map[bool]time.Time),
	}
}

// brutalStream 分析单个UDP流
type brutalStream struct {
	logger       analyzer.Logger
	invalidCount int
	packetCount  int
	lossCount    int
	lastTime     time.Time
	isBrutal     bool

	positiveScore             int
	negativeScore             int
	totalScore                int
	scoreThreshold            int
	directionDetectionEnabled bool

	detectionWindowDuration time.Duration
	detectionWindowCount    int
	detectionWindows        map[bool][]float64
	windowStartTime         map[bool]time.Time

	mu            sync.Mutex
	positiveCount int
}

// Feed 处理每个接收到的 UDP 数据包
func (s *brutalStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	if len(data) == 0 {
		return nil, false
	}

	// 丢包模拟
	if rand.Float64() < brutalMaxPacketLossRate {
		s.mu.Lock()
		s.lossCount++
		s.mu.Unlock()
		return nil, false
	}

	s.mu.Lock()
	s.packetCount++
	s.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(s.lastTime).Seconds()
	if elapsed > 0 {
		s.mu.Lock()
		packetRate := float64(s.packetCount) / elapsed
		lossRate := float64(s.lossCount) / float64(s.packetCount)
		s.mu.Unlock()

		prop, d := s.updateDetection(packetRate, lossRate, rev, now)
		if prop != nil || d {
			return prop, d
		}
	}

	s.lastTime = now

	// 此处可根据需要添加对UDP数据包内容的具体分析逻辑
	return nil, false
}

// updateDetection 实现容错机制，通过检测窗口内的指标更新总得分
func (s *brutalStream) updateDetection(packetRate float64, lossRate float64, rev bool, now time.Time) (*analyzer.PropUpdate, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isBrutal {
		// 已经封锁的流直接返回结束
		return nil, true
	}

	metric := packetRate * (1 - lossRate)

	if now.Sub(s.windowStartTime[rev]) >= s.detectionWindowDuration {
		if len(s.detectionWindows[rev]) < s.detectionWindowCount && rand.Intn(100) < 10 {
			s.detectionWindows[rev] = append(s.detectionWindows[rev], metric)
		}
		s.windowStartTime[rev] = now
	}

	if len(s.detectionWindows[rev]) >= s.detectionWindowCount {
		var sum float64
		for _, m := range s.detectionWindows[rev] {
			sum += m
		}
		avg := sum / float64(len(s.detectionWindows[rev]))

		allWithinRange := true
		for _, m := range s.detectionWindows[rev] {
			if m < 0.98*avg || m > 1.1*avg {
				allWithinRange = false
				break
			}
		}

		detected := allWithinRange // 如果所有窗口值在范围内则为阳性
		if detected {
			// 阳性，加分
			s.totalScore += s.positiveScore
			s.positiveCount++
		} else {
			// 阴性，减分
			s.totalScore -= s.negativeScore
			if s.totalScore < 0 {
				s.totalScore = 0
			}
		}

		// 清空检测窗口
		s.detectionWindows[rev] = s.detectionWindows[rev][:0]

		if s.totalScore > s.scoreThreshold && !s.isBrutal {
			// 如果没有 Warn 方法，使用 Info 或 Error
			s.logger.Info("Brutal traffic detected, blocking connection")
			s.isBrutal = true

			return &analyzer.PropUpdate{
				Type: analyzer.PropUpdateReplace,
				M: analyzer.PropMap{
					"yes":           detected,
					"score":         s.totalScore,
					"positiveCount": s.positiveCount,
					"action":        "block",
					"isBrutal":      true,
				},
			}, true
		} else {
			return &analyzer.PropUpdate{
				Type: analyzer.PropUpdateReplace,
				M: analyzer.PropMap{
					"yes":           detected,
					"score":         s.totalScore,
					"positiveCount": s.positiveCount,
					"action":        "allow",
					"isBrutal":      false,
				},
			}, false
		}
	}

	return nil, false
}

// Close 在连接关闭时输出流量是否为 brutal 及相关统计信息
func (s *brutalStream) Close(limited bool) *analyzer.PropUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M: analyzer.PropMap{
			"packetCount":    s.packetCount,
			"lossCount":      s.lossCount,
			"lossRate":       calculateLossRate(s.lossCount, s.packetCount),
			"totalScore":     s.totalScore,
			"positiveCount":  s.positiveCount,
			"isBrutal":       s.isBrutal,
		},
	}
}

// calculateLossRate 计算丢包率，避免除以零
func calculateLossRate(lossCount, packetCount int) float64 {
	if packetCount == 0 {
		return 0.0
	}
	return float64(lossCount) / float64(packetCount)
}
