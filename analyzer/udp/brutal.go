package udp

import (
	"sync"
	"time"

	"github.com/uQUIC/XGFW/analyzer"
	"github.com/uQUIC/XGFW/analyzer/internal"
	"github.com/uQUIC/XGFW/analyzer/udp/internal/quic"
	"github.com/uQUIC/XGFW/analyzer/utils"
	"math/rand"
)

// 配置常量，可根据需求调整
const (
	brutalInvalidCountThreshold = 4
	brutalMaxPacketLossRate     = 0.02 // 最大丢包率 2%

	// 容错机制参数
	positiveScoreIncrement  = 2  // 阳性时加分
	negativeScoreDecrement  = 1  // 阴性时减分，不可减至负数
	blockThreshold          = 20 // 总分大于此值则封锁

	intervalCount        = 5               // 总共需要随机选择的区间数
	intervalDuration     = 10 * time.Millisecond // 每个区间的持续时间
	intervalStartChance  = 0.01            // 每次 Feed 尝试启动区间的概率

	// 最小数据包大小: 协议版本 (2 字节) + 随机数 (32 字节) + 会话ID (1 字节) + 密码套件 (4 字节) + 压缩方法 (2 字节) + 无扩展
	minDataSize = 41
)

// 确保 BrutalAnalyzer 和 brutalStream 实现了相应的接口
var (
	_ analyzer.UDPAnalyzer = (*BrutalAnalyzer)(nil)
	_ analyzer.UDPStream   = (*brutalStream)(nil)
)

// BrutalAnalyzer 实现了 analyzer.UDPAnalyzer 接口
type BrutalAnalyzer struct{}

// Name 返回分析器的名称
func (a *BrutalAnalyzer) Name() string {
	return "brutal"
}

// Limit 返回分析器的限制，这里为0表示无限制
func (a *BrutalAnalyzer) Limit() int {
	return 0
}

// NewUDP 创建一个新的 UDP 流分析实例
func (a *BrutalAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return &brutalStream{
		logger: logger,
		score:  0, // 初始分数
	}
}

// intervalData 用于存储每个观察区间的数据
type intervalData struct {
	byteCount   int
	packetCount int
	lossCount   int
	startTime   time.Time
	endTime     time.Time
}

// brutalStream 实现了 analyzer.UDPStream 接口
type brutalStream struct {
	logger       analyzer.Logger
	score        int // 当前总得分
	packetCount  int
	lossCount    int
	totalBytes   int // 累计收到的总字节数（未丢包的包）
	invalidCount int

	// 容错机制相关
	mu               sync.Mutex // 保护以下字段的互斥锁
	intervals        []intervalData
	currentInterval  *intervalData
	intervalsDone    int
	allIntervalsDone bool
}

// Feed 处理每个接收到的数据包
func (s *brutalStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// 模拟丢包
	drop := rand.Float64() < brutalMaxPacketLossRate
	if drop {
		s.lossCount++
		s.packetCount++
		s.updateIntervalStats(len(data), true, now)
		// 丢弃当前数据包
		return nil, false
	}

	// 处理有效数据包
	s.packetCount++
	s.totalBytes += len(data)
	s.updateIntervalStats(len(data), false, now)

	// 处理观察区间
	s.handleIntervals(now)

	// 处理反向流量（不支持服务器方向的流量）
	if rev {
		s.invalidCount++
		if s.invalidCount >= brutalInvalidCountThreshold {
			return nil, true // 达到无效包阈值，标记完成
		}
		return nil, false
	}

	// 解析 QUIC 加密负载
	pl, err := quic.ReadCryptoPayload(data)
	if err != nil || len(pl) < 4 {
		s.invalidCount++
		if s.invalidCount >= brutalInvalidCountThreshold {
			return nil, true
		}
		return nil, false
	}

	if pl[0] != internal.TypeClientHello {
		s.invalidCount++
		if s.invalidCount >= brutalInvalidCountThreshold {
			return nil, true
		}
		return nil, false
	}

	chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
	if chLen < minDataSize {
		s.invalidCount++
		if s.invalidCount >= brutalInvalidCountThreshold {
			return nil, true
		}
		return nil, false
	}

	// 解析客户端握手消息
	m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
	if m == nil {
		s.invalidCount++
		if s.invalidCount >= brutalInvalidCountThreshold {
			return nil, true
		}
		return nil, false
	}

	// 返回数据流的更新，包括当前请求信息
	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateMerge,
		M:    analyzer.PropMap{"req": m},
	}, true
}

// updateIntervalStats 根据当前包的状态更新当前区间的统计数据
func (s *brutalStream) updateIntervalStats(byteCount int, dropped bool, now time.Time) {
	if s.currentInterval == nil {
		return
	}
	s.currentInterval.packetCount++
	if !dropped {
		s.currentInterval.byteCount += byteCount
	} else {
		s.currentInterval.lossCount++
	}
}

// handleIntervals 处理观察区间的启动和结束
func (s *brutalStream) handleIntervals(now time.Time) {
	if s.allIntervalsDone {
		return
	}

	// 启动新的观察区间的条件
	if s.currentInterval == nil && s.intervalsDone < intervalCount {
		if rand.Float64() < intervalStartChance {
			s.currentInterval = &intervalData{
				startTime: now,
			}
			s.logger.Debugf("Started new interval at %v", now)
		}
	}

	// 检查当前区间是否已结束
	if s.currentInterval != nil {
		if now.Sub(s.currentInterval.startTime) >= intervalDuration {
			s.currentInterval.endTime = now
			s.intervals = append(s.intervals, *s.currentInterval)
			s.currentInterval = nil
			s.intervalsDone++

			s.logger.Debugf("Ended interval %d at %v", s.intervalsDone, now)

			// 检查是否完成所有观察区间
			if s.intervalsDone == intervalCount {
				s.allIntervalsDone = true
				s.evaluateIntervals()
			}
		}
	}
}

// evaluateIntervals 评估所有收集到的观察区间，并更新评分
func (s *brutalStream) evaluateIntervals() {
	if len(s.intervals) < intervalCount {
		s.logger.Warnf("Insufficient intervals for evaluation: got %d, expected %d", len(s.intervals), intervalCount)
		return
	}

	// 计算每个区间的 (字节速率 * (1 - 丢包率))
	vals := make([]float64, 0, intervalCount)
	for _, iv := range s.intervals {
		duration := iv.endTime.Sub(iv.startTime).Seconds()
		if duration <= 0 {
			duration = 0.01 // 防止除以零，最小10ms
		}
		byteRate := float64(iv.byteCount) / duration
		lossRate := 0.0
		if iv.packetCount > 0 {
			lossRate = float64(iv.lossCount) / float64(iv.packetCount)
		}
		val := byteRate * (1 - lossRate)
		vals = append(vals, val)
	}

	if len(vals) == 0 {
		s.logger.Warn("No valid interval data to evaluate")
		return
	}

	// 计算 max, min, avg
	maxVal, minVal, sum := vals[0], vals[0], 0.0
	for _, v := range vals {
		if v > maxVal {
			maxVal = v
		}
		if v < minVal {
			minVal = v
		}
		sum += v
	}
	avg := sum / float64(len(vals))
	rangeVal := maxVal - minVal

	s.logger.Debugf("Interval evaluation - Max: %.2f, Min: %.2f, Avg: %.2f, Range: %.2f", maxVal, minVal, avg, rangeVal)

	// 判断极差是否小于平均数的2%
	if avg > 0 && rangeVal < avg*0.02 {
		// 阳性
		s.score += positiveScoreIncrement
		s.logger.Debugf("Interval positive. Score increased to %d", s.score)
	} else {
		// 阴性
		s.score -= negativeScoreDecrement
		if s.score < 0 {
			s.score = 0
		}
		s.logger.Debugf("Interval negative. Score decreased to %d", s.score)
	}
}

// Close 处理流关闭时的逻辑，并返回最终的统计信息
func (s *brutalStream) Close(limited bool) *analyzer.PropUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 在 Close 时，如果还有未结束的区间，可以选择是否等待或忽略
	// 这里选择忽略，确保不会阻塞 Close 调用
	if s.allIntervalsDone == false && s.intervalsDone > 0 {
		s.logger.Warn("Stream closed before completing all intervals")
		s.evaluateIntervals() // 尝试评估已完成的区间
	}

	// 判断是否封锁
	blocked := s.score > blockThreshold

	// 记录最终统计信息
	update := &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M: analyzer.PropMap{
			"packetCount": s.packetCount,
			"lossCount":   s.lossCount,
			"lossRate":    calculateLossRate(s.lossCount, s.packetCount),
			"totalBytes":  s.totalBytes,
			"score":       s.score,
			"blocked":     blocked,
		},
	}

	// 额外信息：所有区间的详细数据
	for i, iv := range s.intervals {
		update.M[analyzer.PropMapKey(fmt.Sprintf("interval_%d_byteRate", i+1))] = calculateByteRate(iv.byteCount, iv.startTime, iv.endTime)
		update.M[analyzer.PropMapKey(fmt.Sprintf("interval_%d_lossRate", i+1))] = calculateLossRate(iv.lossCount, iv.packetCount)
	}

	return update
}

// calculateLossRate 计算丢包率，避免除以零
func calculateLossRate(lossCount, packetCount int) float64 {
	if packetCount == 0 {
		return 0.0
	}
	return float64(lossCount) / float64(packetCount)
}

// calculateByteRate 计算字节速率，避免除以零
func calculateByteRate(byteCount int, startTime, endTime time.Time) float64 {
	duration := endTime.Sub(startTime).Seconds()
	if duration <= 0 {
		duration = 0.01 // 防止除以零，最小10ms
	}
	return float64(byteCount) / duration
}
