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

	// 以下为新添加的参数（可自定义）
	positiveScoreIncrement = 2  // 阳性时加分
	negativeScoreDecrement = 1  // 阴性时减分，不可减至负数
	blockThreshold         = 20 // 总分大于此值则封锁

	intervalCount = 5            // 总共需要随机选择的区间数
	intervalDuration = 10 * time.Millisecond
	intervalStartChance = 0.01   // 每次 Feed 尝试启动区间的概率
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
	return &brutalStream{
		logger: logger,
		score:  0, // 初始分数
	}
}

type intervalData struct {
	byteCount     int
	packetCount   int
	lossCount     int
	startTime     time.Time
	endTime       time.Time
}

type brutalStream struct {
	logger          analyzer.Logger
	invalidCount    int
	packetCount     int
	lossCount       int
	totalBytes      int // 累计收到的总字节数（未丢包的包）
	lastTime        time.Time
	lastPacketSize  int

	// 容错机制相关
	score            int // 当前总得分
	intervals        []intervalData
	currentInterval  *intervalData
	intervalsDone    int

	// 标记当前是否已经完成了5个区间的选择和统计
	allIntervalsDone bool
}

// 在 Feed 中模拟丢包和统计数据
func (s *brutalStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	// 丢包模拟：根据最大丢包率控制丢包概率
	drop := rand.Float64() < brutalMaxPacketLossRate
	if drop {
		s.lossCount++
		s.packetCount++
		// 即使丢包也需要计入当前区间的数据统计(丢包计数、总包计数)
		s.updateIntervalStats(len(data), true)
		return nil, false // 丢弃当前数据包
	}

	s.packetCount++
	s.totalBytes += len(data)
	s.updateIntervalStats(len(data), false)

	now := time.Now()
	s.handleIntervals(now)

	// 不需要对是否是 brutal 做初步判定的逻辑，直接移除

	s.lastTime = now

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

// 根据当前区间状态更新统计信息
func (s *brutalStream) updateIntervalStats(byteCount int, dropped bool) {
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

// 尝试随机启动新的区间或者结束当前区间
func (s *brutalStream) handleIntervals(now time.Time) {
	if s.allIntervalsDone {
		return
	}

	// 如果当前没有正在进行的区间且还需要收集区间数据
	if s.currentInterval == nil && s.intervalsDone < intervalCount {
		// 随机概率启动一个区间
		if rand.Float64() < intervalStartChance {
			s.currentInterval = &intervalData{
				startTime: now,
			}
		}
	} else if s.currentInterval != nil {
		// 判断是否已超过10ms
		if now.Sub(s.currentInterval.startTime) >= intervalDuration {
			s.currentInterval.endTime = now
			s.intervals = append(s.intervals, *s.currentInterval)
			s.currentInterval = nil
			s.intervalsDone++

			if s.intervalsDone == intervalCount {
				// 完成5个区间的收集
				s.allIntervalsDone = true
				s.evaluateIntervals()
			}
		}
	}
}

// 对5个区间进行计算与评分
func (s *brutalStream) evaluateIntervals() {
	if len(s.intervals) < intervalCount {
		return
	}

	// 计算每个区间的 (字节速率 * (1 - 丢包率))
	// 字节速率 = 区间内总字节数 / 区间时长(秒)
	// 丢包率 = 区间内丢失包数 / 区间内总包数
	// 我们需要 max-min 与平均值比较
	vals := make([]float64, 0, intervalCount)
	for _, iv := range s.intervals {
		duration := iv.endTime.Sub(iv.startTime).Seconds()
		if duration <= 0 {
			// 理论上不可能，但以防万一
			duration = 0.01 // 最小10ms
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
		return
	}

	// 计算max, min, avg
	maxVal := vals[0]
	minVal := vals[0]
	sum := 0.0
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

	// 判断极差是否小于平均数的2%
	if avg > 0 && rangeVal < avg*0.02 {
		// 阳性
		s.score += positiveScoreIncrement
	} else {
		// 阴性
		s.score -= negativeScoreDecrement
		if s.score < 0 {
			s.score = 0
		}
	}
}

func (s *brutalStream) Close(limited bool) *analyzer.PropUpdate {
	// 如果还有正在进行的区间，在close前无法完整统计，这里不再继续
	// 如果区间未满5个，则也无法进行最后的评估
	// 已在 evaluateIntervals 中更新 s.score
	// 判断是否分数大于20则封锁
	blocked := s.score > blockThreshold

	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M: analyzer.PropMap{
			"packetCount": s.packetCount,
			"lossCount":   s.lossCount,
			"lossRate":    float64(s.lossCount) / float64(s.packetCount),
			"score":       s.score,
			"blocked":     blocked,
		},
	}
}
