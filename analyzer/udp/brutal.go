package udp

import (
	"math/rand"
	"time"

	"github.com/uQUIC/XGFW/analyzer"
	"github.com/uQUIC/XGFW/analyzer/internal"
	"github.com/uQUIC/XGFW/analyzer/udp/internal/quic"
	"github.com/uQUIC/XGFW/analyzer/utils"
)

const (
	brutalInvalidCountThreshold = 4
	brutalMaxPacketLossRate     = 0.02 // 最大丢包率 2%
	brutalQuicInvalidCountThreshold = 4 // 重命名后的常量
)

// 确保实现接口
var (
	_ analyzer.UDPAnalyzer = (*BrutalAnalyzer)(nil)
	_ analyzer.UDPStream   = (*brutalStream)(nil)
)

// BrutalAnalyzer 结构体，嵌入 BrutalQUICAnalyzer
type BrutalAnalyzer struct {
	quicAnalyzer *BrutalQUICAnalyzer

	// Brutal 容错机制相关配置
	positiveScore           int
	negativeScore           int
	scoreThreshold          int
	detectionWindowDuration time.Duration
	detectionWindowCount    int
}

// NewBrutalAnalyzer 构造函数，允许自定义参数
func NewBrutalAnalyzer(positiveScore, negativeScore, scoreThreshold int, detectionWindowDuration time.Duration, detectionWindowCount int) *BrutalAnalyzer {
	return &BrutalAnalyzer{
		quicAnalyzer:            &BrutalQUICAnalyzer{},
		positiveScore:           positiveScore,
		negativeScore:           negativeScore,
		scoreThreshold:          scoreThreshold,
		detectionWindowDuration: detectionWindowDuration,
		detectionWindowCount:    detectionWindowCount,
	}
}

// Name 返回分析器名称
func (a *BrutalAnalyzer) Name() string {
	return "brutal"
}

// Limit 返回限制值
func (a *BrutalAnalyzer) Limit() int {
	return 0
}

// NewUDP 创建并返回一个新的 brutalStream 实例
func (a *BrutalAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return &brutalStream{
		logger:                  logger,
		quicAnalyzer:            a.quicAnalyzer,
		positiveScore:           a.positiveScore,
		negativeScore:           a.negativeScore,
		scoreThreshold:          a.scoreThreshold,
		detectionWindowDuration: a.detectionWindowDuration,
		detectionWindowCount:    a.detectionWindowCount,
		detectionWindows:        make([]float64, 0, a.detectionWindowCount),
		windowStartTime:         time.Now(),
	}
}

// brutalStream 结构体，处理单个 UDP 流
type brutalStream struct {
	logger       analyzer.Logger
	quicAnalyzer *BrutalQUICAnalyzer

	invalidCount int
	packetCount  int
	lossCount    int
	lastTime     time.Time
	isBrutal     bool // 标记是否为 brutal 流量

	// 容错机制相关字段
	positiveScore          int
	negativeScore          int
	totalScore             int
	scoreThreshold         int
	detectionWindowDuration time.Duration
	detectionWindowCount    int
	detectionWindows        []float64
	windowStartTime         time.Time
}

// Feed 处理每个接收到的数据包
func (s *brutalStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	// 仅对 QUIC 流量进行丢包模拟和检测
	if s.isQUIC(data) {
		// 丢包模拟：根据最大丢包率控制丢包概率
		if rand.Float64() < brutalMaxPacketLossRate {
			s.lossCount++
			return nil, false // 丢弃当前数据包
		}
		s.packetCount++

		// 计算传输速率和丢包率
		now := time.Now()
		elapsed := now.Sub(s.lastTime).Seconds()
		if elapsed > 0 {
			packetRate := float64(s.packetCount) / elapsed
			lossRate := float64(s.lossCount) / float64(s.packetCount)

			// 容错机制检测
			s.updateDetection(packetRate, lossRate, now)
		}

		s.lastTime = now
	}

	// 处理非 QUIC 流量的逻辑（忽略）
	if !s.isQUIC(data) {
		// 可以选择记录非 QUIC 流量或忽略
		return nil, false
	}

	// 数据包有效性检查，由 BrutalQUICAnalyzer 处理
	update, done := s.quicAnalyzer.ProcessQUIC(rev, data, brutalQuicInvalidCountThreshold)
	if done {
		s.invalidCount++
		if s.invalidCount >= brutalQuicInvalidCountThreshold {
			return update, true
		}
	}
	return update, done
}

// updateDetection 更新容错机制的检测窗口和得分
func (s *brutalStream) updateDetection(packetRate float64, lossRate float64, now time.Time) {
	// 计算字节速率与 (1 - 丢包率) 的乘积
	metric := packetRate * (1 - lossRate)

	// 检查是否超过检测窗口持续时间
	if now.Sub(s.windowStartTime) >= s.detectionWindowDuration {
		// 随机选择是否将当前窗口添加到检测窗口中
		if len(s.detectionWindows) < s.detectionWindowCount && rand.Intn(100) < 10 { // 10% 概率选择
			s.detectionWindows = append(s.detectionWindows, metric)
		}
		s.windowStartTime = now
	}

	// 如果已收集到足够的检测窗口，进行判定
	if len(s.detectionWindows) >= s.detectionWindowCount {
		// 计算平均数
		var sum float64
		for _, m := range s.detectionWindows {
			sum += m
		}
		avg := sum / float64(len(s.detectionWindows))

		// 计算极差
		var min, max float64
		min, max = s.detectionWindows[0], s.detectionWindows[0]
		for _, m := range s.detectionWindows {
			if m < min {
				min = m
			}
			if m > max {
				max = m
			}
		}
		rangeValue := max - min

		// 判定条件
		if rangeValue < 0.5*avg {
			// 阳性
			s.totalScore += s.positiveScore
		} else {
			// 阴性
			s.totalScore += s.negativeScore
			if s.totalScore < 0 {
				s.totalScore = 0
			}
		}

		// 清空检测窗口
		s.detectionWindows = s.detectionWindows[:0]

		// 判断是否超过封锁阈值
		if s.totalScore > s.scoreThreshold {
			s.logger.Info("Brutal traffic detected, blocking connection") // 使用 Info 代替 Warn
			s.isBrutal = true
			// 立即断开连接
			// 这里选择返回 done = true 来终止连接
		}
	}
}

// Close 在连接关闭时输出流量判定结果
func (s *brutalStream) Close(limited bool) *analyzer.PropUpdate {
	// 输出流量是否为 brutal 的判定结果
	if s.isBrutal {
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"isBrutal":    true,
				"packetCount": s.packetCount,
				"lossCount":   s.lossCount,
				"lossRate":    float64(s.lossCount) / float64(s.packetCount),
				"totalScore":  s.totalScore,
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
			"totalScore":  s.totalScore,
		},
	}
}

// isQUIC 判断数据包是否为 QUIC 流量
func (s *brutalStream) isQUIC(data []byte) bool {
	return s.quicAnalyzer.IsQUIC(data)
}

// BrutalQUICAnalyzer 用于检测和解析 QUIC 流量（重命名后的类型）
type BrutalQUICAnalyzer struct{}

// IsQUIC 判断数据包是否为 QUIC 流量
func (q *BrutalQUICAnalyzer) IsQUIC(data []byte) bool {
	// 简单判断数据包是否为 QUIC 流量，可以根据具体协议特征进行调整
	// 例如，QUIC 的初始字节通常以特定的类型标识符开头
	if len(data) < 1 {
		return false
	}
	return data[0] == internal.TypeClientHello
}

// ProcessQUIC 处理 QUIC 流量的数据包，返回属性更新和是否完成的标志
func (q *BrutalQUICAnalyzer) ProcessQUIC(rev bool, data []byte, invalidCountThreshold int) (*analyzer.PropUpdate, bool) {
	// minimal data size: protocol version (2 bytes) + random (32 bytes) +
	// session ID (1 byte) + cipher suites (4 bytes) +
	// compression methods (2 bytes) + no extensions
	const minDataSize = 41

	if rev {
		// 不支持服务器方向的流量
		return nil, false
	}

	pl, err := quic.ReadCryptoPayload(data)
	if err != nil || len(pl) < 4 { // FIXME: isn't length checked inside quic.ReadCryptoPayload? Also, what about error handling?
		return nil, false
	}

	if pl[0] != internal.TypeClientHello {
		return nil, false
	}

	chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
	if chLen < minDataSize {
		return nil, false
	}

	m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
	if m == nil {
		return nil, false
	}

	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateMerge,
		M:    analyzer.PropMap{"req": m},
	}, true
}
