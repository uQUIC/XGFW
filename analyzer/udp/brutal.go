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
	quicInvalidCountThreshold = 4
	maxPacketLossRate = 0.02  // 最大丢包率 2%
)

var (
	_ analyzer.UDPAnalyzer = (*QUICAnalyzer)(nil)
	_ analyzer.UDPStream   = (*quicStream)(nil)
)

type QUICAnalyzer struct{}

func (a *QUICAnalyzer) Name() string {
	return "quic"
}

func (a *QUICAnalyzer) Limit() int {
	return 0
}

func (a *QUICAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return &quicStream{logger: logger}
}

type quicStream struct {
	logger       analyzer.Logger
	invalidCount int
	packetCount  int
	lossCount    int
	lastTime     time.Time
	lastPacketSize int
	isBrutal     bool  // 用于标记是否为brutal流量
}

// 模拟丢包和速率分析
func (s *quicStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	// 丢包模拟：根据最大丢包率控制丢包概率
	if rand.Float64() < maxPacketLossRate {
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

		// 判断流量是否符合brutal特征：速率与丢包率的反比关系
		if lossRate > 0.1 && packetRate > 0.5 {
			s.isBrutal = true
		}
	}

	s.lastTime = now

	// 最小数据包大小: 协议版本 (2 字节) + 随机数 (32 字节) + 会话ID (1 字节) + 密码套件 (4 字节) + 压缩方法 (2 字节) + 无扩展
	const minDataSize = 41

	if rev {
		// 不支持服务器方向的流量
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}

	pl, err := quic.ReadCryptoPayload(data)
	if err != nil || len(pl) < 4 {
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}

	if pl[0] != internal.TypeClientHello {
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}

	chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
	if chLen < minDataSize {
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}

	// 解析客户端握手消息
	m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
	if m == nil {
		s.invalidCount++
		return nil, s.invalidCount >= quicInvalidCountThreshold
	}

	// 返回数据流的更新，包括当前请求信息
	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateMerge,
		M:    analyzer.PropMap{"req": m},
	}, true
}

func (s *quicStream) Close(limited bool) *analyzer.PropUpdate {
	// 输出流量是否为brutal的判定结果
	if s.isBrutal {
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"isBrutal": true,
				"packetCount": s.packetCount,
				"lossCount": s.lossCount,
				"lossRate": float64(s.lossCount) / float64(s.packetCount),
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
