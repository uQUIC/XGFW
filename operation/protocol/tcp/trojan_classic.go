package tcp

import (
	"bytes"

	"github.com/uQUIC/XGFW/operation/protocol"
)

var _ analyzer.TCPAnalyzer = (*TrojanClassicAnalyzer)(nil)

// CCS stands for "Change Cipher Spec"
var trojanClassicCCS = []byte{20, 3, 3, 0, 1, 1}

const (
	trojanClassicUpLB    = 650
	trojanClassicUpUB    = 1000
	trojanClassicDownLB1 = 170
	trojanClassicDownUB1 = 180
	trojanClassicDownLB2 = 3000
	trojanClassicDownUB2 = 7500
)

// TrojanClassicAnalyzer uses a very simple packet length based check to determine
// if a TLS connection is actually the Trojan proxy protocol.
// The algorithm is from the following project, with small modifications:
// https://github.com/XTLS/Trojan-killer
// Warning: Experimental only. This method is known to have significant false positives and false negatives.
type TrojanClassicAnalyzer struct{}

func (a *TrojanClassicAnalyzer) Name() string {
	return "trojanClassic"
}

func (a *TrojanClassicAnalyzer) Limit() int {
	return 16384
}

func (a *TrojanClassicAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newTrojanClassicStream(logger)
}

type trojanClassicStream struct {
	logger    analyzer.Logger
	active    bool
	upCount   int
	downCount int
}

func newTrojanClassicStream(logger analyzer.Logger) *trojanClassicStream {
	return &trojanClassicStream{logger: logger}
}

func (s *trojanClassicStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
	if skip != 0 {
		return nil, true
	}
	if len(data) == 0 {
		return nil, false
	}
	if !rev && !s.active && len(data) >= 6 && bytes.Equal(data[:6], trojanClassicCCS) {
		// Client CCS encountered, start counting
		s.active = true
	}
	if s.active {
		if rev {
			// Down direction
			s.downCount += len(data)
		} else {
			// Up direction
			if s.upCount >= trojanClassicUpLB && s.upCount <= trojanClassicUpUB &&
				((s.downCount >= trojanClassicDownLB1 && s.downCount <= trojanClassicDownUB1) ||
					(s.downCount >= trojanClassicDownLB2 && s.downCount <= trojanClassicDownUB2)) {
				return &analyzer.PropUpdate{
					Type: analyzer.PropUpdateReplace,
					M: analyzer.PropMap{
						"up":   s.upCount,
						"down": s.downCount,
						"yes":  true,
					},
				}, true
			}
			s.upCount += len(data)
		}
	}
	// Give up when either direction is over the limit
	return nil, s.upCount > trojanClassicUpUB || s.downCount > trojanClassicDownUB2
}

func (s *trojanClassicStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}
