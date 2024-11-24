// tcp/trojan_analyzer.go
package tcp

import (
	"bytes"

	"github.com/uQUIC/XGFW/analyzer"
)

var _ analyzer.TCPAnalyzer = (*TrojanAnalyzer)(nil)

// CCS stands for "Change Cipher Spec"
var ccsPattern = []byte{20, 3, 3, 0, 1, 1}

// Configurable parameters for detection
const (
	positiveIncrement = 2 // Increment for positive detections
	negativeDecrement = 1 // Decrement for negative detections
	threshold         = 20 // Threshold for blocking
)

// TrojanAnalyzer uses length-based heuristics to detect Trojan traffic.
// The detection uses a decision tree and configurable parameters for detection.
type TrojanAnalyzer struct{}

func (a *TrojanAnalyzer) Name() string {
	return "trojan"
}

func (a *TrojanAnalyzer) Limit() int {
	return 512000
}

func (a *TrojanAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newTrojanStream(logger)
}

type trojanStream struct {
	logger        analyzer.Logger
	first         bool
	count         bool
	rev           bool
	seq           [4]int
	seqIndex      int
	score         int // Tracks the current score for blocking logic
	positiveCount int // Counts positive results from detection tree
}

func newTrojanStream(logger analyzer.Logger) *trojanStream {
	return &trojanStream{
		logger:        logger,
		first:         true,
		score:         0,
		positiveCount: 0,
	}
}

func (s *trojanStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
	if skip != 0 {
		return nil, true
	}
	if len(data) == 0 {
		return nil, false
	}

	if s.first {
		s.first = false
		// Stop if it's not a valid TLS connection
		if !(!rev && len(data) >= 3 && data[0] >= 0x16 && data[0] <= 0x17 &&
			data[1] == 0x03 && data[2] <= 0x09) {
			return nil, true
		}
	}

	if !rev && !s.count && len(data) >= 6 && bytes.Equal(data[:6], ccsPattern) {
		// Client Change Cipher Spec encountered, start counting
		s.count = true
	}

	if s.count {
		if rev == s.rev {
			// Same direction as last time, just update the number
			s.seq[s.seqIndex] += len(data)
		} else {
			// Different direction, bump the index
			s.seqIndex += 1
			if s.seqIndex == 4 {
				// Perform detection using isTrojanSeq
				detected := isTrojanSeq(s.seq)

				// Adjust score based on detection result
				if detected {
					s.score += positiveIncrement
					s.positiveCount++ // Increment positive result counter
				} else {
					s.score -= negativeDecrement
					if s.score < 0 {
						s.score = 0
					}
				}

				// Return blocking result if score exceeds threshold
				if s.score > threshold {
					return &analyzer.PropUpdate{
						Type: analyzer.PropUpdateReplace,
						M: analyzer.PropMap{
							"seq":            s.seq,
							"yes":            detected,
							"score":          s.score,
							"positiveCount":  s.positiveCount,
							"action":         "block",
						},
					}, true
				}

				// Otherwise return updated state
				return &analyzer.PropUpdate{
					Type: analyzer.PropUpdateReplace,
					M: analyzer.PropMap{
						"seq":            s.seq,
						"yes":            detected,
						"score":          s.score,
						"positiveCount":  s.positiveCount,
						"action":         "allow",
					},
				}, false
			}
			s.seq[s.seqIndex] += len(data)
			s.rev = rev
		}
	}

	return nil, false
}

func (s *trojanStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}

// isTrojanSeq determines whether the sequence is detected as Trojan using the decision tree
func isTrojanSeq(seq [4]int) bool {
	length1 := seq[0]
	length2 := seq[1]
	length3 := seq[2]
	length4 := seq[3]

	// Decision tree logic
	if length2 <= 2431 {
		if length2 <= 157 {
			if length1 <= 156 {
				if length3 <= 108 {
					return false
				} else {
					return false
				}
			} else {
				if length1 <= 892 {
					if length3 <= 40 {
						return false
					} else {
						if length3 <= 788 {
							if length4 <= 185 {
								if length1 <= 411 {
									return true
								} else {
									return false
								}
							} else {
								if length2 <= 112 {
									return false
								} else {
									return true
								}
							}
						} else {
							if length3 <= 1346 {
								if length1 <= 418 {
									return false
								} else {
									return true
								}
							} else {
								return false
							}
						}
					}
				} else {
					if length2 <= 120 {
						if length2 <= 63 {
							return false
						} else {
							if length4 <= 653 {
								return false
							} else {
								return false
							}
						}
					} else {
						return false
					}
				}
			}
		} else {
			if length1 <= 206 {
				if length1 <= 185 {
					if length1 <= 171 {
						return false
					} else {
						if length4 <= 211 {
							return false
						} else {
							return false
						}
					}
				} else {
					if length2 <= 251 {
						return true
					} else {
						return false
					}
				}
			} else {
				if length2 <= 286 {
					if length1 <= 1123 {
						if length3 <= 70 {
							return false
						} else {
							if length1 <= 659 {
								if length3 <= 370 {
									return true
								} else {
									return false
								}
							} else {
								if length4 <= 272 {
									return false
								} else {
									return true
								}
							}
						}
					} else {
						if length4 <= 537 {
							if length2 <= 276 {
								if length3 <= 1877 {
									return false
								} else {
									return false
								}
							} else {
								return false
							}
						} else {
							if length1 <= 1466 {
								if length1 <= 1435 {
									return false
								} else {
									return true
								}
							} else {
								if length2 <= 193 {
									return false
								} else {
									return false
								}
							}
						}
					}
				} else {
					if length1 <= 284 {
						if length1 <= 277 {
							if length2 <= 726 {
								return false
							} else {
								if length2 <= 768 {
									return true
								} else {
									return false
								}
							}
						} else {
							if length2 <= 782 {
								if length4 <= 783 {
									return true
								} else {
									return false
								}
							} else {
								return false
							}
						}
					} else {
						if length2 <= 492 {
							if length2 <= 396 {
								if length2 <= 322 {
									return false
								} else {
									return false
								}
							} else {
								if length4 <= 971 {
									return false
								} else {
									return true
								}
							}
						} else {
							if length2 <= 2128 {
								if length2 <= 1418 {
									return false
								} else {
									return false
								}
							} else {
								if length3 <= 103 {
									return false
								} else {
									return false
								}
							}
						}
					}
				}
			}
		}
	} else {
		if length2 <= 6232 {
			if length3 <= 85 {
				if length2 <= 3599 {
					return false
				} else {
					if length1 <= 613 {
						return false
					} else {
						return false
					}
				}
			} else {
				if length3 <= 220 {
					if length4 <= 1173 {
						if length1 <= 874 {
							if length4 <= 337 {
								if length4 <= 68 {
									return true
								} else {
									return true
								}
							} else {
								if length1 <= 667 {
									return true
								} else {
									return true
								}
							}
						} else {
							if length3 <= 108 {
								if length1 <= 1930 {
									return true
								} else {
									return true
								}
							} else {
								if length2 <= 5383 {
									return false
								} else {
									return true
								}
							}
						}
					} else {
						return false
					}
				} else {
					if length1 <= 664 {
						if length3 <= 411 {
							if length3 <= 383 {
								if length4 <= 346 {
									return true
								} else {
									return false
								}
							} else {
								if length1 <= 445 {
									return true
								} else {
									return false
								}
							}
						} else {
							if length2 <= 3708 {
								if length4 <= 307 {
									return true
								} else {
									return false
								}
							} else {
								if length2 <= 4656 {
									return false
								} else {
									return false
								}
							}
						}
					} else {
						if length1 <= 1055 {
							if length3 <= 580 {
								if length1 <= 724 {
									return true
								} else {
									return false
								}
							} else {
								if length1 <= 678 {
									return false
								} else {
									return true
								}
							}
						} else {
							if length2 <= 5352 {
								if length3 <= 1586 {
									return false
								} else {
									return false
								}
							} else {
								if length4 <= 2173 {
									return true
								} else {
									return false
								}
							}
						}
					}
				}
			}
		} else {
			if length2 <= 9408 {
				if length1 <= 670 {
					if length4 <= 76 {
						if length3 <= 175 {
							return true
						} else {
							return true
						}
					} else {
						if length2 <= 9072 {
							if length3 <= 314 {
								if length3 <= 179 {
									return false
								} else {
									return false
								}
							} else {
								if length4 <= 708 {
									return false
								} else {
									return false
								}
							}
						} else {
							return true
						}
					}
				} else {
					if length1 <= 795 {
						if length2 <= 6334 {
							if length2 <= 6288 {
								return true
							} else {
								return false
							}
						} else {
							if length4 <= 6404 {
								if length2 <= 8194 {
									return true
								} else {
									return true
								}
							} else {
								if length2 <= 8924 {
									return false
								} else {
									return true
								}
							}
						}
					} else {
						if length3 <= 732 {
							if length1 <= 1397 {
								if length3 <= 179 {
									return false
								} else {
									return false
								}
							} else {
								if length1 <= 1976 {
									return false
								} else {
									return false
								}
							}
						} else {
							if length1 <= 2840 {
								if length1 <= 2591 {
									return false
								} else {
									return true
								}
							} else {
								return false
							}
						}
					}
				}
			} else {
				if length4 <= 30 {
					return false
				} else {
					if length2 <= 13314 {
						if length4 <= 1786 {
							if length2 <= 13018 {
								if length4 <= 869 {
									return false
								} else {
									return false
								}
							} else {
								return true
							}
						} else {
							if length3 <= 775 {
								return false
							} else {
								return false
							}
						}
					} else {
						if length4 <= 73 {
							return false
						} else {
							if length3 <= 640 {
								if length3 <= 237 {
									return false
								} else {
									return false
								}
							} else {
								if length2 <= 43804 {
									return false
								} else {
									return false
								}
							}
						}
					}
				}
			}
		}
	}
}
