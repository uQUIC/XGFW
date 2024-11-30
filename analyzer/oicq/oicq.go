package oicq

import (
    "bytes"
    "encoding/binary"
    "github.com/uQUIC/XGFW/analyzer"
)

const (
    OICQPacketStartFlag = 0x02
    OICQPacketEndFlag   = 0x03
)

// 确保 OICQAnalyzer 实现了 UDPAnalyzer 和 TCPAnalyzer 接口
var _ analyzer.UDPAnalyzer = (*OICQAnalyzer)(nil)
var _ analyzer.TCPAnalyzer = (*OICQAnalyzer)(nil)

// OICQAnalyzer 用于分析 OICQ（QQ）协议的 UDP 和 TCP 流量
type OICQAnalyzer struct{}

func (a *OICQAnalyzer) Name() string {
    return "oicq"
}

func (a *OICQAnalyzer) Limit() int {
    return 0
}

// NewUDP 创建一个新的 UDP 流分析器
func (a *OICQAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
    return &OICQStream{logger: logger}
}

// NewTCP 创建一个新的 TCP 流分析器
func (a *OICQAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    return &OICQStream{logger: logger}
}

// OICQStream 用于分析单个 UDP 或 TCP 流
type OICQStream struct {
    logger analyzer.Logger
    buffer []byte
    done   bool
}

func (s *OICQStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
    if s.done {
        return nil, true
    }

    s.buffer = append(s.buffer, data...)
    m, remaining := parseOICQStream(s.buffer)
    s.buffer = remaining

    if m != nil {
        s.done = true // 发现有效的 OICQ 包，停止进一步处理
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M:    m,
        }, true
    }

    // 限制缓冲区大小以防止内存问题
    if len(s.buffer) > 1024*1024 {
        s.buffer = nil
    }

    return nil, false
}

func (s *OICQStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}

// parseOICQStream 尝试从数据缓冲区中解析 OICQ 包
func parseOICQStream(data []byte) (analyzer.PropMap, []byte) {
    index := 0
    for {
        // 查找起始标志
        start := bytes.IndexByte(data[index:], OICQPacketStartFlag)
        if start == -1 || index+start+1 >= len(data) {
            break
        }
        start += index

        // 查找结束标志
        end := bytes.IndexByte(data[start+1:], OICQPacketEndFlag)
        if end == -1 {
            break
        }
        end += start + 1

        packet := data[start : end+1]
        m := parseOICQMessage(packet)
        if m != nil {
            // 找到有效的 OICQ 包
            remaining := data[end+1:]
            return m, remaining
        }

        index = start + 1 // 继续搜索
    }
    return nil, data
}

// parseOICQMessage 解析单个 OICQ 消息
func parseOICQMessage(data []byte) analyzer.PropMap {
    /* OICQ 数据包结构:
    起始标志: 0x02
    结束标志: 0x03
    +------+---------+---------+----------+----------+
    | 0x02 | Version | Command | Sequence |  Number  |
    +------+---------+---------+----------+----------+
    |          Data (可变长度)                |
    +------+-----------------------------------------+
    |                    0x03                        |
    +------------------------------------------------+
    */
    // 确保最小长度
    if len(data) < 12 {
        return nil
    }
    // 检查起始和结束标志
    if data[0] != OICQPacketStartFlag || data[len(data)-1] != OICQPacketEndFlag {
        return nil
    }
    // 去除起始和结束标志
    data = data[1 : len(data)-1]
    if len(data) < 10 {
        return nil
    }
    // 解析字段
    version := binary.BigEndian.Uint16(data[0:2])
    command := binary.BigEndian.Uint16(data[2:4])
    seq := binary.BigEndian.Uint16(data[4:6])
    number := binary.BigEndian.Uint32(data[6:10])

    if number == 0 || command == 0 || version == 0 {
        return nil
    }

    // 已知的 OICQ 命令码（示例）
    knownOICQCommands := map[uint16]bool{
        0x0825: true, // 登录请求
        0x0826: true, // 登录响应
        0x00EC: true, // 心跳包
        0x0016: true, // 获取用户信息
        0x00CD: true, // 获取好友列表
        // 根据需要添加更多已知的命令码
    }

    // 签名匹配：检查命令码是否已知
    if !knownOICQCommands[command] {
        return nil
    }

    // 构建属性映射
    m := analyzer.PropMap{
        "version": version,
        "command": command,
        "seq":     seq,
        "number":  number,
    }

    // 检测到有效的 OICQ 包
    return m
}
