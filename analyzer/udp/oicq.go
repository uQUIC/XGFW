package analyzer

import (
    "bytes"
    "encoding/binary"
    "sync"

    "github.com/uquic/XGFW/analyzer"
)

// 常量定义
const (
    OICQPacketStartFlag = 0x02
    OICQPacketEndFlag   = 0x03
)

// 已知的 OICQ 版本，用于减少误报
var knownOICQVersions = map[uint16]bool{
    0x0001: true,
    0x0002: true,
    // 可根据实际情况添加更多已知版本
}

// 确保 OICQAnalyzer 实现了 TCPAnalyzer 和 UDPAnalyzer 接口
var (
    _ analyzer.TCPAnalyzer = (*OICQAnalyzer)(nil)
    _ analyzer.UDPAnalyzer = (*OICQAnalyzer)(nil)
)

// OICQAnalyzer 用于检测和封锁 OICQ (QQ) 流量
type OICQAnalyzer struct{}

// Name 返回分析器的名称
func (a *OICQAnalyzer) Name() string {
    return "OICQ_Analyzer"
}

// Limit 返回分析器的限制（例如同时分析的连接数）
func (a *OICQAnalyzer) Limit() int {
    return 0 // 不限制
}

// NewUDP 创建一个新的 UDP 流分析器
func (a *OICQAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
    return &OICQUDPStream{
        logger: logger,
    }
}

// NewTCP 创建一个新的 TCP 流分析器
func (a *OICQAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    return &OICQTCPStream{
        logger: logger,
        buffer: bytes.Buffer{},
        mutex:  &sync.Mutex{},
    }
}

// OICQUDPStream 处理 UDP 流量
type OICQUDPStream struct {
    logger analyzer.Logger
}

// Feed 处理 UDP 数据包
func (s *OICQUDPStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
    m := parseOICQMessage(data)
    if m == nil {
        return nil, false // 继续分析后续数据包
    }

    // 记录检测到的 OICQ 流量
    s.logger.Info("Detected OICQ UDP traffic: %+v", m)

    // 返回封锁指令
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M:    m,
    }, true // 停止分析，触发封锁
}

// Close 关闭 UDP 流
func (s *OICQUDPStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}

// OICQTCPStream 处理 TCP 流量
type OICQTCPStream struct {
    logger analyzer.Logger
    buffer bytes.Buffer
    mutex  *sync.Mutex
}

// Feed 处理 TCP 数据流
func (s *OICQTCPStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    // 将新数据添加到缓冲区
    s.buffer.Write(data)
    bufferedData := s.buffer.Bytes()

    // 查找所有可能的 OICQ 包
    startIndex := bytes.IndexByte(bufferedData, OICQPacketStartFlag)
    for startIndex != -1 {
        // 检查是否有足够的数据
        if startIndex+10 > len(bufferedData) {
            break // 等待更多数据
        }

        // 查找结束标志
        endIndex := bytes.IndexByte(bufferedData[startIndex+1:], OICQPacketEndFlag)
        if endIndex == -1 {
            break // 等待更多数据
        }
        endIndex += startIndex + 1

        // 提取完整的包
        packet := bufferedData[startIndex : endIndex+1]

        // 解析包
        m := parseOICQMessage(packet)
        if m != nil {
            // 记录检测到的 OICQ 流量
            s.logger.Info("Detected OICQ TCP traffic: %+v", m)

            // 清空缓冲区
            s.buffer.Reset()

            // 返回封锁指令
            return &analyzer.PropUpdate{
                Type: analyzer.PropUpdateReplace,
                M:    m,
            }, true // 停止分析，触发封锁
        }

        // 继续查找下一个可能的包
        startIndex = bytes.IndexByte(bufferedData[endIndex+1:], OICQPacketStartFlag)
        if startIndex != -1 {
            startIndex += endIndex + 1
        }
    }

    // 移除已处理的数据
    if startIndex > 0 {
        s.buffer.Next(startIndex)
    }

    return nil, false // 继续分析
}

// Close 关闭 TCP 流
func (s *OICQTCPStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}

// parseOICQMessage 解析 OICQ 消息，返回属性映射
func parseOICQMessage(data []byte) analyzer.PropMap {
    /*
        OICQ Packet Structure:
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
        |SFlag| Version | Command | Sequence | Number |
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
        | ................Data................(Dynamic Len)|EFlag|
        +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
    */

    // 最小长度检查（包括 SFlag 和 EFlag）
    if len(data) < 12 {
        return nil
    }

    // 检查起始和结束标志
    if data[0] != OICQPacketStartFlag || data[len(data)-1] != OICQPacketEndFlag {
        return nil
    }

    // 解析字段
    version := binary.BigEndian.Uint16(data[1:3])
    command := binary.BigEndian.Uint16(data[3:5])
    seq := binary.BigEndian.Uint16(data[5:7])
    number := binary.BigEndian.Uint32(data[7:11])

    // 基本字段验证
    if version == 0 || command == 0 || number == 0 {
        return nil
    }

    // 验证版本号
    if !knownOICQVersions[version] {
        return nil
    }

    // 构建属性映射
    m := analyzer.PropMap{
        "protocol": "OICQ",
        "version":  version,
        "command":  command,
        "seq":      seq,
        "number":   number,
        // 可以根据需要添加更多字段
    }

    return m
}
