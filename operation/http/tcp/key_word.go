package http

import (
	"strings"
	"sync"
	"time"

	"github.com/uQUIC/XGFW/analyzer"
)

// 确保接口实现
var (
	_ analyzer.TCPAnalyzer = (*HTTPKeywordBlocker)(nil)
	_ analyzer.TCPStream   = (*httpStream)(nil)
)

// HTTPKeywordBlocker 实现 analyzer.TCPAnalyzer 接口
type HTTPKeywordBlocker struct {
	keyword string
}

// NewHTTPKeywordBlocker 创建新的HTTP关键字检测器
// keyword：用户通过expr表达式定义的关键词（例如："Forbidden"）
func NewHTTPKeywordBlocker(keyword string) *HTTPKeywordBlocker {
	return &HTTPKeywordBlocker{keyword: keyword}
}

// Name 返回分析器名称
func (a *HTTPKeywordBlocker) Name() string {
	return "http-keyword-blocker"
}

// Limit 返回连接限制，0表示无限制
func (a *HTTPKeywordBlocker) Limit() int {
	return 0
}

// NewTCP 创建新的 TCP 流
func (a *HTTPKeywordBlocker) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return &httpStream{
		keyword: keywordMatcher(a.keyword),
		logger:  logger,
	}
}

// keywordMatcher 根据用户定义的expr表达式创建关键词匹配器
// 这里以简单的字符串包含为例，未来可扩展为正则表达式匹配
func keywordMatcher(expr string) func(string) bool {
	return func(content string) bool {
		return strings.Contains(content, expr)
	}
}

// httpStream 实现 analyzer.TCPStream 接口
type httpStream struct {
	keyword func(string) bool
	logger  analyzer.Logger

	mutex   sync.Mutex
}

// Feed 处理每个TCP数据包
// 如果数据包中包含关键词，则返回PropUpdate指令丢弃该包
func (s *httpStream) Feed(rev bool, data []byte) (*analyzer.PropUpdate, bool) {
	// 只分析客户端->服务器方向的数据包（rev=false）
	if rev {
		return nil, false
	}

	content := string(data)

	// 检查是否包含关键词
	if s.keyword(content) {
		s.logger.Infof("HTTP keyword detected, dropping packet.")
		// 返回PropUpdate指令丢弃该包
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"drop":   true,
				"reason": "keyword-detected",
			},
		}, true
	}

	// 未匹配到关键词，正常继续
	return nil, false
}

// Close 在连接结束时执行清理（如无特殊需求，可以按需填写）
func (s *httpStream) Close(limited bool) *analyzer.PropUpdate {
	// 此处无需特殊处理，返回nil表示不做任何操作
	return nil
}
