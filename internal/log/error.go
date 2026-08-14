// Package log provides MPC node process logging helpers.
package log

import (
	"fmt"
	"strings"

	"github.com/godaddy-x/freego/core/ex"
	"github.com/godaddy-x/freego/infra/zlog"
	"go.uber.org/zap"
)

// ParsedError is a human-readable view of freego ex.Throw (and plain errors).
type ParsedError struct {
	Msg    string
	Code   int
	Detail string
}

// ParseError unwraps structured freego errors for logging.
func ParseError(err error) ParsedError {
	if err == nil {
		return ParsedError{}
	}
	t := ex.Catch(err)
	msg := strings.TrimSpace(t.Msg)
	if msg == "" {
		msg = strings.TrimSpace(err.Error())
	}
	detail := strings.TrimSpace(t.ErrMsg)
	if detail == msg {
		detail = ""
	}
	return ParsedError{Msg: msg, Code: t.Code, Detail: detail}
}

// FormatError returns a single-line message suitable for logs and stderr.
func FormatError(err error) string {
	return ParseError(err).ErrorText()
}

// ErrorText renders ParsedError as one line.
func (p ParsedError) ErrorText() string {
	if p.Msg == "" {
		return ""
	}
	if p.Code > 0 && p.Code != ex.BIZ {
		if p.Detail != "" {
			return fmt.Sprintf("%s (code=%d, detail=%s)", p.Msg, p.Code, p.Detail)
		}
		return fmt.Sprintf("%s (code=%d)", p.Msg, p.Code)
	}
	if p.Detail != "" {
		return fmt.Sprintf("%s: %s", p.Msg, p.Detail)
	}
	return p.Msg
}

// ZapFields returns structured log fields for an error.
func (p ParsedError) ZapFields() []zap.Field {
	if p.Msg == "" {
		return nil
	}
	fields := []zap.Field{zlog.String("error", p.Msg)}
	if p.Code > 0 && p.Code != ex.BIZ {
		fields = append(fields, zlog.Int("code", p.Code))
	}
	if p.Detail != "" {
		fields = append(fields, zlog.String("detail", p.Detail))
	}
	return fields
}

// ZapErrorFields parses err and returns structured log fields.
func ZapErrorFields(err error) []zap.Field {
	return ParseError(err).ZapFields()
}
