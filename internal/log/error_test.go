package log

import (
	"errors"
	"testing"

	"github.com/godaddy-x/freego/core/ex"
)

func TestParseErrorPlain(t *testing.T) {
	err := errors.New("plain failure")
	p := ParseError(err)
	if p.Msg != "plain failure" {
		t.Fatalf("msg=%q", p.Msg)
	}
}

func TestParseErrorThrowJSON(t *testing.T) {
	throw := ex.Throw{
		Code: 502,
		Msg:  "WebSocket connection failed: dial tcp 127.0.0.1:9522: connect: connection refused",
	}
	p := ParseError(throw)
	if p.Code != 502 {
		t.Fatalf("code=%d", p.Code)
	}
	if p.Msg == "" {
		t.Fatal("msg empty")
	}
	text := p.ErrorText()
	if text == throw.Error() {
		t.Fatalf("expected readable text, got json: %s", text)
	}
}

func TestFormatErrorNil(t *testing.T) {
	if FormatError(nil) != "" {
		t.Fatal("expected empty")
	}
}
