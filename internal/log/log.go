// Package log provides MPC node process logging helpers.
package log

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/godaddy-x/freego/zlog"
)

// InitNodeLog configures zlog after node JSON config is loaded ({source}.log).
func InitNodeLog(source, level string, console bool, logDir string) {
	logName := nodeLogFileFromSource(source)
	var logPath string
	if d := strings.TrimSpace(logDir); d != "" {
		logPath = filepath.Join(filepath.Clean(d), logName)
	} else {
		exe, err := os.Executable()
		if err != nil {
			panic("cannot resolve executable path for log file: " + err.Error())
		}
		logPath = filepath.Join(filepath.Clean(filepath.Dir(exe)), logName)
	}
	lvl := normalizeLogLevel(level)
	loc, _ := time.LoadLocation("Asia/Shanghai")
	zlog.InitDefaultLog(&zlog.ZapConfig{
		Layout:   0,
		Location: loc,
		Level:    lvl,
		Console:  console,
		FileConfig: &zlog.FileConfig{
			Filename:   logPath,
			MaxSize:    512,
			MaxBackups: 7,
			MaxAge:     30,
			Compress:   true,
		},
	})
}

func normalizeLogLevel(level string) string {
	s := strings.ToLower(strings.TrimSpace(level))
	switch s {
	case zlog.DEBUG, zlog.INFO, zlog.WARN, zlog.ERROR:
		return s
	default:
		return zlog.ERROR
	}
}

func nodeLogFileFromSource(source string) string {
	base := strings.TrimSpace(source)
	if base != "" {
		base = filepath.Base(base)
	}
	if base == "" || base == "." || base == ".." {
		panic("node config source is empty or invalid; cannot create {source}.log")
	}
	return base + ".log"
}

// Keygenf logs MPC keygen diagnostics at debug level.
func Keygenf(format string, args ...interface{}) {
	msg := strings.TrimRight(fmt.Sprintf("[mpc-keygen] "+format, args...), "\r\n")
	if zlog.IsDebug() {
		zlog.Debug(msg, 0)
	}
}

// Signf logs MPC sign diagnostics at debug level.
func Signf(format string, args ...interface{}) {
	msg := strings.TrimRight(fmt.Sprintf("[mpc-sign] "+format, args...), "\r\n")
	if zlog.IsDebug() {
		zlog.Debug(msg, 0)
	}
}

// SignErrf logs MPC sign trace and error events.
func SignErrf(format string, args ...interface{}) {
	msg := strings.TrimRight(fmt.Sprintf("[mpc-sign] "+format, args...), "\r\n")
	if strings.HasPrefix(format, "TRACE_") {
		switch {
		case strings.Contains(format, "FAILED"),
			strings.Contains(format, "TIMEOUT"),
			strings.Contains(format, "FINAL_FAILED"),
			strings.Contains(format, "NO_PUBKEY"),
			strings.Contains(format, "NO_DECAPS_KEY"),
			strings.Contains(format, "RECVCH_WAIT"):
			zlog.Error(msg, 0)
		default:
			zlog.Info(msg, 0)
		}
		return
	}
	zlog.Error(msg, 0)
}
