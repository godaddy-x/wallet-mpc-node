// 节点进程统一 zlog 初始化与 MPC 诊断日志封装（keygen/sign 共用）。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/godaddy-x/freego/zlog"
)

// initNodeLog 在读取节点 JSON 配置后调用，文件名为 {source}.log。
// logDir 非空时日志写在 logDir 下（如 go test 时传入 Getwd()，文件会出现在包目录）；为空时写在可执行文件所在目录（正式部署）。
// console 为 true 时额外输出到标准输出。
// source 为空或经 Base 后为非法名时 panic，须在 JSON 中填写有效 source。
// level 为 debug / info / warn / error（大小写不敏感）；非法或空则按 error。
func initNodeLog(source, level string, console bool, logDir string) {
	logName := nodeLogFileFromSource(source)
	var logPath string
	if d := strings.TrimSpace(logDir); d != "" {
		logPath = filepath.Join(filepath.Clean(d), logName)
	} else {
		exe, err := os.Executable()
		if err != nil {
			panic("无法获取可执行文件路径，无法确定日志目录: " + err.Error())
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

// nodeLogFileFromSource 返回日志文件名（不含目录）：{source}.log。
func nodeLogFileFromSource(source string) string {
	base := strings.TrimSpace(source)
	if base != "" {
		base = filepath.Base(base)
	}
	if base == "" || base == "." || base == ".." {
		panic("节点配置 source 为空或非法，无法生成日志文件名（{source}.log），请在 JSON 中设置有效 source")
	}
	return base + ".log"
}

func logKeygenf(format string, args ...interface{}) {
	msg := strings.TrimRight(fmt.Sprintf("[mpc-keygen] "+format, args...), "\r\n")
	if zlog.IsDebug() {
		zlog.Debug(msg, 0)
	}
}

func logSignf(format string, args ...interface{}) {
	msg := strings.TrimRight(fmt.Sprintf("[mpc-sign] "+format, args...), "\r\n")
	if zlog.IsDebug() {
		zlog.Debug(msg, 0)
	}
}

func logSignErrf(format string, args ...interface{}) {
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
