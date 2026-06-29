package mpc

import (
	"encoding/base64"
	"fmt"
)

// EncodeWire 将 module + protobuf bytes 编码为 base64（写入 CliMPC*MsgRes.WireBytesBase64）。
func EncodeWire(module byte, protoBytes []byte) string {
	payload := make([]byte, 1+len(protoBytes))
	payload[0] = module
	copy(payload[1:], protoBytes)
	return base64.StdEncoding.EncodeToString(payload)
}

// DecodeWire 解码 module 与 protobuf bytes。
func DecodeWire(wireB64 string) (module byte, protoBytes []byte, err error) {
	raw, err := base64.StdEncoding.DecodeString(wireB64)
	if err != nil {
		return 0, nil, err
	}
	if len(raw) < 1 {
		return 0, nil, fmt.Errorf("mpc: empty wire")
	}
	return raw[0], raw[1:], nil
}
