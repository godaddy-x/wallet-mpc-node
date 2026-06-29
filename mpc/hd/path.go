package hd

import (
	"fmt"
	"strconv"
	"strings"
)

const MPCPurposeIndex = 0

// MPCHDPath 三层 HD 路径：m/0/accountIndex/change/addressIndex（全非硬化）。
type MPCHDPath struct {
	AccountIndex uint32
	Change       uint32
	AddressIndex uint32
}

func NewMPCHDPath(accountIndex, change, addressIndex uint32) MPCHDPath {
	return MPCHDPath{
		AccountIndex: accountIndex,
		Change:       change,
		AddressIndex: addressIndex,
	}
}

// FormatAccountHDPath 账户层展示路径 m/0/{account}。
func FormatAccountHDPath(accountIndex uint32) string {
	return fmt.Sprintf("m/%d/%d", MPCPurposeIndex, accountIndex)
}

// FormatAddressHDPath 地址层完整路径 m/0/{account}/{change}/{address}。
func FormatAddressHDPath(accountIndex, change, addressIndex uint32) string {
	return fmt.Sprintf("m/%d/%d/%d/%d", MPCPurposeIndex, accountIndex, change, addressIndex)
}

func (p MPCHDPath) FormatAddress() string {
	return FormatAddressHDPath(p.AccountIndex, p.Change, p.AddressIndex)
}

// ParseMPCHDPath 解析 m/0/account/change/address。
func ParseMPCHDPath(path string) (MPCHDPath, error) {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimPrefix(path, "m/")
	if path == "" {
		return MPCHDPath{}, fmt.Errorf("hd: empty path")
	}
	parts := strings.Split(path, "/")
	if len(parts) != 4 {
		return MPCHDPath{}, fmt.Errorf("hd: invalid path length: %s", path)
	}
	if parts[0] != strconv.Itoa(MPCPurposeIndex) {
		return MPCHDPath{}, fmt.Errorf("hd: invalid purpose in path: %s", parts[0])
	}
	parseU32 := func(s, label string) (uint32, error) {
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("hd: invalid %s: %w", label, err)
		}
		return uint32(v), nil
	}
	account, err := parseU32(parts[1], "account index")
	if err != nil {
		return MPCHDPath{}, err
	}
	change, err := parseU32(parts[2], "change index")
	if err != nil {
		return MPCHDPath{}, err
	}
	addr, err := parseU32(parts[3], "address index")
	if err != nil {
		return MPCHDPath{}, err
	}
	return MPCHDPath{AccountIndex: account, Change: change, AddressIndex: addr}, nil
}
