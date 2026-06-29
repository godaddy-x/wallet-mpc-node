// Package dto 定义钱包 API 与 CLI 使用的请求/响应及 MPC 相关数据结构（easyjson 生成代码在 *_easyjson.go）。
// import 路径：github.com/godaddy-x/wallet-mpc-node/dto。
package dto

import "github.com/godaddy-x/freego/node/common"

//easyjson:json
type CliWalletResult struct {
	Alias    string `json:"alias"`
	WalletID string `json:"walletID"`
	RootPath string `json:"rootPath"`
	Version  int    `json:"version"`
}

//easyjson:json
type CliFindWalletListReq struct {
	common.BaseReq
}

//easyjson:json
type CliFindWalletListRes struct {
	Result []WalletResult `json:"result"`
}

//easyjson:json
type CliUnlockWalletReq struct {
	common.BaseReq
	Filename string `json:"filename"`
}

//easyjson:json
type CliUnlockWalletRes struct {
	WalletID string `json:"walletID"`
}

//easyjson:json
type CliCreateMPCWalletReq struct {
	common.BaseReq
	Alias     string `json:"alias"`
	Algorithm string `json:"algorithm"` // ecdsa | ed25519
}

//easyjson:json
type CliCreateMPCWalletRes struct {
	WalletID  string `json:"walletID"`
	Algorithm string `json:"algorithm"`
}

//easyjson:json
type CliCreateAccountReq struct {
	common.BaseReq
	WalletID  string `json:"walletID"`
	LastIndex int64  `json:"lastIndex"` // 錢包所屬帳戶ID最後索引值
}

//easyjson:json
type CliCreateAccountRes struct {
	WalletID       string   `json:"walletID"`
	AccountID      string   `json:"accountID"`
	OtherOwnerKeys []string `json:"otherOwnerKeys"`
	ReqSigs        int64    `json:"reqSigs"`
	PublicKey      string   `json:"publicKey"`
	HdPath         string   `json:"hdPath"`
	AccountIndex   int64    `json:"accountIndex"`
	AddressIndex   int64    `json:"addressIndex"`
}

//easyjson:json
type CliCreateAddressReq struct {
	common.BaseReq
	WalletID     string `json:"walletID"`
	AccountID    string `json:"accountID"`
	AccountIndex int64  `json:"accountIndex"` // 錢包所屬账户ID索引值
	MainSymbol   string `json:"symbol"`       // 币种字段
	LastIndex    int64  `json:"lastIndex"`    // 錢包所屬地址ID最後索引值
	Count        int64  `json:"count"`        // 地址数量
	Change       int64  `json:"change"`       // 0=外部地址, 1=找零
}

//easyjson:json
type AddressData struct {
	AddressIndex  int64  `json:"addressIndex"`
	AddressPubHex string `json:"addressPubHex"`
	HdPath        string `json:"hdPath"`
}

//easyjson:json
type CliCreateAddressRes struct {
	AddressList []AddressData `json:"addressList"`
}

//easyjson:json
type CliSignTransactionReq struct {
	common.BaseReq
	Type      int64  `json:"type"` // 0 普通交易 1 汇总交易 2 合约写链（SmartContractRawTransaction，与 wallet-adapter flow 一致）
	Data      string `json:"data"`
	TradeSign string `json:"tradeSign"` // CLI系统进行校验签名
}

//easyjson:json
type CliSignTransactionRes struct {
	SignerList map[string]string `json:"signerList"`
}

//easyjson:json
type CliSignTradeKeyReq struct {
	common.BaseReq
	Type int64  `json:"type"` // 0 普通 1 汇总 2 合约写链
	Data string `json:"data"`
}

//easyjson:json
type CliSignTradeKeyRes struct {
	Sign string `json:"sign"`
}

//easyjson:json
type CliMPCPublicKeyPair struct {
	Subject   string `json:"subject"`
	PublicKey string `json:"publicKey"`
}

// CliMPCKeygenStartRes 服务端下发给节点的「开始 MPC keygen」消息（push: mpcKeygenStart）
//
//easyjson:json
type CliMPCKeygenStartRes struct {
	TaskID        string                `json:"taskID"`
	Algorithm     string                `json:"algorithm,omitempty"` // MPC 算法标识，例如 \"ecdsa\"、\"ed25519\"
	NodeIDs       []string              `json:"nodeIDs"`
	Threshold     int                   `json:"threshold"`
	ExpiredTime   int64                 `json:"expiredTime"`
	PublicKeyPair []CliMPCPublicKeyPair `json:"publicKeyPair"`
}

// CliMPCKeygenResultReq 节点上报 keygen 结果（POST /ws/mpcKeygenResult）
//
//easyjson:json
type CliMPCKeygenResultReq struct {
	common.BaseReq
	TaskID     string `json:"taskID"`
	NodeID     string `json:"nodeID"`
	KeyID      string `json:"keyID"`
	RootPubHex string `json:"rootPubHex"` // 65-byte uncompressed root pubkey hex (04||X||Y)
	Err        string `json:"err"`
}

// CliMPCKeygenResultRes 服务端对 keygen 结果的上报响应
//
//easyjson:json
type CliMPCKeygenResultRes struct {
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
}

// CliMPCKeygenMsgRes 加密前内层 payload（经 ML-KEM-1024 封装在 CliMPCEncryptData.Data 中）
//
//easyjson:json
type CliMPCKeygenMsgRes struct {
	TaskID          string `json:"taskID"`
	WireBytesBase64 string `json:"wireBytesBase64"`
	FromIndex       int    `json:"fromIndex"`
	IsBroadcast     bool   `json:"isBroadcast"`
}

// CliMPCTempPublicKeyReq 节点推送给服务端临时 ML-KEM-1024 封装公钥（base64，1568 字节）
//
//easyjson:json
type CliMPCTempPublicKeyReq struct {
	common.BaseReq
	TaskID    string `json:"taskID"`
	Module    string `json:"module"`
	PublicKey string `json:"publicKey"`
}

// CliMPCTempPublicKeyRes 节点推送给服务端临时 ML-KEM-1024 封装公钥结果
//
//easyjson:json
type CliMPCTempPublicKeyRes struct {
	Success bool `json:"success"`
}

// CliMPCEncryptData 加密传输对象
//
//easyjson:json
type CliMPCEncryptData struct {
	TaskID  string `json:"taskID"`
	Subject string `json:"subject"`
	Data    string `json:"data"`
}

// 分布式签名相关 DTO

//easyjson:json
type SignData struct {
	WalletID     string
	AccountIndex int64
	Change       int64
	AddressIndex int64
	Message      string
}

// CliMPCSignStartRes 服务端下发给节点的「开始 MPC sign」消息（push: mpcSignStart）
//
//easyjson:json
type CliMPCSignStartRes struct {
	TaskID        string                `json:"taskID"`
	Algorithm     string                `json:"algorithm,omitempty"` // MPC 算法标识，例如 \"ecdsa\"、\"ed25519\"
	KeyID         string                `json:"keyID"`               // 要使用的根密钥 KeyID
	AllNodeIDs    []string              `json:"allNodeIDs"`          // 全量节点列表
	SignNodeIDs   []string              `json:"signNodeIDs"`         // 参与签名的节点（TSS 顺序）
	Threshold     int                   `json:"threshold"`           // 门限（通常与 keygen 一致）
	ExpiredTime   int64                 `json:"expiredTime"`         // 任务过期时间，秒级时间戳
	PublicKeyPair []CliMPCPublicKeyPair `json:"publicKeyPair"`
	SignData      SignData              `json:"signData"` // 签名数据内容与参数
	RefreshWarmOnly bool                `json:"refreshWarmOnly,omitempty"` // true：仅后台 refresh warm，不签名
}

// CliMPCSignResultReq 节点上报签名结果（POST /ws/mpcSignResult）
//
//easyjson:json
type CliMPCSignResultReq struct {
	common.BaseReq
	TaskID       string `json:"taskID"`
	NodeID       string `json:"nodeID"`
	KeyID        string `json:"keyID"`
	SignatureHex string `json:"signatureHex"` // R||S 的 64字节 hex（或空，当 Err 不为空时）
	Err          string `json:"err"`
	RefreshWarmOK bool  `json:"refreshWarmOK,omitempty"` // 后台 refresh warm 成功
	NeedRefreshWarm bool `json:"needRefreshWarm,omitempty"` // 材料使用次数达阈值，建议触发 warm
	MaterialUseCount int `json:"materialUseCount,omitempty"` // 本次签名后材料 uses 计数
}

// CliMPCSignResultRes 服务端对签名结果上报的响应
//
//easyjson:json
type CliMPCSignResultRes struct {
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
}

// CliMPCSignMsgRes 加密前内层 payload（经 ML-KEM-1024 封装在 CliMPCEncryptData.Data 中）
//
//easyjson:json
type CliMPCSignMsgRes struct {
	TaskID          string `json:"taskID"`
	WireBytesBase64 string `json:"wireBytesBase64"`
	FromIndex       int    `json:"fromIndex"`
	IsBroadcast     bool   `json:"isBroadcast"`
}

//easyjson:json
type CliMPCResultRes struct {
	OK bool `json:"ok"`
}
