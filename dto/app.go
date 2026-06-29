package dto

import "github.com/godaddy-x/freego/node/common"

//easyjson:json
type AppLoginReq struct {
	common.BaseReq
	AppID  string `json:"appID"`
	Sign   string `json:"sign"`
	Nonce  string `json:"nonce"`
	Time   int64  `json:"time"`
	Source string `json:"source"` // 请求来源
}

//easyjson:json
type AppLoginRes struct {
	Subject string `json:"subject"`
}

// CliPlan2LoginReq MPC/CLI Plan2 登录：身份由外层 ML-DSA + cipherNo 保证，body 仅需 source。
//
//easyjson:json
type CliPlan2LoginReq struct {
	common.BaseReq
	Source string `json:"source"`
}

//easyjson:json
type CliPlan2LoginRes struct {
	Subject string `json:"subject"`
}
