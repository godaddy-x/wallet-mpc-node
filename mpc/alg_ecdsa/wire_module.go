package alg_ecdsa

// Wire module byte prefix for protobuf payloads over WS.
const (
	WireModuleDKG     byte = 1
	WireModuleRefresh byte = 2
	WireModuleSign    byte = 3
	WireModulePartPub byte = 4 // partial public key exchange after DKG
)
