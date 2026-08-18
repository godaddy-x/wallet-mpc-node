module github.com/godaddy-x/wallet-mpc-node

go 1.26

require (
	github.com/decred/dcrd/dcrec/edwards v1.0.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0
	github.com/getamis/alice v1.0.7
	github.com/getamis/sirius v1.1.7
	github.com/godaddy-x/eccrypto v1.1.17
	github.com/godaddy-x/freego v1.1.34
	github.com/godaddy-x/wallet-adapter v1.0.9
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/mailru/easyjson v0.9.1
	go.uber.org/zap v1.27.0
	google.golang.org/protobuf v1.36.10
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	filippo.io/mldsa v0.0.0-20260215214346-43d0283efc3e // indirect
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/lxzan/gws v1.9.1 // indirect
	github.com/minio/blake2b-simd v0.0.0-20160723061019-3f5f724cb5b1 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/rollbar/rollbar-go v1.2.0 // indirect
	github.com/valyala/fastjson v1.6.3 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/mobile v0.0.0-20260803200217-62cee1672c8e // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	gonum.org/v1/gonum v0.16.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

//replace github.com/godaddy-x/freego => ../freego

replace github.com/btcsuite/btcd => github.com/btcsuite/btcd v0.22.1

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)

exclude google.golang.org/genproto v0.0.0-20220819174105-e9f053255caa
