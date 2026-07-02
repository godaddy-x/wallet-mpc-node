// Package tempkey manages ML-KEM-1024 temporary keys for MPC protocol encryption.
package tempkey

import (
	"crypto/mlkem"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	ecc "github.com/godaddy-x/eccrypto"
	"github.com/godaddy-x/freego/cache"
	"github.com/godaddy-x/freego/utils"
	"github.com/godaddy-x/freego/utils/sdk"
	"github.com/godaddy-x/wallet-mpc-node/dto"
)

const (
	KeygenCacheTTL = 900
	SignCacheTTL   = 900
)

const mlkem1024EncapsulationKeyBytes = 1568

var keyCache = cache.NewLocalCache()

func tempPublicKeyCacheKey(mod, subject, taskID string) string {
	return utils.FNV1a64(utils.AddStr(subject, ":", taskID, ":", mod, ":tempPublicKey"))
}

// DecapsKey returns the local ML-KEM decapsulation key for a task/module.
func DecapsKey(mod, subject, taskID string) (*mlkem.DecapsulationKey1024, error) {
	key := utils.FNV1a64(utils.AddStr(subject, ":", taskID, ":", mod, ":tempPrivateKey"))
	value, ok, err := keyCache.Get(key, nil)
	if err != nil {
		return nil, err
	}
	if ok && value != nil {
		return value.(*mlkem.DecapsulationKey1024), nil
	}
	return nil, nil
}

func refreshPrivateKeyTTL(mod, myNodeID, taskID string, ttlSec int) error {
	key := utils.FNV1a64(utils.AddStr(myNodeID, ":", taskID, ":", mod, ":tempPrivateKey"))
	value, ok, err := keyCache.Get(key, nil)
	if err != nil {
		return err
	}
	if !ok || value == nil {
		return errors.New("temp decaps key missing at " + mod + " start")
	}
	if err := keyCache.Put(key, value, ttlSec); err != nil {
		return fmt.Errorf("refresh tempPrivateKey TTL: %w", err)
	}
	return nil
}

// RefreshKeygenPrivateKeyTTL refreshes the local keygen decaps key TTL after mpcKeygenStart.
func RefreshKeygenPrivateKeyTTL(myNodeID, taskID string) error {
	return refreshPrivateKeyTTL("keygen", myNodeID, taskID, KeygenCacheTTL)
}

// RefreshSignPrivateKeyTTL refreshes the local sign decaps key TTL after mpcSignStart.
func RefreshSignPrivateKeyTTL(myNodeID, taskID string) error {
	return refreshPrivateKeyTTL("sign", myNodeID, taskID, SignCacheTTL)
}

// PeerPublicKey returns a peer node's cached ML-KEM encapsulation key bytes.
func PeerPublicKey(mod, subject, taskID string) ([]byte, error) {
	value, ok, err := keyCache.Get(tempPublicKeyCacheKey(mod, subject, taskID), nil)
	if err != nil || !ok || value == nil {
		return nil, err
	}
	switch v := value.(type) {
	case []byte:
		if len(v) == 0 {
			return nil, nil
		}
		return append([]byte(nil), v...), nil
	case string:
		b := utils.Base64Decode(strings.TrimSpace(v))
		if len(b) == 0 {
			return nil, nil
		}
		return append([]byte(nil), b...), nil
	default:
		return nil, nil
	}
}

// PutPeerPublicKey caches a peer ML-KEM encapsulation key from base64.
func PutPeerPublicKey(mod, subject, taskID, pubKeyB64 string, ttl int) error {
	if strings.TrimSpace(pubKeyB64) == "" {
		return errors.New("empty ML-KEM encapsulation key")
	}
	ek, err := ecc.LoadMLKEM1024EncapsulationKeyFromBase64(pubKeyB64)
	if err != nil {
		return fmt.Errorf("invalid ML-KEM-1024 encapsulation key: %w", err)
	}
	pubBytes := ecc.GetMLKEM1024EncapsulationKeyBytes(ek)
	if len(pubBytes) != mlkem1024EncapsulationKeyBytes {
		return fmt.Errorf("invalid ML-KEM-1024 key length: got %d want %d", len(pubBytes), mlkem1024EncapsulationKeyBytes)
	}
	return keyCache.Put(tempPublicKeyCacheKey(mod, subject, taskID), append([]byte(nil), pubBytes...), ttl)
}

// ClearSignSessionKeys removes sign-phase ML-KEM keys for a completed task.
func ClearSignSessionKeys(myNodeID, taskID string, allNodeIDs []string) {
	_ = keyCache.Del(utils.FNV1a64(utils.AddStr(myNodeID, ":", taskID, ":sign:tempPrivateKey")))
	for _, id := range allNodeIDs {
		_ = keyCache.Del(tempPublicKeyCacheKey("sign", id, taskID))
	}
}

// ClearKeygenSessionKeys removes keygen-phase ML-KEM keys for a completed task.
func ClearKeygenSessionKeys(myNodeID, taskID string, allNodeIDs []string) {
	_ = keyCache.Del(utils.FNV1a64(utils.AddStr(myNodeID, ":", taskID, ":keygen:tempPrivateKey")))
	for _, id := range allNodeIDs {
		_ = keyCache.Del(tempPublicKeyCacheKey("keygen", id, taskID))
	}
}

// SubmitTempPublicKey reports the node's ML-KEM encapsulation key to the broker.
func SubmitTempPublicKey(wsClient *sdk.SocketSDK, request *dto.CliMPCTempPublicKeyReq, maxAttempts int) error {
	if wsClient == nil || request == nil {
		return errors.New("SubmitTempPublicKey invalid argument")
	}
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	backoff := []time.Duration{100 * time.Millisecond, 300 * time.Millisecond, 800 * time.Millisecond}
	var lastErr error
	for i := 1; i <= maxAttempts; i++ {
		var response dto.CliMPCTempPublicKeyRes
		err := wsClient.SendWebSocketMessage("/ws/mpcTempPublicKey", request, &response, true, true, 5)
		if err == nil && response.Success {
			return nil
		}
		if err != nil {
			lastErr = err
		} else if !response.Success {
			lastErr = errors.New("server returned success=false for mpcTempPublicKey")
		}
		if i < maxAttempts {
			sleep := backoff[i-1]
			if i-1 >= len(backoff) {
				sleep = backoff[len(backoff)-1]
			}
			time.Sleep(sleep)
		}
	}
	return lastErr
}

// HandleTempPublicKey creates a local ML-KEM key pair and uploads the encapsulation key.
func HandleTempPublicKey(wsClient *sdk.SocketSDK, subject, router string, data []byte) error {
	request := dto.CliMPCTempPublicKeyReq{}
	if err := json.Unmarshal(data, &request); err != nil {
		return errors.New("HandleTempPublicKey json unmarshal error: " + err.Error())
	}
	if request.Module == "" {
		return errors.New("HandleTempPublicKey invalid module")
	}
	var ttl int
	switch request.Module {
	case "keygen":
		ttl = KeygenCacheTTL
	case "sign":
		ttl = SignCacheTTL
	default:
		return errors.New("HandleTempPublicKey invalid module: " + request.Module)
	}
	dk, err := ecc.CreateMLKEM1024()
	if err != nil {
		return errors.New("HandleTempPublicKey create ML-KEM-1024 key error: " + err.Error())
	}
	cacheKey := utils.FNV1a64(utils.AddStr(subject, ":", request.TaskID, ":", request.Module, ":tempPrivateKey"))
	if err := keyCache.Put(cacheKey, dk, ttl); err != nil {
		return errors.New("HandleTempPublicKey put tempPrivateKey error: " + err.Error())
	}
	request.PublicKey = ecc.MLKEM1024EncapsulationKeyToBase64(dk.EncapsulationKey())
	if err := SubmitTempPublicKey(wsClient, &request, 3); err != nil {
		return errors.New("HandleTempPublicKey submit temp public key error: " + err.Error())
	}
	return nil
}
