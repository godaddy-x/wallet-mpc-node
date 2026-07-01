// 节点进程统一入口：配置路径 + 日志选项 + WebSocket 生命周期。
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/godaddy-x/freego/utils/crypto"
	"github.com/godaddy-x/wallet-mpc-node/connect"
	"github.com/godaddy-x/wallet-mpc-node/mpc/keystore"
)

const defaultShardKeysDir = "keys"

// shardKeysDir 为本节点 MPC 分片密钥落盘目录，由 LaunchMPCNode / -keysdir 设置。
var shardKeysDir = defaultShardKeysDir

func setShardKeysDir(dir string) {
	if dir != "" {
		shardKeysDir = dir
	} else {
		shardKeysDir = defaultShardKeysDir
	}
}

// LaunchMPCNode 读取 JSON 配置、env 覆盖、初始化 zlog 并调用 RunMPCNode 连接 WebSocket。
// 分片目录优先级：-keysdir（非空）> json shardKeysDir > 默认 keys。
// 生产 TEE 注入：MPC_NODE_CLIENT_PRK、MPC_KEYSTORE_KEY（见 node/config.go）。
func LaunchMPCNode(configPath, logLevel string, console bool, logDir, keysDirFlag string) (source string, err error) {
	cliConfig, err := loadNodeConfigFile(configPath)
	if err != nil {
		return "", err
	}
	setShardKeysDir(resolveShardKeysDir(keysDirFlag, cliConfig.ShardKeysDir))
	if err := initKeystoreEncryption(cliConfig); err != nil {
		return cliConfig.Source, err
	}
	initNodeLog(cliConfig.Source, logLevel, console, logDir)
	err = RunMPCNode(cliConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "node failed to start source=%s: %v\n", cliConfig.Source, err)
	} else {
		fmt.Printf("node started (source=%s, waiting for server if not connected yet)\n", cliConfig.Source)
	}
	return cliConfig.Source, err
}

func initKeystoreEncryption(cfg connect.SdkConfig) error {
	key := strings.TrimSpace(cfg.KeystoreKey)
	if key == "" {
		return fmt.Errorf("MPC_KEYSTORE_KEY or keystoreKey is required (plaintext keystore shards are not supported)")
	}
	keystore.SetEncryptionKey(key)
	return nil
}

func resolveShardKeysDir(flagVal, configVal string) string {
	if v := strings.TrimSpace(flagVal); v != "" {
		return v
	}
	if v := strings.TrimSpace(configVal); v != "" {
		return v
	}
	return defaultShardKeysDir
}

func migrateShardKeysDir(configPath, keysDirFlag string) error {
	cliConfig, err := loadNodeConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := initKeystoreEncryption(cliConfig); err != nil {
		return err
	}
	setShardKeysDir(resolveShardKeysDir(keysDirFlag, cliConfig.ShardKeysDir))
	migrated, skipped, err := keystore.MigratePlaintextDir(shardKeysDir)
	if err != nil {
		return err
	}
	fmt.Printf("keystore migrate keysdir=%s migrated=%d skipped=%d\n", shardKeysDir, migrated, skipped)
	return nil
}

// LaunchMPCNodeForTest 供测试使用：loglevel=info、默认不写控制台（与 -console 默认一致，仅 {source}.log）；日志目录为 Getwd()（go test 时一般为 node/）。
func LaunchMPCNodeForTest(configPath string) {
	wd, err := os.Getwd()
	if err != nil {
		panic("LaunchMPCNodeForTest: 无法获取工作目录，无法写入 {source}.log: " + err.Error())
	}
	_, _ = LaunchMPCNode(configPath, "info", true, wd, defaultShardKeysDir)
}

func runGenKey(requireEnc bool, outDir string) (*crypto.Plan2ProvisionResult, error) {
	wrapKey := strings.TrimSpace(os.Getenv(crypto.Plan2WrapKeyEnv))
	if requireEnc && wrapKey == "" {
		return nil, fmt.Errorf("%s is required when -enc is set", crypto.Plan2WrapKeyEnv)
	}
	if wrapKey == "" {
		log.Printf("WARN: genkey: %s not set, writing plaintext private key file", crypto.Plan2WrapKeyEnv)
	}
	key, err := crypto.GeneratePlan2KeyPair()
	if err != nil {
		return nil, err
	}
	result, err := crypto.WritePlan2KeyProvision(outDir, wrapKey, key)
	if err != nil {
		return nil, err
	}
	fmt.Printf("genkey: clientNo=%d\n", result.ClientNo)
	fmt.Printf("genkey: wrote %s %s\n", result.PublicPath(), result.PrivatePath())
	return result, nil
}

// Main 解析标准 flag 并启动节点，随后长时间阻塞以保持进程（与原有 main 行为一致）。
func run() {
	name := flag.String("name", "mpc-node", "节点名称")
	configFile := flag.String("config", "cli_node.json", "节点配置文件路径（JSON）；私钥可由 env MPC_NODE_CLIENT_PRK 覆盖")
	logLevel := flag.String("loglevel", "info", "日志级别: debug, info, warn, error（默认 info）")
	logConsole := flag.Bool("console", false, "是否同时输出日志到控制台（默认否，仅写入 {source}.log）")
	logDir := flag.String("logdir", "", "日志文件夹路径（默认可执行文件目录）")
	keysDir := flag.String("keysdir", "", "MPC 分片落盘目录（覆盖 json shardKeysDir；默认 shardKeysDir 或 keys）")
	migrateKeys := flag.Bool("migrate-keys", false, "将 keysdir 下明文分片批量加密后退出（需 MPC_KEYSTORE_KEY 或 keystoreKey）")
	genKey := flag.Bool("genkey", false, "生成 Plan2 密钥")
	genKeyEnc := flag.Bool("enc", false, "与 -genkey 合用：强制加密（需 env MPC_PLAN2_WRAP_KEY）")
	genKeyOutDir := flag.String("outdir", "", "与 -genkey 合用：输出目录（默认 plan2-provision）")
	flag.Parse()

	fmt.Println(*name)

	if *genKey {
		if _, err := runGenKey(*genKeyEnc, *genKeyOutDir); err != nil {
			fmt.Fprintf(os.Stderr, "genkey failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *migrateKeys {
		if err := migrateShardKeysDir(*configFile, *keysDir); err != nil {
			fmt.Fprintf(os.Stderr, "keystore migrate failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if _, err := LaunchMPCNode(*configFile, *logLevel, *logConsole, *logDir, *keysDir); err != nil {
		fmt.Fprintf(os.Stderr, "node launch failed: %v\n", err)
		os.Exit(1)
	}

	select {}
}
