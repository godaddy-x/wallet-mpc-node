package app

import (
	"flag"
	"fmt"
	"os"
)

// Run parses CLI flags and starts the MPC node (or genkey / migrate-keys subcommands).
func Run() {
	name := flag.String("name", "mpc-node", "node display name")
	configFile := flag.String("config", "cli_node.json", "node config JSON path; clientPrk may be overridden by MPC_NODE_CLIENT_PRK")
	logLevel := flag.String("loglevel", "info", "log level: debug, info, warn, error")
	logConsole := flag.Bool("console", false, "also log to stdout")
	logDir := flag.String("logdir", "", "log directory (default: executable directory)")
	keysDir := flag.String("keysdir", "", "MPC shard directory (overrides json shardKeysDir)")
	migrateKeys := flag.Bool("migrate-keys", false, "encrypt plaintext shards under keysdir and exit")
	genKey := flag.Bool("genkey", false, "generate Plan2 ML-DSA key pair")
	genKeyEnc := flag.Bool("enc", false, "with -genkey: require encrypted output (MPC_PLAN2_WRAP_KEY)")
	genKeyOutDir := flag.String("outdir", "", "with -genkey: output directory (default plan2-provision)")
	flag.Parse()

	fmt.Println(*name)

	if *genKey {
		if _, err := RunGenKey(*genKeyEnc, *genKeyOutDir); err != nil {
			fmt.Fprintf(os.Stderr, "genkey failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *migrateKeys {
		if err := MigrateShardKeysDir(*configFile, *keysDir); err != nil {
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
