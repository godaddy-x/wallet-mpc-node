package mobile

import (
	"strings"
	"testing"
)

func TestPrepareMobileNodeConfigStripsSecrets(t *testing.T) {
	in := `{
		"domain": "127.0.0.1:9522",
		"source": "node1",
		"keyPath": "/ws/key",
		"loginPath": "/ws/login",
		"clientNo": 1,
		"clientPrk": "secret-prk",
		"serverPub": "pub",
		"broadcastKey": "bc",
		"keystoreKey": "secret-keystore",
		"shardKeysDir": "keys"
	}`

	redacted, secrets, err := prepareMobileNodeConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	if secrets.keystoreKey != "secret-keystore" {
		t.Fatalf("keystoreKey=%q", secrets.keystoreKey)
	}
	if secrets.clientPrk != "secret-prk" {
		t.Fatalf("clientPrk=%q", secrets.clientPrk)
	}

	out := string(redacted)
	for _, forbidden := range []string{`"keystoreKey"`, `"clientPrk"`, "secret-keystore", "secret-prk"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("redacted config must not contain %q: %s", forbidden, out)
		}
	}
	for _, required := range []string{`"domain"`, `"source"`, `"serverPub"`, `"broadcastKey"`} {
		if !strings.Contains(out, required) {
			t.Fatalf("redacted config missing %q: %s", required, out)
		}
	}
}
