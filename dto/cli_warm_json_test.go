package dto

import (
	"testing"

	"github.com/godaddy-x/freego/utils"
)

func TestCliMPCSignStartResRefreshWarmOnlyJSON(t *testing.T) {
	payload := CliMPCSignStartRes{
		TaskID:          "warm-task",
		KeyID:           "key1",
		RefreshWarmOnly: true,
	}
	raw, err := utils.JsonMarshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !containsAll(s, `"refreshWarmOnly":true`) {
		t.Fatalf("missing refreshWarmOnly in json: %s", s)
	}
	if containsAll(s, `"signData"`) {
		t.Fatalf("warm payload should omit signData: %s", s)
	}

	var decoded CliMPCSignStartRes
	if err := utils.JsonUnmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.RefreshWarmOnly {
		t.Fatal("RefreshWarmOnly not decoded")
	}
}

func TestCliMPCSignResultReqRefreshWarmOKJSON(t *testing.T) {
	req := CliMPCSignResultReq{
		TaskID:        "warm-task",
		NodeID:        "node0",
		RefreshWarmOK: true,
	}
	raw, err := utils.JsonMarshal(req)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !containsAll(s, `"refreshWarmOK":true`) {
		t.Fatalf("missing refreshWarmOK in json: %s", s)
	}

	var decoded CliMPCSignResultReq
	if err := utils.JsonUnmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.RefreshWarmOK {
		t.Fatal("RefreshWarmOK not decoded")
	}
}

func TestCliMPCSignResultReqNeedRefreshWarmJSON(t *testing.T) {
	req := CliMPCSignResultReq{
		TaskID:          "sign-task",
		NodeID:          "node1",
		NeedRefreshWarm: true,
	}
	raw, err := utils.JsonMarshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(string(raw), `"needRefreshWarm":true`) {
		t.Fatalf("missing needRefreshWarm: %s", raw)
	}
	var decoded CliMPCSignResultReq
	if err := utils.JsonUnmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.NeedRefreshWarm {
		t.Fatal("NeedRefreshWarm not decoded")
	}
}

func containsAll(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
