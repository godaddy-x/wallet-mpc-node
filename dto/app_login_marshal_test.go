package dto

import (
	"strings"
	"testing"

	"github.com/godaddy-x/freego/utils"
)

func TestCliPlan2LoginReqMarshalIncludesSource(t *testing.T) {
	req := &CliPlan2LoginReq{Source: "node0"}
	b, err := utils.JsonMarshal(req)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"source"`) || !strings.Contains(s, `node0`) {
		t.Fatalf("marshal missing source: %s", s)
	}
}
