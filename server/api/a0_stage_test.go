package api

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestHardHardA0SessionTagsAreStableAndRedacted(t *testing.T) {
	const token = "a01face0-1234abcd"
	role, sessionTag, planTag, ok := hardHardA0SessionTags("hh1:i:" + token + ":1:2:3:4")
	if !ok {
		t.Fatal("valid Hard-Hard session envelope was rejected")
	}
	if role != "initiator" || sessionTag != "a8d6d3fb9b4788de" || planTag != "91a49269735e274e" {
		t.Fatalf("unexpected A0 identity tags: role=%q session=%q plan=%q", role, sessionTag, planTag)
	}
	if strings.Contains(sessionTag+planTag, token) {
		t.Fatal("A0 identity tags exposed the raw session token")
	}
	for _, malformed := range []string{"ordinary-session", "hh1:x:" + token + ":1", "hh1:i:unsafe/token:1"} {
		if _, _, _, ok := hardHardA0SessionTags(malformed); ok {
			t.Fatalf("malformed Hard-Hard session envelope accepted: %q", malformed)
		}
	}
}

func TestHardHardA0SessionTagsMatchNativeHH2Envelope(t *testing.T) {
	// These golden envelopes are emitted by the native HH2 encoder and
	// checked in control::tests::hard_hard_a0_control_tags_cover_native_hh2_stages.
	const offer = "hh2:KAARIjNEVWZ3iJmqu8zd7v8AAAAAAAAAAQAAAAAAAAACAAAAAAAAAAMAAAAAAAAABAAAAAAAAAAAAAAAAAQCnEEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJQAL"
	const syncAck = "hh2:bQARIjNEVWZ3iJmqu8zd7v8AAAAAAAAAAQAAAAAAAAACAAAAAAAAAAMAAAAAAAAABAAAAAAAAAAAAAAAAAQCnEEEA8NRA6WlpaWlpaWlpaWlpaWlpaUAJQAL"
	for stage := byte(0); stage < 6; stage++ {
		fixture := syncAck
		if stage == 0 {
			fixture = offer
		}
		wire, err := base64.RawURLEncoding.DecodeString(fixture[4:])
		if err != nil {
			t.Fatal(err)
		}
		wire[0] = (stage & 3) | ((stage & 4) << 4) | 8 | 2<<4
		wantRole := "initiator"
		if stage%2 == 1 {
			wire[0] |= 4
			wantRole = "responder"
		}
		envelope := "hh2:" + base64.RawURLEncoding.EncodeToString(wire)
		role, sessionTag, planTag, ok := hardHardA0SessionTags(envelope)
		if !ok || role != wantRole || sessionTag != "bc24448362b87728" || planTag != "b20ba067978b0938" {
			t.Fatalf("HH2 stage %d has incorrect redacted identity: role=%q session=%q plan=%q ok=%v", stage, role, sessionTag, planTag, ok)
		}
	}
}

func TestHardHardA0SessionTagsRejectMalformedHH2Envelope(t *testing.T) {
	const payload = "KAARIjNEVWZ3iJmqu8zd7v8AAAAAAAAAAQAAAAAAAAACAAAAAAAAAAMAAAAAAAAABAAAAAAAAAAAAAAAAAQCnEEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJQAL"
	wire, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	malformed := []string{
		"hh2:invalid",
		"hh2:" + payload + "=",
		"hh2:" + payload + ":suffix",
		"hh2:" + base64.RawURLEncoding.EncodeToString(wire[:89]),
		"hh2:" + base64.RawURLEncoding.EncodeToString(append(append([]byte(nil), wire...), 0)),
		"hh2:!" + payload[1:],
	}
	for _, flags := range []byte{0x80, 0x30, 0x42, 4} {
		mutated := append([]byte(nil), wire...)
		mutated[0] = flags
		malformed = append(malformed, "hh2:"+base64.RawURLEncoding.EncodeToString(mutated))
	}
	for index, envelope := range malformed {
		if _, _, _, ok := hardHardA0SessionTags(envelope); ok {
			t.Errorf("malformed HH2 envelope %d accepted", index)
		}
	}
}
