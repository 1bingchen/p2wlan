package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/yhan-sun/p2wlan/server/database"
)

func TestJWTUpgradeGeneratedUserTokenRoundTrip(t *testing.T) {
	service := NewService("jwt-upgrade-test-only", nil)
	user := &database.User{ID: "user-1", Email: "user@example.com"}
	before := time.Now().Unix()
	raw, err := service.generateToken(user)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	after := time.Now().Unix()
	claims, err := service.ValidateToken(raw)
	if err != nil {
		t.Fatalf("validate generated token: %v", err)
	}
	if claims.UserID != user.ID || claims.Email != user.Email || claims.Issuer != "p2pnet" {
		t.Fatalf("generated identity changed: %+v", claims)
	}
	if claims.IssuedAt == nil || claims.ExpiresAt == nil {
		t.Fatal("generated token lost issue or expiry time")
	}
	const ttl = int64(7 * 24 * 60 * 60)
	if claims.IssuedAt.Unix() < before || claims.IssuedAt.Unix() > after ||
		claims.ExpiresAt.Unix() < before+ttl || claims.ExpiresAt.Unix() > after+ttl {
		t.Fatal("generated token changed its seven-day lifetime")
	}
}

func TestJWTUpgradeRejectsInvalidUserTokens(t *testing.T) {
	const secret = "jwt-upgrade-test-only"
	service := NewService(secret, nil)
	now := time.Now()
	sign := func(claims jwt.Claims, key any) string {
		t.Helper()
		raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return raw
	}
	validClaims := func() jwt.MapClaims {
		return jwt.MapClaims{"user_id": "user-1", "iss": "p2pnet", "exp": now.Add(time.Hour).Unix()}
	}
	valid := sign(validClaims(), []byte(secret))
	expired := validClaims()
	expired["exp"] = now.Add(-time.Hour).Unix()
	future := validClaims()
	future["nbf"] = now.Add(time.Hour).Unix()
	wrongType := validClaims()
	wrongType["exp"] = "tomorrow"
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims()).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("construct unsigned rejection case: %v", err)
	}
	for name, raw := range map[string]string{
		"expired":              sign(expired, []byte(secret)),
		"not_yet_valid":        sign(future, []byte(secret)),
		"wrong_signing_key":    sign(validClaims(), []byte("other-test-only-key")),
		"invalid_expiry_type":  sign(wrongType, []byte(secret)),
		"unsigned":             unsigned,
		"empty":                "",
		"extra_segments":       valid + strings.Repeat(".", 8192),
		"bad_signature_base64": valid[:strings.LastIndex(valid, ".")+1] + "!",
	} {
		t.Run(name, func(t *testing.T) {
			claims, err := service.ValidateToken(raw)
			if claims != nil || !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("invalid user token granted claims: claims=%+v err=%v", claims, err)
			}
		})
	}
}
