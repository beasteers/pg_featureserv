package auth

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CrunchyData/pg_featureserv/internal/conf"
)

// minimal structures for JWT header/payload
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// VerifyAndExtract verifies the token and returns payload claims
// Supports HS256 with shared secret and RS256 with PEM public key file
func VerifyAndExtract(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}
	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	// base64url decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT header: %w", err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, fmt.Errorf("invalid JWT header JSON: %w", err)
	}

	// decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid JWT payload JSON: %w", err)
	}

	// verify signature
	signingInput := headerB64 + "." + payloadB64
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT signature encoding: %w", err)
	}

	switch strings.ToUpper(hdr.Alg) {
	case "HS256":
		sec := conf.Configuration.Auth.JWTHS256Secret
		if sec == "" {
			return nil, errors.New("hs256 secret not configured")
		}
		mac := hmac.New(sha256.New, []byte(sec))
		mac.Write([]byte(signingInput))
		sum := mac.Sum(nil)
		if !hmac.Equal(sum, sig) {
			return nil, errors.New("invalid JWT signature")
		}
	case "RS256":
		pk, err := resolveRSAPublicKey(hdr.Kid)
		if err != nil {
			return nil, fmt.Errorf("resolve public key: %w", err)
		}
		h := sha256.New()
		h.Write([]byte(signingInput))
		digest := h.Sum(nil)
		if err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest, sig); err != nil {
			return nil, errors.New("invalid JWT signature")
		}
	default:
		return nil, fmt.Errorf("unsupported jwt alg: %s", hdr.Alg)
	}

	// validate registered claims if configured
	if err := validateRegisteredClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// parse RSAPublicKey from PEM (PKIX or PKCS1)
func parseRSAPublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	// handle PEM block
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid PEM public key")
	}
	// try PKIX first
	if pk, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if k, ok := pk.(*rsa.PublicKey); ok {
			return k, nil
		}
	}
	// try PKCS1
	if k, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported RSA public key format")
}

// ---------- JWKS / URL key resolution ----------

type jwk struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	Alg string   `json:"alg"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwksCacheEntry struct {
	fetchedAt time.Time
	keys      map[string]*rsa.PublicKey // kid -> key
	anyKey    *rsa.PublicKey            // fallback
}

var (
	jwksMu    sync.Mutex
	jwksCache = map[string]jwksCacheEntry{}
	httpc     = &http.Client{Timeout: 5 * time.Second}
)

func resolveRSAPublicKey(kid string) (*rsa.PublicKey, error) {
	cfg := conf.Configuration.Auth
	// 1) file path or URL in JWTPublicKeyFile
	if v := strings.TrimSpace(cfg.JWTPublicKeyFile); v != "" {
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
			if pk := rsaKeyFromURLCached(v, kid); pk != nil {
				return pk, nil
			}
			return nil, fmt.Errorf("no matching key found at %s", v)
		}
		// Local PEM file path
		pemBytes, err := ioutil.ReadFile(v)
		if err != nil {
			return nil, fmt.Errorf("read public key: %w", err)
		}
		pk, err := parseRSAPublicKeyFromPEM(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		return pk, nil
	}

	// 2) explicit URL
	if v := strings.TrimSpace(cfg.JWTPublicKeyURL); v != "" {
		if pk := rsaKeyFromURLCached(v, kid); pk != nil {
			return pk, nil
		}
		return nil, fmt.Errorf("no matching key found at %s", v)
	}

	// 3) OIDC discovery via issuer -> well-known -> jwks_uri
	if iss := strings.TrimRight(strings.TrimSpace(cfg.JWTIssuer), "/"); iss != "" {
		wk := iss + "/.well-known/openid-configuration"
		jwksURL, err := fetchWellKnownJWKSURL(wk)
		if err != nil {
			return nil, err
		}
		if pk := rsaKeyFromURLCached(jwksURL, kid); pk != nil {
			return pk, nil
		}
		return nil, fmt.Errorf("no matching key found at %s", jwksURL)
	}

	return nil, errors.New("rs256 public key not configured")
}

func rsaKeyFromURLCached(url string, kid string) *rsa.PublicKey {
	// check cache
	jwksMu.Lock()
	entry, ok := jwksCache[url]
	jwksMu.Unlock()

	ttl := time.Duration(conf.Configuration.Auth.JWKSRefreshSec) * time.Second
	needsFetch := true
	if ok && time.Since(entry.fetchedAt) < ttl {
		needsFetch = false
	}

	if needsFetch {
		if e := fetchAndCacheJWKS(url); e != nil {
			// fall through to use stale cache if any
		}
		jwksMu.Lock()
		entry = jwksCache[url]
		jwksMu.Unlock()
	}

	if entry.keys != nil {
		if kid != "" {
			if k := entry.keys[kid]; k != nil {
				return k
			}
		}
		if entry.anyKey != nil {
			return entry.anyKey
		}
	}
	return nil
}

func fetchAndCacheJWKS(url string) error {
	// Fetch URL; try to parse as JWKS; if not, try as PEM
	resp, err := httpc.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Try JSON JWKS first
	var j jwks
	if err := json.Unmarshal(body, &j); err == nil && len(j.Keys) > 0 {
		keys := map[string]*rsa.PublicKey{}
		var any *rsa.PublicKey
		for _, k := range j.Keys {
			if strings.ToUpper(k.Kty) != "RSA" {
				continue
			}
			if pk := rsaFromJWK(k); pk != nil {
				if any == nil {
					any = pk
				}
				if k.Kid != "" {
					keys[k.Kid] = pk
				}
			}
		}
		jwksMu.Lock()
		jwksCache[url] = jwksCacheEntry{fetchedAt: time.Now(), keys: keys, anyKey: any}
		jwksMu.Unlock()
		return nil
	}

	// Try PEM certificate/key (single key)
	if pk, err := parseRSAPublicKeyFromPEM(body); err == nil {
		jwksMu.Lock()
		jwksCache[url] = jwksCacheEntry{fetchedAt: time.Now(), keys: map[string]*rsa.PublicKey{"": pk}, anyKey: pk}
		jwksMu.Unlock()
		return nil
	}
	return errors.New("unable to parse keys from URL")
}

func rsaFromJWK(k jwk) *rsa.PublicKey {
	// Prefer n/e. If missing, try x5c
	if k.N != "" && k.E != "" {
		nb, errN := base64.RawURLEncoding.DecodeString(k.N)
		eb, errE := base64.RawURLEncoding.DecodeString(k.E)
		if errN == nil && errE == nil {
			n := new(big.Int).SetBytes(nb)
			e := 0
			for _, b := range eb {
				e = e<<8 + int(b)
			}
			if e == 0 {
				e = 65537 // common default
			}
			return &rsa.PublicKey{N: n, E: e}
		}
	}
	if len(k.X5c) > 0 {
		// x5c is base64 DER cert; parse it
		if der, err := base64.StdEncoding.DecodeString(k.X5c[0]); err == nil {
			if cert, err := x509.ParseCertificate(der); err == nil {
				if pk, ok := cert.PublicKey.(*rsa.PublicKey); ok {
					return pk
				}
			}
		}
	}
	return nil
}

func fetchWellKnownJWKSURL(wellKnownURL string) (string, error) {
	resp, err := httpc.Get(wellKnownURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return "", err
	}
	if v, ok := obj["jwks_uri"].(string); ok && v != "" {
		return v, nil
	}
	return "", errors.New("jwks_uri not found in well-known configuration")
}

func validateRegisteredClaims(claims map[string]interface{}) error {
	now := time.Now().Unix()
	// exp
	if v, ok := claims["exp"]; ok {
		switch t := v.(type) {
		case float64:
			if now >= int64(t) {
				return errors.New("token expired")
			}
		case json.Number:
			if i, err := t.Int64(); err == nil && now >= i {
				return errors.New("token expired")
			}
		}
	}
	// nbf
	if v, ok := claims["nbf"]; ok {
		switch t := v.(type) {
		case float64:
			if now < int64(t) {
				return errors.New("token not yet valid")
			}
		case json.Number:
			if i, err := t.Int64(); err == nil && now < i {
				return errors.New("token not yet valid")
			}
		}
	}
	// iss
	if want := conf.Configuration.Auth.JWTIssuer; want != "" {
		if got, _ := claims["iss"].(string); got != want {
			return errors.New("invalid token issuer")
		}
	}
	// aud
	if want := conf.Configuration.Auth.JWTAudience; want != "" {
		switch aud := claims["aud"].(type) {
		case string:
			if aud != want {
				return errors.New("invalid token audience")
			}
		case []interface{}:
			match := false
			for _, a := range aud {
				if s, ok := a.(string); ok && s == want {
					match = true
					break
				}
			}
			if !match {
				return errors.New("invalid token audience")
			}
		}
	}
	return nil
}

// RoleFromClaims extracts configured role claim
func RoleFromClaims(claims map[string]interface{}) string {
	claimName := conf.Configuration.Auth.JWTRoleClaim
	if claimName == "" {
		claimName = "role"
	}
	if v, ok := claims[claimName]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
