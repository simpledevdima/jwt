// Package jwt simple JSON WEB TOKEN to create and validate tokens
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// LoadToken getting token from cookie
func LoadToken(name string, r *http.Request) (string, error) {
	if cookie, err := r.Cookie(name); err != nil {
		return "", errors.New(fmt.Sprintf("variable \"%s\" not found in cookies: %s", name, err.Error()))
	} else {
		return cookie.Value, nil
	}
}

// NewToken creates and returns a new JSON WEB TOKEN
func NewToken(claims []byte, key string) (string, error) {
	if cls, err := NewClaims(claims); err != nil {
		return "", err
	} else {
		t := &Token{
			header: NewHeader(),
			claims: cls,
			key:    key,
		}
		if err = t.makeHashes(); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s.%s.%s", t.hashes[0], t.hashes[1], t.hashes[2]), nil
	}
}

// ValidateToken token validation
func ValidateToken(token string, key string) (bool, error) {
	if t, err := parseToken(token); err != nil {
		return false, err
	} else {
		t.key = key
		return t.isValid()
	}
}

// parseToken assembly of token structures
func parseToken(token string) (*Token, error) {
	hashes := strings.Split(token, ".")
	if len(hashes) != 3 {
		return nil, errors.New("the token must consist of three elements separated by dots")
	}
	if claims, err := decodeSection(hashes[1]); err != nil {
		return nil, errors.New(fmt.Sprintf("incorrect claims data: %s", err.Error()))
	} else {
		if cls, err := NewClaims(claims); err != nil {
			return nil, errors.New(fmt.Sprintf("claims format error: %s", err.Error()))
		} else {
			t := &Token{
				header: NewHeader(),
				claims: cls,
				hashes: hashes,
				layout: "2006-01-02T15:04:05Z07:00",
			}
			return t, nil
		}
	}
}

// Token is a token structure
type Token struct {
	header *Header
	claims *Claims
	key    string
	hashes []string
	layout string
}

// isValid determines if the token is valid
func (t *Token) isValid() (bool, error) {
	if valid, err := t.signatureValid(); !valid {
		return false, err
	}
	if valid, err := t.notBeforeValid(); !valid {
		return false, err
	}
	if valid, err := t.expValid(); !valid {
		return false, err
	}
	return true, nil
}

// signatureValid token signature validation
func (t *Token) signatureValid() (bool, error) {
	hasher := hmac.New(sha256.New, []byte(t.key))
	hasher.Write([]byte(fmt.Sprintf("%s.%s", t.hashes[0], t.hashes[1])))
	signature := encodeSection(hasher.Sum(nil))
	if signature == t.hashes[2] {
		return true, nil
	}
	return false, errors.New("signature not valid")
}

// notBeforeValid the token validity time has come
func (t *Token) notBeforeValid() (bool, error) {
	if nbf, ok := (*t.claims)["nbf"]; ok {
		if nbft, err := time.Parse(t.layout, nbf.(string)); err != nil {
			return false, errors.New(fmt.Sprintf("incorrect format of token validity start time: %s", err.Error()))
		} else {
			if nbft.Unix() >= time.Now().Unix() {
				return false, errors.New("token not yet valid")
			}
		}
	}
	return true, nil
}

// expValid the validity period of the token has not yet expired
func (t *Token) expValid() (bool, error) {
	if exp, ok := (*t.claims)["exp"]; ok {
		if expt, err := time.Parse(t.layout, exp.(string)); err != nil {
			return false, errors.New(fmt.Sprintf("incorrect token expiration time format: %s", err.Error()))
		} else {
			if expt.Unix() < time.Now().Unix() {
				return false, errors.New("token expired")
			}
		}
	}
	return true, nil
}

// makeHashes creating header, claim and signature hashes
func (t *Token) makeHashes() error {
	t.hashes = nil
	if jh, err := json.Marshal(t.header); err != nil {
		return errors.New(fmt.Sprintf("failed to convert header to byte slice: %s", err.Error()))
	} else {
		t.hashes = append(t.hashes, encodeSection(jh))
	}
	if jc, err := json.Marshal(t.claims); err != nil {
		return errors.New(fmt.Sprintf("failed to convert claims to byte slice: %s", err.Error()))
	} else {
		t.hashes = append(t.hashes, encodeSection(jc))
	}
	hasher := hmac.New(sha256.New, []byte(t.key))
	hasher.Write([]byte(fmt.Sprintf("%s.%s", t.hashes[0], t.hashes[1])))
	t.hashes = append(t.hashes, encodeSection(hasher.Sum(nil)))
	return nil
}

// encodeSection encodes a slice of bytes into base64 string format
func encodeSection(s []byte) string {
	return base64.RawURLEncoding.EncodeToString(s)
}

// decodeSection decodes a base64 string into a slice of bytes
func decodeSection(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(s)
}
