package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
)

// NewClaims creates and returns a link to a new claims block
func NewClaims(claims []byte) (*Claims, error) {
	c := make(Claims)
	if err := json.Unmarshal(claims, &c); err != nil {
		return nil, errors.New(fmt.Sprintf("incorrect claims data: %s", err.Error()))
	}
	return &c, nil
}

// Claims payload parameter map
type Claims map[string]interface{}
