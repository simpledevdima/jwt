package jwt

// NewHeader creates and returns a link to a new header block
func NewHeader() *Header {
	h := &Header{
		Alg: "HS256",
		Typ: "JWT",
	}
	return h
}

// Header is a token headers
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}
