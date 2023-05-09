# JWT
Package for working with JSON WEB TOKEN.
Issues tokens based on a standard header, submitted claims encrypted with the transmitted secret key using the sha256 algorithm.

## Installation
```
go get github.com/simpledevdima/jwt
```

## Example
```go
package main

import (
	"encoding/json"
	"fmt"
	"github.com/simpledevdima/jwt"
	"log"
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/token", func (w http.ResponseWriter, r *http.Request) {
		secretKey := "abcd"
		var token string
		var err error
		tokenName := "access"
		if token, err = jwt.LoadToken(tokenName, r); err != nil {
			// token not found
			// create new token
			claims := struct {
				Nbf time.Time `json:"nbf"`
				Iat time.Time `json:"iat"`
				Exp time.Time `json:"exp"`
			}{
				Nbf: time.Now().Add(time.Minute * 1),
				Iat: time.Now(),
				Exp: time.Now().Add(time.Minute * 2),
			}
			jclaims, err := json.Marshal(claims)
			if err != nil {
				log.Println(err)
			}
			if token, err = jwt.NewToken(jclaims, secretKey); err != nil {
				log.Println(err)
			} else {
				fmt.Printf("we make a new token: %s\n", token)
				// save token
				http.SetCookie(w, &http.Cookie{
					Name:     tokenName,
					Value:    token,
					HttpOnly: true,
					Expires:  time.Now().Add(time.Minute * 3),
					Path:     "/",
					//Domain:   ".YourDomain",
				})
				fmt.Printf("and save him in cookie %s\n", tokenName)
			}
		}
		if valid, err := jwt.ValidateToken(token, secretKey); valid {
			fmt.Printf("token valid\n")
		} else {
			fmt.Printf("token invalid: %s\n", err.Error())
		}
	})
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalln(err)
	}
}
```