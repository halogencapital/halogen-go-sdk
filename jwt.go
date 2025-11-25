package wallet

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const (
	es256 string = "ES256"
	rs256 string = "RS256"
)

type tokenHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type tokenPayload struct {
	BodyHash string `json:"bodyHash"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	Nonce    string `json:"nonce"`
	Sub      string `json:"sub"`
	Uri      string `json:"uri"`
	Kid      string `json:"kid"`
}

type token struct {
	Header         *tokenHeader
	Payload        *tokenPayload
	shouldCleanKey bool `json:"-"`
}

func newToken(keyID string, uri string, body []byte, ttl time.Duration, shouldCleanKey bool) (*token, error) {
	nonceBuffer := make([]byte, 20)
	if _, err := rand.Read(nonceBuffer); err != nil {
		return nil, fmt.Errorf("wallet: newToken: failed to read random bytes. err=%v", err)
	}

	iat := time.Now().UTC()
	bodyHash := sha256.Sum256(body)
	return &token{
		shouldCleanKey: shouldCleanKey,
		Header: &tokenHeader{
			// alg is set when parsing the private key upon signing
			Alg: "",
			Typ: "JWT",
		},
		Payload: &tokenPayload{
			Kid:      keyID,
			Sub:      "wallet",
			Iat:      iat.Unix(),
			Exp:      iat.Add(ttl).Unix(),
			Nonce:    fmt.Sprintf("%x", nonceBuffer),
			BodyHash: fmt.Sprintf("%x", bodyHash),
			Uri:      uri,
		},
	}, nil
}

func (t *token) signAndFormat(privateKeyPEM []byte) (string, error) {
	// clean up the private key from memory
	defer func() {
		if !t.shouldCleanKey {
			return
		}
		for i := range privateKeyPEM {
			privateKeyPEM[i] = 0

		}
	}()

	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	if privateKeyBlock == nil {
		return "", fmt.Errorf("wallet: signAndFormat: private key must be in PEM format.")
	}
	defer func() {
		for i := range privateKeyBlock.Bytes {
			privateKeyBlock.Bytes[i] = 0
		}
	}()

	var privateKeyAny any
	var err error
	// try EC
	privateKeyAny, err = x509.ParseECPrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		// try RSA
		privateKeyAny, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
		if err != nil {
			privateKeyAny, err = x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
			if err != nil {
				return "", fmt.Errorf("wallet: signAndFormat: unable to deduce private key type. Valid key would either be EC or RSA.")
			}
		}
	}

	var jsonBuffer bytes.Buffer
	if err := json.NewEncoder(&jsonBuffer).Encode(t.Payload); err != nil {
		return "", fmt.Errorf("wallet: signAndFormat: %v", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(jsonBuffer.Bytes())
	jsonBuffer.Reset()

	signingString := ""
	signatureB := []byte{}
	switch key := privateKeyAny.(type) {
	case *ecdsa.PrivateKey:
		t.Header.Alg = es256
		if err := json.NewEncoder(&jsonBuffer).Encode(t.Header); err != nil {
			return "", fmt.Errorf("wallet: signAndFormat: %v", err)
		}
		encodedHeader := base64.RawURLEncoding.EncodeToString(jsonBuffer.Bytes())
		signingString = encodedHeader + "." + encodedPayload
		hashed := sha256.Sum256([]byte(signingString))
		jsonBuffer.Reset()
		signatureB, err = ecdsa.SignASN1(rand.Reader, key, hashed[:])
		if err != nil {
			return "", fmt.Errorf("wallet: signAndFormat: failed to sign with EC key. err=%v", err)
		}
		key.D = big.NewInt(0)
		key.X = big.NewInt(0)
		key.Y = big.NewInt(0)
		key = nil
	case *rsa.PrivateKey:
		t.Header.Alg = rs256
		if err := json.NewEncoder(&jsonBuffer).Encode(t.Header); err != nil {
			return "", fmt.Errorf("wallet: signAndFormat: %v", err)
		}
		encodedHeader := base64.RawURLEncoding.EncodeToString(jsonBuffer.Bytes())
		jsonBuffer.Reset()
		signingString = encodedHeader + "." + encodedPayload
		hashed := sha256.Sum256([]byte(signingString))
		signatureB, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
		if err != nil {
			return "", fmt.Errorf("wallet: signAndFormat: failed to sign with RSA key. err=%v", err)
		}
		key.D = big.NewInt(0)
		key.N = big.NewInt(0)
		key = nil
	default:
		return "", fmt.Errorf("wallet: signAndFormat: unable to cast private key type. Valid key would either be *[rsa.PrivateKey] or *[ecdsa.PrivateKey].")
	}
	privateKeyAny = nil

	return signingString + "." + base64.RawURLEncoding.EncodeToString(signatureB), nil
}
