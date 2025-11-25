package wallet

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

const (
	testKeyID = "f42018241cb0ce8ac4f82d7049fa63db2caaad9a"
)

func TestClientSimple(t *testing.T) {
	c := New(&Options{Debug: true})
	prv, _ := os.ReadFile(".key/ec_private_key.pem")
	c.SetCredentials(testKeyID, prv)
	output, err := c.ListClientAccounts(context.Background(), &ListClientAccountsInput{})
	if err != nil {
		panic(err)
	}
	b, _ := json.MarshalIndent(output, "", "\t")
	fmt.Println(string(b))

	// output, err = c.ListClientAccounts(context.Background(), &ListClientAccountsInput{
	// 	ClientID: testClientID,
	// })
	// if err != nil {
	// 	panic(err)
	// }
	// b, _ = json.MarshalIndent(output, "", "\t")
	// fmt.Println(string(b))
}

func TestClientWithCredentialsLoaderFunc(t *testing.T) {
	c := New(&Options{
		CredentialsLoaderFunc: func() (keyID string, privateKeyPEM []byte, err error) {
			b, _ := os.ReadFile(".key/rsa_private_key.pem")
			return testKeyID, b, nil
		},
		Debug: true,
	})
	output, err := c.ListClientAccounts(context.Background(), &ListClientAccountsInput{})
	if err != nil {
		panic(err)
	}
	b, _ := json.MarshalIndent(output, "", "\t")
	fmt.Println(string(b))

	// output, err = c.ListClientAccounts(context.Background(), &ListClientAccountsInput{
	// 	ClientID: testClientID,
	// })
	// if err != nil {
	// 	panic(err)
	// }
	// b, _ = json.MarshalIndent(output, "", "\t")
	// fmt.Println(string(b))
}

func TestClientWithErrorCasting(t *testing.T) {
	c := New()
	prv, _ := os.ReadFile(".key/ec_private_key.pem")
	c.SetCredentials(testKeyID, prv)
	output, err := c.ListClientAccounts(context.Background(), &ListClientAccountsInput{
		AccountIDs: []string{"invalid_account_id"},
	})
	if err != nil {
		if werr, ok := err.(Error); ok {
			fmt.Println(werr.Code, werr.Message)
			return
		}
		panic(err)
	}
	b, _ := json.MarshalIndent(output, "", "\t")
	fmt.Println(string(b))
}

func TestSignRequest(t *testing.T) {
	c := New()
	c.SetCredentials(testKeyID, nil)
	token, err := newToken(testKeyID, "/query", []byte("XXX"), 10*time.Second, false)
	if err != nil {
		panic(err)
	}
	b, _ := os.ReadFile(".key/private.pem")
	j, err := token.signAndFormat(b)
	if err != nil {
		panic(err)
	}
	fmt.Println(j)
}

func TestSignRequestV2(t *testing.T) {
	token, err := newToken(testKeyID, "/query", []byte("XXX"), 10*time.Second, false)
	if err != nil {
		panic(err)
	}
	b, _ := os.ReadFile(".key/private.pem")
	jwtToken, err := token.signAndFormat(b)
	if err != nil {
		panic(err)
	}
	fmt.Println(jwtToken)
}

func TestSignRequestEC(t *testing.T) {
	token, err := newToken(testKeyID, "/query", []byte("XXX"), 10*time.Second, false)
	if err != nil {
		panic(err)
	}
	b, err := os.ReadFile(".key/ecc_private_key.pem")
	if err != nil {
		panic(err)
	}
	jwtToken, err := token.signAndFormat(b)
	if err != nil {
		panic(err)
	}
	fmt.Println(jwtToken)
}
