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
	testKeyID    = "3394eb8831ff50634ad973cda5b93fc0b36bd885"
	testClientID = "5b153c9a5d8b0467a9ba887a1ff4dfe209c3d6f4"
)

func TestClientSimple(t *testing.T) {
	c := New()
	prv, _ := os.ReadFile(".key/ec_private_key.pem")
	c.SetCredentials(testKeyID, prv)
	output, err := c.ListClientAccounts(context.Background(), &ListClientAccountsInput{
		ClientID: testClientID,
	})
	if err != nil {
		panic(err)
	}
	b, _ := json.MarshalIndent(output, "", "\t")
	fmt.Println(string(b))

	output, err = c.ListClientAccounts(context.Background(), &ListClientAccountsInput{
		ClientID: testClientID,
	})
	if err != nil {
		panic(err)
	}
	b, _ = json.MarshalIndent(output, "", "\t")
	fmt.Println(string(b))
}

func TestClientWithCredentialsLoaderFunc(t *testing.T) {
	c := New(&Options{
		CredentialsLoaderFunc: func() (keyID string, privateKeyPEM []byte, err error) {
			b, _ := os.ReadFile(".key/rsa_private_key.pem")
			return testKeyID, b, nil
		},
		Debug: true,
	})
	output, err := c.ListClientAccounts(context.Background(), &ListClientAccountsInput{
		ClientID: testClientID,
	})
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
	c.SetCredentials(testKeyID, nil)
	output, err := c.ListClientAccounts(context.Background(), &ListClientAccountsInput{
		ClientID:   testClientID,
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
