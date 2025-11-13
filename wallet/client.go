package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"time"
)

// TODO: update this URL to sdk server endpoint
const endpoint string = "https://external-api.wallet.halogen.my"

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s", e.Message)
}

type queryInput struct {
	Name        string      `json:"name"`
	Payload     interface{} `json:"payload"`
	PayloadJSON string      `json:"payloadJSON"`
}

func (c *Client) query(ctx context.Context, name string, input interface{}, output interface{}) error {
	var jsonBuffer bytes.Buffer
	if err := json.NewEncoder(&jsonBuffer).Encode(input); err != nil {
		return err
	}
	body := queryInput{
		Name:    name,
		Payload: input,
		// PayloadJSON: strings.TrimRight(jsonBuffer.String(), "\n"),
	}
	jsonBuffer.Reset()

	if err := json.NewEncoder(&jsonBuffer).Encode(body); err != nil {
		return err
	}
	reqBody := bytes.TrimRight(jsonBuffer.Bytes(), "\n")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/query", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	jsonBuffer.Reset()

	o := c.options
	keyID := ""
	privateKeyPEM := []byte{}
	if o.CredentialsLoaderFunc == nil {
		keyID, privateKeyPEM, err = c.defaultCredentialsLoaderFunc()
		if err != nil {
			return err
		}
	} else {
		keyID, privateKeyPEM, err = o.CredentialsLoaderFunc()
		if err != nil {
			return err
		}
	}
	// clean up the memory when CredentialsLoaderFunc is set.
	token, err := newToken(keyID, "/query", reqBody, 1*time.Hour, o.CredentialsLoaderFunc != nil)
	if err != nil {
		return err
	}
	signature, err := token.signAndFormat(privateKeyPEM)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+signature)
	if o.Debug {
		reqB, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			return err
		}
		log.Printf("INFO: sending request\n%s\n", string(reqB))
	}
	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	if o.Debug {
		r, err := httputil.DumpResponse(resp, true)
		if err != nil {
			return err
		}
		log.Printf("INFO: received response\n%s\n", r)
	}
	keyID = ""
	req = nil
	if resp.StatusCode >= 500 {
		return Error{
			Code:    resp.StatusCode,
			Message: resp.Status,
		}
	}
	if resp.StatusCode >= 400 {
		sdkErr := Error{}
		if err := json.NewDecoder(resp.Body).Decode(&sdkErr); err != nil {
			return Error{
				Code:    resp.StatusCode,
				Message: resp.Status,
			}
		}
		return sdkErr
	}
	return json.NewDecoder(resp.Body).Decode(&output)
}

func (c *Client) defaultCredentialsLoaderFunc() (keyID string, privateKeyPEM []byte, err error) {
	if c.credentials == nil {
		return "", nil, fmt.Errorf("credentials are not set. You may either use SetCredentials or provide CredentialsLoaderFunc upon client initialization.")
	}
	return c.credentials.keyID, c.credentials.privateKeyPEM, nil
}
