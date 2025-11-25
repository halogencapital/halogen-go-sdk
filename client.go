package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"
)

const (
	endpoint  string = "https://external-api.wallet.halogen.my"
	version   string = "0.0.1"
	userAgent string = "wallet/" + version + " lang/go"
)

type queryInput struct {
	Name    string      `json:"name"`
	Payload interface{} `json:"payload"`
}

func (c *Client) query(ctx context.Context, name string, input interface{}, output interface{}) error {
	// retriedCount increments on >= 500 errors
	retriedCount := 0
retry:
	body := queryInput{
		Name:    name,
		Payload: input,
	}
	var jsonBuffer bytes.Buffer
	if err := json.NewEncoder(&jsonBuffer).Encode(body); err != nil {
		return err
	}
	reqBody := bytes.TrimRight(jsonBuffer.Bytes(), "\n")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/query", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	jsonBuffer.Reset()
	req.Header.Set("User-Agent", userAgent)

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
	if resp.StatusCode >= 400 {
		sdkErr := Error{
			StatusCode: resp.StatusCode,
		}
		if err := json.NewDecoder(resp.Body).Decode(&sdkErr); err != nil {
			return sdkErr
		}
		// rate-limited
		if resp.StatusCode == http.StatusTooManyRequests {
			i, err := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64)
			if err != nil {
				return sdkErr
			}
			time.Sleep(time.Duration(i) * time.Second)
			goto retry
		}
		// retry server error
		if resp.StatusCode >= http.StatusInternalServerError {
			if retriedCount >= c.options.MaxReadRetry-1 {
				return sdkErr
			}
			retriedCount++
			time.Sleep(c.options.RetryInterval)
			goto retry
		}
		return sdkErr
	}
	return json.NewDecoder(resp.Body).Decode(&output)
}

type commandInput struct {
	Name    string      `json:"name"`
	Payload interface{} `json:"payload"`
}

func (c *Client) command(ctx context.Context, name string, input interface{}, output interface{}) error {
	// only retry rate limited errors.
retry:
	body := commandInput{
		Name:    name,
		Payload: input,
	}
	var jsonBuffer bytes.Buffer
	if err := json.NewEncoder(&jsonBuffer).Encode(body); err != nil {
		return err
	}
	reqBody := bytes.TrimRight(jsonBuffer.Bytes(), "\n")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/command", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	jsonBuffer.Reset()
	req.Header.Set("User-Agent", userAgent)

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
	token, err := newToken(keyID, "/command", reqBody, 1*time.Hour, o.CredentialsLoaderFunc != nil)
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
	if resp.StatusCode >= 400 {
		sdkErr := Error{
			StatusCode: resp.StatusCode,
		}
		if err := json.NewDecoder(resp.Body).Decode(&sdkErr); err != nil {
			return sdkErr
		}
		// rate-limited
		if resp.StatusCode == http.StatusTooManyRequests {
			i, err := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64)
			if err != nil {
				return sdkErr
			}
			time.Sleep(time.Duration(i) * time.Second)
			goto retry
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
