package wallet

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// mockTransport allows us to intercept the request because the URL
// is hardcoded in the client package.
type mockTransport struct {
	RoundTripFunc func(req *http.Request) *http.Response
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.RoundTripFunc(req), nil
}

func TestNewClient_Defaults(t *testing.T) {
	c := New()
	if c.options.MaxReadRetry != 5 {
		t.Errorf("expected default MaxReadRetry 5, got %d", c.options.MaxReadRetry)
	}
	if c.options.HTTPClient.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", c.options.HTTPClient.Timeout)
	}
}

func TestSigning_RSA(t *testing.T) {
	keyPEM, err := os.ReadFile(".key/rsa_private_key.pem")
	if err != nil {
		t.Fatalf("failed to retrive RSA key: %v", err)
	}

	token, err := newToken("test-key-id", "/test", []byte("payload"), time.Hour, false)
	if err != nil {
		t.Fatalf("newToken failed: %v", err)
	}

	sig, err := token.signAndFormat(keyPEM)
	if err != nil {
		t.Fatalf("signAndFormat failed with RSA: %v", err)
	}

	parts := strings.Split(sig, ".")
	if len(parts) != 3 {
		t.Errorf("expected JWT to have 3 parts, got %d", len(parts))
	}
}

func TestSigning_ECDSA(t *testing.T) {
	keyPEM, err := os.ReadFile(".key/ec_private_key.pem")
	if err != nil {
		t.Fatalf("failed to gen EC key: %v", err)
	}

	token, err := newToken("test-key-id", "/test", []byte("payload"), time.Hour, false)
	if err != nil {
		t.Fatalf("newToken failed: %v", err)
	}

	sig, err := token.signAndFormat(keyPEM)
	if err != nil {
		t.Fatalf("signAndFormat failed with ECDSA: %v", err)
	}

	parts := strings.Split(sig, ".")
	if len(parts) != 3 {
		t.Errorf("expected JWT to have 3 parts, got %d", len(parts))
	}
}

func TestQuery_Success(t *testing.T) {
	keyPEM, _ := os.ReadFile(".key/rsa_private_key.pem")

	// Mock successful response
	mock := &mockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			if req.URL.Path != "/query" {
				return &http.Response{StatusCode: 404, Body: io.NopCloser(bytes.NewBufferString(""))}
			}
			// Verify Auth Header exists
			if req.Header.Get("Authorization") == "" {
				return &http.Response{StatusCode: 401, Body: io.NopCloser(bytes.NewBufferString(""))}
			}

			respBody := `{"result": "success"}`
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(respBody)),
				Header:     make(http.Header),
			}
		},
	}

	client := New(&Options{
		HTTPClient: &http.Client{Transport: mock},
	})
	client.SetCredentials("key-1", keyPEM)

	var output map[string]string
	err := client.query(context.Background(), "test-query", "input", &output)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if output["result"] != "success" {
		t.Errorf("expected result 'success', got %v", output["result"])
	}
}

func TestQuery_RetryOn500(t *testing.T) {
	keyPEM, _ := os.ReadFile(".key/rsa_private_key.pem")
	attempts := 0

	// Mock: Fail twice with 500, then succeed
	mock := &mockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			attempts++
			if attempts < 3 {
				return &http.Response{
					StatusCode: 500,
					Body:       io.NopCloser(bytes.NewBufferString(`{"code": "internal_error"}`)),
				}
			}
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(`{"result": "success"}`)),
			}
		},
	}

	client := New(&Options{
		HTTPClient:    &http.Client{Transport: mock},
		MaxReadRetry:  5,
		RetryInterval: 1 * time.Millisecond, // Fast retry for test
	})
	client.SetCredentials("key-1", keyPEM)

	var output map[string]string
	err := client.query(context.Background(), "test-query", "input", &output)
	if err != nil {
		t.Fatalf("expected success after retry, got error: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts (2 fails + 1 success), got %d", attempts)
	}
}

func TestCommand_NoRetryOn500(t *testing.T) {
	keyPEM, _ := os.ReadFile(".key/rsa_private_key.pem")
	attempts := 0

	// Mock: Fail with 500. Should NOT retry for Commands.
	mock := &mockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			attempts++
			return &http.Response{
				StatusCode: 500,
				Body:       io.NopCloser(bytes.NewBufferString(`{"code": "internal_error"}`)),
			}
		},
	}

	client := New(&Options{
		HTTPClient:    &http.Client{Transport: mock},
		MaxReadRetry:  5, // Even if set, command shouldn't use it for 500s
		RetryInterval: 1 * time.Millisecond,
	})
	client.SetCredentials("key-1", keyPEM)

	var output map[string]string
	err := client.command(context.Background(), "test-cmd", "input", &output)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if attempts != 1 {
		t.Errorf("expected exactly 1 attempt for command 500 error, got %d", attempts)
	}
}

func TestRateLimit_429(t *testing.T) {
	keyPEM, _ := os.ReadFile(".key/rsa_private_key.pem")
	attempts := 0

	mock := &mockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			attempts++
			if attempts == 1 {
				header := make(http.Header)
				// Retry after 1 second (we will mock/sleep small in test)
				header.Set("Retry-After", "1")
				return &http.Response{
					StatusCode: 429,
					Header:     header,
					Body:       io.NopCloser(bytes.NewBufferString(`{"code": "too_many_requests"}`)),
				}
			}
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(`{"result": "success"}`)),
			}
		},
	}

	// We can't easily mock time.Sleep without refactoring the package,
	// so this test will actually sleep for 1 second.
	client := New(&Options{
		HTTPClient: &http.Client{Transport: mock},
	})
	client.SetCredentials("key-1", keyPEM)

	start := time.Now()
	var output map[string]string
	err := client.query(context.Background(), "test-query", "input", &output)

	if err != nil {
		t.Fatalf("expected success after rate limit, got error: %v", err)
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
	if time.Since(start) < 1*time.Second {
		t.Log("Warning: Test finished faster than the Retry-After header indicated. Did logic sleep?")
	}
}

func TestCredentialsLoader_Priority(t *testing.T) {
	rsaKey, _ := os.ReadFile(".key/rsa_private_key.pem")
	ecKey, _ := os.ReadFile(".key/ec_private_key.pem")

	loaderCalled := false

	// Define a loader that returns the EC key
	loader := func() (string, []byte, error) {
		loaderCalled = true
		return "ec-key-id", ecKey, nil
	}

	mock := &mockTransport{
		RoundTripFunc: func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
			}
		},
	}

	client := New(&Options{
		HTTPClient:            &http.Client{Transport: mock},
		CredentialsLoaderFunc: loader,
	})

	// Set credentials manually (should be ignored due to loader)
	client.SetCredentials("rsa-key-id", rsaKey)

	// Perform a request
	client.query(context.Background(), "test", nil, &map[string]any{})

	if !loaderCalled {
		t.Error("expected CredentialsLoaderFunc to be called")
	}
}

func TestCredentials_Missing(t *testing.T) {
	client := New()
	// No credentials set

	err := client.query(context.Background(), "test", nil, nil)
	if err == nil {
		t.Fatal("expected error due to missing credentials, got nil")
	}
	if !strings.Contains(err.Error(), "credentials are not set") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestInvalidPrivateKey(t *testing.T) {
	client := New()
	// Set garbage key
	client.SetCredentials("bad-key", []byte("-----BEGIN RSA PRIVATE KEY-----\nNOTABASE64\n-----END RSA PRIVATE KEY-----"))

	err := client.query(context.Background(), "test", nil, nil)
	if err == nil {
		t.Fatal("expected error due to invalid private key, got nil")
	}
}
