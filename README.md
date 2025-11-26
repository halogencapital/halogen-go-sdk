# Halogen Wallet

Package wallet is a Go client for calling the Halogen Wallet HTTP API.

### Installation

You may install the package using `go get`.

```bash
$ go get github.com/halogencapital/wallet-go
```

### Documentation:

Checkout https://pkg.go.dev/github.com/halogencapital/wallet-go

### Quick start

1. Login to https://wallet.halogen.my.

2. Navigate to **Settings > API Keys**.

3. Create a new API key by providing a Certificate Signing Request (CSR). Elliptic Curve P-256 (recommended) and RSA-4096 are supported.
    - Generate new EC P-256 CSR using OpenSSL.
        ```bash
        mkdir -p .key
        openssl ecparam -name prime256v1 -genkey -noout -out .key/ec_private_key.pem
        openssl req -new -key .key/ec_private_key.pem -out .key/ec_csr.pem -sha256 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com"
        ```
    - Or generate new RSA-4096 CSR using OpenSSL.
        ```bash
        mkdir -p .key
        openssl req -new -newkey rsa:4096 -nodes -keyout .key/rsa_private_key.pem -out .key/rsa_csr.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com"
        ```
    - Keep the generated **Private Key** in a secure storage and never share it with any party. This package will use the **Private Key** to sign the requests before it is sent to Halogen Wallet server.
4. Save the Key ID and use it in the client as following:
    ```golang
    client := wallet.New()
    client.SetCredentials(os.Getenv("HALOGEN_WALLET_KEY_ID"), []byte(os.Getenv("HALOGEN_WALLET_PRIVATE_KEY_PEM")))
    output, err := client.ListClientAccounts(context.Background(), &wallet.ListClientAccountsInput{})
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("got %d accounts", len(output.Accounts))
    ```

### Rolling out your own client

Checkout [OpenAPI 3.0 specifications](https://developer.halogen.my/openapi.yml).

### Wallet Server availability

Halogen Wallet status page at https://halogen-wallet.openstatus.dev/

