# Halogen Wallet

Package wallet is a Go client for calling the Halogen Wallet HTTP API.

### Installation

You may install the package using `go get`.

```bash
$ go get github.com/halogencapital/halogen-go-sdk/wallet
```

### Quick start

1. Login to https://wallet.halogen.my.

2. Navigate to **Settings > API Keys**.

3. Create a new API key by providing a Certificate Signing Request (CSR). Elliptic Curve P-256 (recommended) and RSA-4096 are supported.
    - Generate new EC P-256 CSR using OpenSSL.
        ```bash
        $ mkdir -p .key
        $ openssl ecparam -name prime256v1 -genkey -noout -out .key/ec_private_key.pem
        $ openssl req -new -key .key/ec_private_key.pem -out .key/ec_csr.pem -sha256 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com"
        ```
    - Or generate new RSA-4096 CSR using OpenSSL.
        ```bash
        $ mkdir -p .key
        $ openssl req -new -newkey rsa:4096 -nodes -keyout .key/rsa_private_key.pem -out .key/rsa_csr.pem -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com"
        ```
    - Keep the generated **Private Key** in a secure storage and never share it with any party. This package will use the **Private Key** to sign the requests before it is sent to Halogen Wallet server.
4. Save the returned Key ID and use it in the client as following:
    ```golang
    client := wallet.New()
    client.SetCredentials(os.Getenv("HALOGEN_WALLET_KEY_ID"), []byte(os.Getenv("HALOGEN_WALLET_PRIVATE_KEY_PEM")))
    output, err := client.ListClientAccounts(context.Background(), &wallet.ListClientAccountsInput{
        ClientID: "...",
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("got %d accounts", len(output.Accounts))
    ```

### Rolling out your own client

The endpoint of the REST API is `https://external-api.wallet.halogen.my`.

The server offers two kind of calls, **Query** and **Command**. Each can be called by path as following:
- /query
- /command

Example of a Query call:

```bash
curl -X "POST" "https://external-api.wallet.halogen.my/query" \
     -H 'Authorization: Bearer [JSON Web Token]' \
     -H 'Content-Type: application/json; charset=utf-8' \
     -d $'{
  "name": "list_client_accounts",
  "payload": {
    "clientId": "5b153c9a5d8b0467a9ba887a1ff4dfe209c3d6f4"
  }
}'
```

Example of a Command call:

```bash
curl -X "POST" "https://external-api.wallet.halogen.my/command" \
     -H 'Content-Type: application/json; charset=utf-8' \
     -H 'Authorization: Bearer [JSON Web Token]' \
     -d $'{
  "name": "invest",
  "payload": {
    "clientId":"5b153c9a5d8b0467a9ba887a1ff4dfe209c3d6f4",
    "accountId":"2308001002",
    "fundId":"1d3ede3d8023fb76a6b73ab2972bdc28b73cc549",
    "fundClassSequence":1,
    "amount":1000,
    "consentFundIM":true,
    "consentHighRisk":false
    }
}'
```


# Authentication

The server expects a JSON Web Token (JWT) in the Authorization header. The client constructs the token such that the JWT payload contains a SHA-256 hash of the request body, the request URI (e.g. "/query"), a nonce, issued and expiry times, and the key identifier (kid). The token is then signed using either an EC (ES256) or RSA (RS256) private key.

