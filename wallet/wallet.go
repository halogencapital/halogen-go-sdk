package wallet

import (
	"context"
	"log"
	"net/http"
	"time"
)

const (
	AccountTypeSingle string = "single"
	AccountTypeJoint  string = "joint"

	AccountExperienceFundManagement string = "fundmanagement"
	AccountExperienceMandate        string = "mandate"
	AccountExperienceDim            string = "dim"
)

type Client struct {
	options     *Options
	credentials *credentials
}

type Options struct {
	// CredentialsLoaderFunc is responsible for retreiving credentials to enable the client
	// sending authenticated requests. This is recommended over [wallet.Client.SetCredentials] which
	// lets credentials live in memory along with Client instance.
	//
	// Optional, if set, credentials will be retrieved for every request, and
	// at best-effort cleared from the memory post call.
	CredentialsLoaderFunc func() (keyID string, privateKeyPEM []byte, err error)

	// HTTPClient specifies an HTTP client used to call the server
	//
	// Optional.
	HTTPClient *http.Client

	// MaxReadRetry reports how many times to retry a query request when fails.
	//
	// Optional, defaulted to 5 times.
	MaxReadRetry int

	// RetryInterval reports how long to wait before retrying a query request when fails.
	//
	// Optional, defaulted to 50 milliseconds.
	RetryInterval time.Duration

	// Debug reports whether the client is running in debug mode which enables logging.
	//
	// Optional, defaulted to false.
	Debug bool
}

func New(opts ...*Options) *Client {
	defaultOptions := Options{
		HTTPClient:    &http.Client{Timeout: 10 * time.Second},
		MaxReadRetry:  5,
		RetryInterval: 50 * time.Millisecond,
	}
	if len(opts) == 0 {
		return &Client{
			options: &defaultOptions,
		}
	}
	o := opts[0]
	// HTTP options
	if o.HTTPClient == nil {
		o.HTTPClient = defaultOptions.HTTPClient
	}
	// force timeout in HTTP client
	if o.HTTPClient.Timeout <= 0 {
		o.HTTPClient.Timeout = 10 * time.Second
	}

	// retry options
	if o.MaxReadRetry <= 0 {
		o.MaxReadRetry = defaultOptions.MaxReadRetry
	}
	if o.RetryInterval <= 0 {
		o.RetryInterval = defaultOptions.RetryInterval
	}

	return &Client{
		options: o,
	}
}

type credentials struct {
	keyID         string
	privateKeyPEM []byte
}

// SetCredentials sets credentials to the client instance. If [wallet.Options.CredentialsLoaderFunc] is set
// upon client's initialization then this is ignored.
func (c *Client) SetCredentials(keyID string, privateKeyPEM []byte) {
	if c.options.CredentialsLoaderFunc != nil {
		if c.options.Debug {
			log.Println("INFO: ignoring SetCredentials call as CredentialsLoaderFunc was set to the client.")
		}
		return
	}
	c.credentials = &credentials{
		keyID:         keyID,
		privateKeyPEM: privateKeyPEM,
	}
}

// ClientAccount is ...
type ClientAccount struct {
	// ID specifies the identifier of the account.
	ID string `json:"id,omitempty"`

	// Type specifies the type of the account.
	//
	// Value can be one of "single" or "joint".
	Type string `json:"type,omitempty"`

	// Name specifies the name of the account.
	Name string `json:"name,omitempty"`

	// Experience specifies the investing experience this account has.
	//
	// Value can be one of "fundmanagement", "mandate" or "dim".
	Experience string `json:"experience,omitempty"`

	// ExperienceLabel specifies a friendly name of the experience to
	// be shown on the UI.
	ExperienceLabel string `json:"experienceLabel,omitempty"`

	// Asset specifies the quote asset of the portfolio value and other related
	// fields such PnlAmount, NetInflow.
	Asset string `json:"asset,omitempty"`

	// PortfolioValue specifies the value of this account in Asset terms
	PortfolioValue float64 `json:"portfolioValue"`

	// ExposurePercentage specifies the exposure of this account relatively to the total
	// value of other accounts
	ExposurePercentage float64 `json:"exposurePercentage"`

	// PnlAmount specifies the profit or loss amount in Asset terms.
	//
	// The value will be negative when it is a loss.
	PnlAmount float64 `json:"pnlAmount"`

	// PnlAmount specifies the percentage of profit or loss relative
	// to the invested amount.
	//
	// The value will be negative when it is a loss.
	PnlPercentage float64 `json:"pnlPercentage"`

	// NetInflow specifies the net total traded in this account
	NetInflow float64 `json:"netInflow"`

	// TotalInflow specifies the total amount that has been injected
	// into this account.
	TotalInflow float64 `json:"totalInflow"`

	// TotalOutflow specifies the total amount that has been redeemed
	// from this account.
	TotalOutflow float64 `json:"totalOutflow"`

	// PendingSwitchInAmount specifies the total switching amount that is pending
	// confirmation.
	PendingSwitchInAmount float64 `json:"pendingSwitchInAmount"`

	RiskLabel       string `json:"riskLabel"`
	RiskDescription string `json:"riskDescription"`

	// CanInvest reports whether the requester can create investment request
	//
	// It is only available for "fundmanagement" experience
	CanInvest bool `json:"canInvest"`

	// CanRedeem reports whether the requester can create redemption request
	//
	// It is only available for "fundmanagement" experience
	CanRedeem bool `json:"canRedeem"`

	// CanSwitch reports whether the requester can create switch request
	//
	// It is only available for "fundmanagement" experience
	CanSwitch bool `json:"canSwitch"`

	// CanDeposit reports whether the requester can create deposit request
	//
	// It is only available for "dim" experience
	CanDeposit bool `json:"canDeposit"`

	// CanWithdraw reports whether the requester can create withdrawal request
	//
	// It is only available for "dim" experience
	CanWithdraw bool `json:"canWithdraw"`

	// CanUpdateAccountName reports whether the requester can update the account name
	CanUpdateAccountName bool `json:"canUpdateAccountName"`
}

type ListClientAccountsInput struct {
	AccountIDs []string `json:"accountIds,omitempty"`
}

type ListClientAccountsOutput struct {
	Amount           float64         `json:"amount"`
	Asset            string          `json:"asset,omitempty"`
	CanCreateAccount bool            `json:"canCreateAccount"`
	Accounts         []ClientAccount `json:"accounts"`
}

// ListClientAccounts lists all the accounts associated with the provided client ID
func (c *Client) ListClientAccounts(ctx context.Context, input *ListClientAccountsInput) (*ListClientAccountsOutput, error) {
	output := ListClientAccountsOutput{}
	err := c.query(ctx, "list_client_accounts", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
}
