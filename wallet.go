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

// ClientAccount represents Halogen investment account. One client may have many accounts.
//
// Halogen offers two Types of accounts, "single" and "joint".
//
//   - Single: Owned by one client, who is the the primary.
//   - Joint: Owned by two clients, the first is the "primary", and the second is the "secondary". Secondary client may or may not have
//     control over the account, however, funds can only be withdrawn to a bank account in the primary name.
//
// Halogen offers three Experiences "fundmanagement", "mandate" and "dim".
//
//   - Fund Management experience is meant for sophesticated investors who are eligible to invest in Public Wholesale Funds.
//   - Mandate experience is meant for clients who have private mandates with Halogen.
//   - DIM experience is meant for retail-investors who have diversifed automated portfolios with Halogen.
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
	// AccountIDs filters the list of returned accounts.
	//
	// Optional, if not set, all accounts associated with the client are returned.
	AccountIDs []string `json:"accountIds,omitempty"`
}

type ListClientAccountsOutput struct {
	// Amount is the total value of all returned accounts.
	Amount float64 `json:"amount"`
	// Asset specifies the Amount's asset.
	//
	// In case the display currency is updated then the amount will be
	// converted to the display currency and this will hold the display currency value.
	Asset string `json:"asset,omitempty"`
	// CanCreateAccount reports whether the requester can create a new account under the client.
	CanCreateAccount bool `json:"canCreateAccount"`
	// Accounts is the list of accounts the client has access to. Filter may apply
	// using AccountIDs in the input.
	Accounts []ClientAccount `json:"accounts"`
}

// ListClientAccounts lists all the accounts associated with the client.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_client_accounts",
//	  "payload": {
//	    "accountIds": ["<accountId>"]
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInternal]
func (c *Client) ListClientAccounts(ctx context.Context, input *ListClientAccountsInput) (output *ListClientAccountsOutput, err error) {
	err = c.query(ctx, "list_client_accounts", input, &output)
	return output, err
}

type Address struct {
	// Type specifies whether the address is "permanent" or "correspondence".
	Type string `json:"type,omitempty"`
	// Line1 is the first line of the address in text format.
	Line1 string `json:"line1,omitempty"`
	// Line2 is the second line of the address in text format.
	//
	// Optional.
	Line2 *string `json:"line2,omitempty"`
	// City is the city of the address.
	City string `json:"city,omitempty"`
	// Postcode is the postcode of the address.
	Postcode string `json:"postcode,omitempty"`
	// Status is the status of the address.
	//
	// Optional.
	State *string `json:"state,omitempty"`
	// Country is the country of the address.
	Country string `json:"country,omitempty"`
}

type GetClientProfileInput struct {
}

type GetClientProfileOutput struct {
	// Name is the full name of the client as per official documents.
	//
	// Expect '/' to be part of the name.
	Name string `json:"name,omitempty"`

	// Nationality is the nationality of the client.
	Nationality *string `json:"nationality,omitempty"`

	// NricNo is the Malaysian NRIC number of the client.
	//
	// Only exists for Malaysian clients.
	NricNo *string `json:"nricNo,omitempty"`

	// PassportNp is the Passport number of the client.
	//
	// Only exists for Non-Malaysian clients.
	PassportNo *string `json:"passportNo,omitempty"`

	// Msisdn is the phone number of the client.
	Msisdn *string `json:"msisdn,omitempty"`

	// Email is the email of the client. Value is NULL for corporates.
	//
	// AuthorisedPersonEmail is used for corporates.
	Email *string `json:"email,omitempty"`

	// PermanentAddress is the permanent address of the client.
	PermanentAddress *Address `json:"permanentAddress,omitempty"`

	// CorrespondenceAddress is the correspondence address of the client.
	CorrespondenceAddress *Address `json:"correspondenceAddress,omitempty"`

	// Type specifies the client's type "individual" or "corporate".
	Type string `json:"type,omitempty"`

	// InvestorCategory specifies the investor category that can be one of "accreditedInvestor", "highNetworthInvestor",
	// "sophisticatedInvestor250k", "retailInvestor".
	//
	// 	- Accredited investor:
	// 		- Licensed CMSRL or Registered persons, including CEOs/Directors of CMSLs.
	// 		- Allowed to invest in Public Wholesale Fund, Private Mandate, DIM.
	//	- High net-worth investor:
	// 		- Annual Income of > RM300,000 (Individual)
	// 		- or > RM400,000 (Households)
	// 		- or > RM1,000,000 (investment portfolio)
	// 		- or > RM3,000,000 (net personal assets)
	// 		- Allowed to invest in Public Wholesale Fund, Private Mandate, DIM.
	//	- Sophisticated investor - RM 250k:
	// 		- Any investor who can invest RM250k or more for each transaction.
	// 		- Allowed to invest in Public Wholesale Fund, Private Mandate, DIM.
	//	- Retail investor:
	// 		- None of the above.
	// 		- Allowed to invest in Private Mandate, DIM.
	//
	InvestorCategory string `json:"investorCategory,omitempty"`

	// CountryOfIncoporation specifies the origin country of a corporate.
	//
	// This field is NULL for an individual client.
	CountryOfIncoporation *string `json:"countryOfIncorporation,omitempty"`

	// AuthorisedPersonName specifies the authorised person's name of a corporate.
	//
	// This field is NULL for an individual client.
	AuthorisedPersonName *string `json:"authorisedPersonName,omitempty"`

	// AuthorisedPersonEmail specifies the authorised person's email of a corporate.
	//
	// This field is NULL for an individual client.
	AuthorisedPersonEmail *string `json:"authorisedPersonEmail,omitempty"`

	// AuthorisedPersonMsisdn specifies the authorised person's phone number of a corporate.
	//
	// This field is NULL for an individual client.
	AuthorisedPersonMsisdn *string `json:"authorisedPersonMsisdn,omitempty"`

	// AuthorisedPersonOfficeNo specifies the authorised person's office phone number of a corporate.
	//
	// This field is NULL for an individual client.
	AuthorisedPersonOfficeNo *string `json:"authorisedPersonOfficeNo,omitempty"`

	// CompanyRegistrationNo specifies the registration number of a corporate.
	//
	// This field is NULL for an individual client.
	CompanyRegistrationNo *string `json:"companyRegistrationNo,omitempty"`

	// OldCompanyRegistrationNo specifies the old format of the registration number of a corporate.
	//
	// This field is NULL for an individual client.
	OldCompanyRegistrationNo *string `json:"oldCompanyRegistrationNo,omitempty"`

	// Ethnicity specifies the ethnicity of the client. Value is one of "bumiputera", "chinese",
	// "indian" or "other".
	//
	// Field is filled post registration.
	Ethnicity *string `json:"ethnicity,omitempty"`

	// DomesticRinggitBorrowing specifies the domestic ringgit borrowing status of the client. Value
	// is one of "residentWithoutDrbOrNonResidentOfMalaysia", "residentWithDRBButNotExceeded1M" or "residentWithDRBExceeded1M".
	//
	// Field is filled post registration.
	DomesticRinggitBorrowing *string `json:"domesticRinggitBorrowing,omitempty"`

	// TaxResidency specifies the tax residency of the client. Value is one of "onlyMalaysia", "multiple"
	// or "nonMalaysia".
	//
	// Field is filled post registration.
	TaxResidency *string `json:"taxResidency,omitempty"`

	// CountryTax specifies the country which the client pays tax to. Value is free-text country name.
	//
	// Field is filled post registration.
	CountryTax *string `json:"countryTax,omitempty"`

	// TaxIdentificationNo specifies the tax account number of the client. Value is free-text.
	//
	// Field is filled post registration.
	TaxIdentificationNo *string `json:"taxIdentificationNo,omitempty"`

	// IncompleteProfile reports whether the client's profile incomplete.
	//
	// False when all fields filled.
	IncompleteProfile bool `json:"incompleteProfile"`

	// IsAccountOwner reports whether the requester is the account owner. False when the requester
	// is acting on behalf the account's owner.
	IsAccountOwner bool `json:"isAccountOwner"`

	// CanInvestInUnitTrust reports whether the requester can invest in unit trust funds.
	CanInvestInUnitTrust bool `json:"canInvestInUnitTrust"`

	// CanInvestInDim reports whether the requester can invest in dim.
	CanInvestInDim bool `json:"canInvestInDim"`

	// CanUpdateProfile reports whether the requester can update and complete the profile.
	CanUpdateProfile bool `json:"canUpdateProfile"`

	// CanSubscribePushNotification reports whether the requester can subscribe to push notifications.
	CanSubscribePushNotification bool `json:"canSubscribePushNotification"`

	// Status specifies the status of the client's profile. Value is one of "pending", "rejected",
	// "active" or "withdrawn".
	Status string `json:"status,omitempty"`
}

// GetClientProfile retrieves the profile details of a client.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "get_client_profile",
//	  "payload": {}
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInternal]
func (c *Client) GetClientProfile(ctx context.Context, input *GetClientProfileInput) (output *GetClientProfileOutput, err error) {
	err = c.query(ctx, "get_client_profile", input, &output)
	return output, err
}

type Fund struct {
	// ID specifies the hexadecimal representation of the Fund identifier. 20 bytes
	// in length (40 hexadecimal characters).
	ID string `json:"id,omitempty"`

	// Type specifies the Fund type. Value is one of "income", "growth".
	Type string `json:"type,omitempty"`

	// Name specifies the legal name of the Fund.
	Name string `json:"name,omitempty"`

	// ShortName specifies the short name of the fund for better user experience.
	ShortName string `json:"shortName,omitempty"`

	// BaseCurrency specifies the fund's denmoinated currency.
	BaseCurrency string `json:"baseCurrency,omitempty"`

	// Category specifies the fund's category.
	Category string `json:"category,omitempty"`

	// Code specifies the fund's code. (e.g HSBTCF, HSETHF, HSCTF, HSRIF)
	Code string `json:"code,omitempty"`

	// InvestmentObjective specifies the objective of the fund as per the
	// information memorandum.
	InvestmentObjective string `json:"investmentObjective,omitempty"`
	// InvestorType specifies the type of the investor who can invest in this fund.
	InvestorType string `json:"investorType,omitempty"`

	// RiskRating specifies the amount of risk this fund has in text format. Value is one of
	// "low", "moderate", "high".
	RiskRating string `json:"riskRating,omitempty"`
	// RiskScore specifies the amount of risk this fund has in numeric format. Value is range
	// from 5 (low) to 16 (high).
	RiskScore int `json:"riskScore,omitempty"`

	// PrimaryFundManager specifies the name of the primary fund manager who
	// is managing the fund.
	PrimaryFundManager string `json:"primaryFundManager,omitempty"`
	// SecondaryFundManager specifies the name of the secondary fund manager who
	// is managing the fund.
	SecondaryFundManager string `json:"secondaryFundManager,omitempty"`

	// ShariahCompliant reports whether the fund is shariah compliant. True when it is shariah compliant.
	ShariahCompliant bool `json:"shariahCompliant,omitempty"`

	// Status specifies the status of the fund. Value is one of "pending", "active" or "archived".
	Status string `json:"status,omitempty"`

	// TagLine specifies the marketing line where it outlines the feature of the fund.
	TagLine string `json:"tagLine,omitempty"`

	// Trustee specifies the name of the trustee of the fund.
	Trustee string `json:"trustee,omitempty"`

	// ImageUrl specifies the Web URL that leads to the logo of the fund. For instance,
	// "https://media.halogen.my/fund/hsbtcf/logo.svg".
	ImageUrl string `json:"imageUrl,omitempty"`

	// CreatedAt specifies the date-time of which the fund was created on.
	CreatedAt string `json:"createdAt,omitempty"`

	// Classes specifies the fund's classes.
	Classes []FundClass `json:"classes,omitempty"`

	// IsOutOfService reports whether the fund is out of service. True when the fund is out of service.
	IsOutOfService bool `json:"isOutOfService"`
	// OutOfServiceMessage specifies the reason of which the fund is out of service.
	OutOfServiceMessage string `json:"outOfServiceMessage,omitempty"`

	// Metadata includes extra attributes related to the requester. For instance,
	// the minimum investment amount the requester must specify upon creating an investment request.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type FundClass struct {
	Sequence                    int                    `json:"sequence,omitempty"`
	Label                       string                 `json:"label,omitempty"`
	BaseCurrency                string                 `json:"baseCurrency,omitempty"`
	ManagementFee               float64                `json:"managementFee,omitempty"`
	TrusteeFee                  float64                `json:"trusteeFee,omitempty"`
	CustodianFee                float64                `json:"custodianFee,omitempty"`
	TransferFee                 float64                `json:"transferFee,omitempty"`
	TrusteeFeeAnnualMinimum     float64                `json:"trusteeFeeAnnualMinimum,omitempty"`
	SwitchingFee                float64                `json:"switchingFee,omitempty"`
	SubscriptionFee             float64                `json:"subscriptionFee,omitempty"`
	RedemptionFee               float64                `json:"redemptionFee,omitempty"`
	PerformanceFee              float64                `json:"performanceFee,omitempty"`
	TaxRate                     float64                `json:"taxRate,omitempty"`
	MinimumInitialInvestment    float64                `json:"minimumInitialInvestment,omitempty"`
	MinimumAdditionalInvestment float64                `json:"minimumAdditionalInvestment,omitempty"`
	MinimumUnitsHeld            float64                `json:"minimumUnitsHeld,omitempty"`
	MinimumRedemptionAmount     float64                `json:"minimumRedemptionAmount,omitempty"`
	CanDistribute               bool                   `json:"canDistribute,omitempty"`
	LaunchPrice                 float64                `json:"launchPrice,omitempty"`
	HexColor                    string                 `json:"hexColor,omitempty"`
	CommencementAt              string                 `json:"commencementAt,omitempty"`
	InitialOfferingPeriodFrom   string                 `json:"initialOfferingPeriodFrom,omitempty"`
	InitialOfferingPeriodTo     string                 `json:"initialOfferingPeriodTo,omitempty"`
	CreatedAt                   string                 `json:"createdAt,omitempty"`
	DistributionFrequency       string                 `json:"distributionFrequency,omitempty"`
	TagLine                     string                 `json:"tagLine,omitempty"`
	Metadata                    map[string]interface{} `json:"metadata,omitempty"`
}

type GetFundInput struct {
	FundID string `json:"fundId,omitempty"`
}

type GetFundOutput struct {
	Fund *Fund `json:"fund,omitempty"`
}

// GetFund retrieves the details of a specific fund.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "get_fund",
//	  "payload": {
//	    "fundId": "<fundId>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrMissingResource]
//   - [ErrInternal]
func (c *Client) GetFund(ctx context.Context, input *GetFundInput) (output *GetFundOutput, err error) {
	err = c.query(ctx, "get_fund", input, &output)
	return output, err
}

type GetRequestByDuitNowEndToEndIDInput struct {
	AccountID  string `json:"accountId,omitempty"`
	EndToEndID string `json:"endToEndId,omitempty"`
}

type GetRequestByDuitNowEndToEndIDOutput struct {
	RequestID string `json:"requestId,omitempty"`
}

// GetRequestByDuitNowEndToEndID retrieves a request ID using the DuitNow end-to-end ID.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "get_request_by_duitnow_endToEndId",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "endToEndId": "<endToEndId>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrMissingResource]
//   - [ErrInternal]
func (c *Client) GetRequestByDuitNowEndToEndID(ctx context.Context, input *GetRequestByDuitNowEndToEndIDInput) (output *GetRequestByDuitNowEndToEndIDOutput, err error) {
	err = c.query(ctx, "get_request_by_duitnow_endToEndId", input, &output)
	return output, err
}

type AllocationPerformance struct {
	Date                 string  `json:"date,omitempty"`
	Units                float64 `json:"units,omitempty"`
	Asset                string  `json:"asset,omitempty"`
	NetAssetValuePerUnit float64 `json:"netAssetValuePerUnit,omitempty"`
	Value                float64 `json:"value,omitempty"`
	PostFeeAmount        float64 `json:"postFeeAmount,omitempty"`
}

type GetClientAccountAllocationPerformanceInput struct {
	AccountID         string `json:"accountId,omitempty"`
	AllocationID      string `json:"allocationId,omitempty"`
	Type              string `json:"type,omitempty"`
	FundClassSequence int    `json:"fundClassSequence,omitempty"`
	Timeframe         string `json:"timeframe,omitempty"`
	Interval          string `json:"interval,omitempty"`
}

type GetClientAccountAllocationPerformanceOutput struct {
	Performance []AllocationPerformance `json:"performance"`
}

// GetClientAccountAllocationPerformance retrieves the performance data for a specific account allocation.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "get_client_account_allocation_performance",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "allocationId": "<allocationId>",
//	    "timeframe": "<timeframe>",
//	    "interval": "<interval>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInvalidParameter]
//   - [ErrInternal]
func (c *Client) GetClientAccountAllocationPerformance(ctx context.Context, input *GetClientAccountAllocationPerformanceInput) (output *GetClientAccountAllocationPerformanceOutput, err error) {
	err = c.query(ctx, "get_client_account_allocation_performance", input, &output)
	return output, err
}

type GetClientAccountStatementInput struct {
	AccountID string `json:"accountId,omitempty"`
	FromDate  string `json:"fromDate,omitempty"`
	ToDate    string `json:"toDate,omitempty"`
	Format    string `json:"format"`
}

type GetClientAccountStatementOutput struct {
	FromDate string `json:"fromDate,omitempty"`
	ToDate   string `json:"toDate,omitempty"`
	Format   string `json:"format,omitempty"`
	Filename string `json:"filename,omitempty"`
	Bytes    []byte `json:"bytes,omitempty"`
}

// GetClientAccountStatement retrieves the account statement for a given date range.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "get_client_account_statement",
//	  "payload": {
//	    "accountId": <accountId>,
//	    "fromDate": "<fromDate>",
//	    "toDate": "<toDate<",
//	    "format": "<format>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInvalidParameter]
//   - [ErrInvalidDateRange]
//   - [ErrInternal]
func (c *Client) GetClientAccountStatement(ctx context.Context, input *GetClientAccountStatementInput) (output *GetClientAccountStatementOutput, err error) {
	err = c.query(ctx, "get_client_account_statement", input, &output)
	return output, err
}

type GetClientAccountRequestConfirmationInput struct {
	AccountID string `json:"accountId,omitempty"`
	RequestID string `json:"requestId,omitempty"`
	Format    string `json:"format,omitempty"`
}

type GetClientAccountRequestConfirmationOutput struct {
	Format   string `json:"format,omitempty"`
	Filename string `json:"filename,omitempty"`
	Bytes    []byte `json:"bytes,omitempty"`
}

// GetClientAccountRequestConfirmation retrieves the confirmation document for a specific request.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "get_client_account_request_confirmation",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "requestId": "<requestId>",
//	    "format": "<format>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInvalidParameter]
//   - [ErrInternal]
func (c *Client) GetClientAccountRequestConfirmation(ctx context.Context, input *GetClientAccountRequestConfirmationInput) (output *GetClientAccountRequestConfirmationOutput, err error) {
	err = c.query(ctx, "get_client_account_request_confirmation", input, &output)
	return output, err
}

type GetClientReferralInput struct {
}

type GetClientReferralOutput struct {
	ReferralCode         string `json:"referralCode,omitempty"`
	ReferredClientsCount int    `json:"referredClientsCount"`
}

// GetClientReferral retrieves the referral information for the client.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "get_client_referral",
//	  "payload": {}
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInternal]
func (c *Client) GetClientReferral(ctx context.Context, input *GetClientReferralInput) (output *GetClientReferralOutput, err error) {
	err = c.query(ctx, "get_client_referral", input, &output)
	return output, err
}

type PolicyGroup struct {
	Label string `json:"label,omitempty"`
	Min   int    `json:"min,omitempty"`
	Max   int    `json:"max,omitempty"`
}

type PolicyParticipant struct {
	Email      string `json:"email,omitempty"`
	GroupLabel string `json:"groupLabel,omitempty"`
	Name       string `json:"name,omitempty"`
	Signed     bool   `json:"signed,omitempty"`
	SignedAt   string `json:"signedAt,omitempty"`
}

type GetClientAccountRequestPolicyInput struct {
	AccountID string `json:"accountId"`
	RequestID string `json:"requestId"`
}

type GetClientAccountRequestPolicyOutput struct {
	Groups       []PolicyGroup       `json:"groups"`
	Participants []PolicyParticipant `json:"participants"`
}

// GetClientAccountRequestPolicy retrieves the approval policy for a specific request.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "get_client_account_request_policy",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "requestId": "<requestId>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInvalidRequestPolicy]
//   - [ErrInternal]
func (c *Client) GetClientAccountRequestPolicy(ctx context.Context, input *GetClientAccountRequestPolicyInput) (output *GetClientAccountRequestPolicyOutput, err error) {
	err = c.query(ctx, "get_client_account_request_policy", input, &output)
	return output, err
}

type ListFundsForSubscriptionInput struct {
	AccountID string `json:"accountId,omitempty"`
}

type ListFundsForSubscriptionOutput struct {
	Funds []Fund `json:"funds"`
}

// ListFundsForSubscription lists funds available for subscription for a given account.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_funds_for_subscription",
//	  "payload": {
//	    "accountId": "<accountId>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInternal]
func (c *Client) ListFundsForSubscription(ctx context.Context, input *ListFundsForSubscriptionInput) (output *ListFundsForSubscriptionOutput, err error) {
	err = c.query(ctx, "list_funds_for_subscription", input, &output)
	return output, err
}

type Balance struct {
	FundID                    string   `json:"fundId,omitempty"`
	FundClassSequence         int      `json:"fundClassSequence,omitempty"`
	FundName                  string   `json:"fundName,omitempty"`
	FundShortName             string   `json:"fundShortName,omitempty"`
	FundClassLabel            string   `json:"fundClassLabel,omitempty"`
	FundCode                  string   `json:"fundCode,omitempty"`
	FundImageUrl              string   `json:"fundImageUrl,omitempty"`
	Units                     float64  `json:"units,omitempty"`
	Asset                     string   `json:"asset,omitempty"`
	Value                     float64  `json:"value,omitempty"`
	ValuedAt                  string   `json:"valuedAt,omitempty"`
	MinimumRedemptionAmount   float64  `json:"minimumRedemptionAmount,omitempty"`
	MinimumRedemptionUnits    float64  `json:"minimumRedemptionUnits,omitempty"`
	MinimumSubscriptionAmount float64  `json:"minimumSubscriptionAmount,omitempty"`
	MinimumSubscriptionUnits  float64  `json:"minimumSubscriptionUnits,omitempty"`
	RedemptionFeePercentage   float64  `json:"redemptionFeePercentage,omitempty"`
	SwitchFeePercentage       float64  `json:"switchFeePercentage,omitempty"`
	AvailableModes            []string `json:"availableModes"`
	IsOutOfService            bool     `json:"isOutOfService"`
	OutOfServiceMessage       string   `json:"outOfServiceMessage,omitempty"`
}

type ListClientAccountBalanceInput struct {
	AccountID string `json:"accountId,omitempty"`
}

type ListClientAccountBalanceOutput struct {
	Balance []*Balance `json:"balance,omitempty"`
}

// ListClientAccountBalance lists the balance of a specific client account.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_client_account_balance",
//	  "payload": {
//	    "accountId": "<accountId>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrMissingResource]
//   - [ErrInternal]
func (c *Client) ListClientAccountBalance(ctx context.Context, input *ListClientAccountBalanceInput) (output *ListClientAccountBalanceOutput, err error) {
	err = c.query(ctx, "list_client_account_balance", input, &output)
	return output, err
}

type BankAccount struct {
	AccountNumber   string `json:"accountNumber,omitempty"`
	AccountName     string `json:"accountName,omitempty"`
	AccountCurrency string `json:"accountCurrency,omitempty"`
	AccountType     string `json:"accountType,omitempty"`
	BankName        string `json:"bankName,omitempty"`
	BankBic         string `json:"bankBic,omitempty"`
	ReferenceNumber string `json:"referenceNumber,omitempty"`
	ImageUrl        string `json:"imageUrl,omitempty"`
	Status          string `json:"status,omitempty"`
	Source          string `json:"source,omitempty"`
	CreatedAt       string `json:"createdAt,omitempty"`
	CreatedBy       string `json:"createdBy,omitempty"`
}

type ClientAccountRequest struct {
	ID string `json:"id,omitempty"`
	// fundmanagement: investment, redemption, switch out, switch in
	// dim: deposit, withdrawal
	Type string `json:"type,omitempty"`

	FundID         string `json:"fundId,omitempty"`
	FundName       string `json:"fundName,omitempty"`
	FundShortName  string `json:"fundShortName,omitempty"`
	FundClassLabel string `json:"fundClassLabel,omitempty"`

	Asset                string   `json:"asset,omitempty"`
	Amount               float64  `json:"amount,omitempty"`
	PostFeeAmount        float64  `json:"postFeeAmount,omitempty"`
	Units                float64  `json:"units,omitempty"`
	UnitPrice            *float64 `json:"unitPrice,omitempty"`
	FeePercentage        float64  `json:"feePercentage,omitempty"`
	StrokedFeePercentage float64  `json:"strokedFeePercentage,omitempty"`
	FeeAmount            float64  `json:"feeAmount,omitempty"`
	RebateFromDate       string   `json:"rebateFromDate,omitempty"`
	RebateToDate         string   `json:"rebateToDate,omitempty"`
	Status               string   `json:"status,omitempty"`

	VoucherCode   *string `json:"voucherCode,omitempty"`
	ConsentType   *string `json:"consentType,omitempty"`
	ConsentStatus *string `json:"consentStatus,omitempty"`

	CollectionBankAccount *BankAccount `json:"collectionBankAccount,omitempty"`

	CreatedAt string `json:"createdAt,omitempty"`
}

type ListClientAccountRequestsInput struct {
	AccountID string  `json:"accountId,omitempty"`
	RequestID *string `json:"requestId,omitempty"`
	// Deprecated: Use FundIDs instead.
	FundID        *string   `json:"fundId,omitempty"`
	FundIDs       []*string `json:"fundIds,omitempty"`
	FromDate      *string   `json:"fromDate,omitempty"`
	ToDate        *string   `json:"toDate,omitempty"`
	Types         []*string `json:"types,omitempty"`
	Statuses      []*string `json:"statuses,omitempty"`
	Limit         *int      `json:"limit,omitempty"`
	Offset        *int      `json:"offset,omitempty"`
	CompletedOnly bool      `json:"completedOnly,omitempty"`
}

type ListClientAccountRequestsOutput struct {
	Requests []ClientAccountRequest `json:"requests"`
}

// ListClientAccountRequests lists requests (investments, redemptions, etc.) for a specific account.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_client_account_requests",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "limit": <limit>
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInvalidParameter]
//   - [ErrInternal]
func (c *Client) ListClientAccountRequests(ctx context.Context, input *ListClientAccountRequestsInput) (output *ListClientAccountRequestsOutput, err error) {
	err = c.query(ctx, "list_client_account_requests", input, &output)
	return output, err
}

type ListClientBankAccountsInput struct {
}

type ListClientBankAccountsOutput struct {
	BankAccounts []BankAccount `json:"bankAccounts"`
}

// ListClientBankAccounts lists all bank accounts registered to the client.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_client_bank_accounts",
//	  "payload": {}
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInternal]
func (c *Client) ListClientBankAccounts(ctx context.Context, input *ListClientBankAccountsInput) (output *ListClientBankAccountsOutput, err error) {
	err = c.query(ctx, "list_client_bank_accounts", input, &output)
	return output, err
}

type DisplayCurrency struct {
	ID       string `json:"id,omitempty"`
	Label    string `json:"label,omitempty"`
	ImageUrl string `json:"imageUrl,omitempty"`
}

type ListDisplayCurrenciesInput struct {
}

type ListDisplayCurrenciesOutput struct {
	DisplayCurrency string            `json:"displayCurrency,omitempty"`
	Currencies      []DisplayCurrency `json:"currencies"`
}

// ListDisplayCurrencies lists the available currencies for display purposes.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_display_currencies",
//	  "payload": {}
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInternal]
func (c *Client) ListDisplayCurrencies(ctx context.Context, input *ListDisplayCurrenciesInput) (output *ListDisplayCurrenciesOutput, err error) {
	err = c.query(ctx, "list_display_currencies", input, &output)
	return output, err
}

type SuitabilityAssessment struct {
	ID                   string `json:"id,omitempty"`
	ClientID             string `json:"clientId,omitempty"`
	Source               string `json:"source,omitempty"`
	InvestmentExperience string `json:"investmentExperience,omitempty"`
	InvestmentObjective  string `json:"investmentObjective,omitempty"`
	InvestmentHorizon    string `json:"investmentHorizon,omitempty"`
	CurrentInvestment    string `json:"currentInvestment,omitempty"`
	ReturnExpectations   string `json:"returnExpectations,omitempty"`
	Attachment           string `json:"attachment,omitempty"`
	TotalScore           int    `json:"totalScore,omitempty"`
	RiskTolerance        string `json:"riskTolerance,omitempty"`
	CreatedBy            string `json:"createdBy,omitempty"`
	CreatedAt            string `json:"createdAt,omitempty"`
}

type ListClientSuitabilityAssessmentsInput struct {
}

type ListClientSuitabilityAssessmentsOutput struct {
	ShouldAskSuitabilityAssessment bool                    `json:"shouldAskSuitabilityAssessment"`
	CanIgnoreSuitabilityAssessment bool                    `json:"canIgnoreSuitabilityAssessment"`
	Assessments                    []SuitabilityAssessment `json:"assessments"`
}

// ListClientSuitabilityAssessments lists the suitability assessments associated with the client.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_client_suitability_assessments",
//	  "payload": {}
//	}'
//
// Errors:
//   - [ErrInsufficientAccess]
//   - [ErrInternal]
func (c *Client) ListClientSuitabilityAssessments(ctx context.Context, input *ListClientSuitabilityAssessmentsInput) (output *ListClientSuitabilityAssessmentsOutput, err error) {
	err = c.query(ctx, "list_client_suitability_assessments", input, &output)
	return output, err
}

type DuitNowBank struct {
	Code     string `json:"code,omitempty"`
	Name     string `json:"name,omitempty"`
	Url      string `json:"url,omitempty"`
	ImageUrl string `json:"imageUrl,omitempty"`
}

type ListDuitNowBanksInput struct {
	AccountID string `json:"accountId,omitempty"`
}

type ListDuitNowBanksOutput struct {
	Banks []DuitNowBank `json:"banks"`
}

// ListDuitNowBanks lists the available banks for DuitNow transfers.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_duitnow_banks",
//	  "payload": {
//	    "accountId": "<accountId>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInternal]
func (c *Client) ListDuitNowBanks(ctx context.Context, input *ListDuitNowBanksInput) (output *ListDuitNowBanksOutput, err error) {
	err = c.query(ctx, "list_duitnow_banks", input, &output)
	return output, err
}

type Consent struct {
	Name  string `json:"name,omitempty"`
	Label string `json:"label,omitempty"`
}

type ListInvestConsentsInput struct {
	AccountID         string `json:"accountId,omitempty"`
	FundID            string `json:"fundId,omitempty"`
	FundClassSequence int    `json:"fundClassSequence,omitempty"`
}

type ListInvestConsentsOutput struct {
	Consents        []Consent `json:"consents"`
	ConsentFundIM   bool      `json:"consentFundIM,omitempty"`
	ConsentHighRisk bool      `json:"consentHighRisk,omitempty"`
}

// ListInvestConsents lists the required consents for a specific investment.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_invest_consents",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "fundId": "<fundId>",
//	    "fundClassSequence": <fundClassSequence>
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrMissingResource]
//   - [ErrInternal]
func (c *Client) ListInvestConsents(ctx context.Context, input *ListInvestConsentsInput) (output *ListInvestConsentsOutput, err error) {
	err = c.query(ctx, "list_invest_consents", input, &output)
	return output, err
}

type Bank struct {
	Name     string `json:"name,omitempty"`
	Bic      string `json:"bic,omitempty"`
	ImageUrl string `json:"imageUrl,omitempty"`
	Rank     int    `json:"rank,omitempty"`
}

type ListBanksInput struct {
}

type ListBanksOutput struct {
	Banks []Bank `json:"banks"`
}

// ListBanks lists the supported banks for the platform.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_banks",
//	  "payload": {}
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInternal]
func (c *Client) ListBanks(ctx context.Context, input *ListBanksInput) (output *ListBanksOutput, err error) {
	err = c.query(ctx, "list_banks", input, &output)
	return output, err
}

type ClientAccountMandateRequest struct {
	ID string `json:"id,omitempty"`
	// Deposit / Withdraw / Buy / Sell
	Type string `json:"type,omitempty"`

	BaseAsset  string  `json:"baseAsset,omitempty"`
	BaseAmount float64 `json:"baseAmount,omitempty"`

	QuoteAsset  string  `json:"quoteAsset,omitempty"`
	QuoteAmount float64 `json:"quoteAmount,omitempty"`

	UnitPrice float64 `json:"unitPrice,omitempty"`
	Status    string  `json:"status,omitempty"`
	CreatedAt string  `json:"createdAt,omitempty"`
}

type ListClientAccountMandateRequestsInput struct {
	AccountID  string    `json:"accountId,omitempty"`
	RequestID  *string   `json:"requestId,omitempty"`
	Types      []*string `json:"types,omitempty"`
	BaseAssets []*string `json:"baseAssets,omitempty"`
	FromDate   *string   `json:"fromDate,omitempty"`
	ToDate     *string   `json:"toDate,omitempty"`
	Limit      *int      `json:"limit,omitempty"`
	Offset     *int      `json:"offset,omitempty"`
}

type ListClientAccountMandateRequestsOutput struct {
	Requests []ClientAccountMandateRequest `json:"requests"`
}

// ListClientAccountMandateRequests lists mandate requests for a client account.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_client_account_mandate_requests",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "limit": <limit>
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInvalidParameter]
//   - [ErrInvalidAccountExperience]
//   - [ErrInternal]
func (c *Client) ListClientAccountMandateRequests(ctx context.Context, input *ListClientAccountMandateRequestsInput) (output *ListClientAccountMandateRequestsOutput, err error) {
	err = c.query(ctx, "list_client_account_mandate_requests", input, &output)
	return output, err
}

type Promo struct {
	AccountID          string  `json:"accountId,omitempty"`
	AccountName        string  `json:"accountName,omitempty"`
	Code               string  `json:"code,omitempty"`
	Label              string  `json:"label,omitempty"`
	Description        string  `json:"description,omitempty"`
	DiscountPercentage float64 `json:"discountPercentage,omitempty"`
	DiscountFrom       string  `json:"discountFrom,omitempty"`
	ValidFromDate      *string `json:"validFromDate,omitempty"`
	ValidToDate        *string `json:"validToDate,omitempty"`
	CreatedAt          string  `json:"createdAt,omitempty"`
}

type ListClientPromosInput struct {
}

type ListClientPromosOutput struct {
	Promos []Promo `json:"promos"`
}

// ListClientPromos lists available promotions for the client.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_client_promos",
//	  "payload": {}
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInternal]
func (c *Client) ListClientPromos(ctx context.Context, input *ListClientPromosInput) (output *ListClientPromosOutput, err error) {
	err = c.query(ctx, "list_client_promos", input, &output)
	return output, err
}

type ClientAccountPerformance struct {
	Date      string  `json:"date,omitempty"`
	AccountID string  `json:"accountId,omitempty"`
	Value     float64 `json:"value,omitempty"`
}

type ListClientAccountPerformanceInput struct {
	AccountIDs []string `json:"accountIds,omitempty"`
	Timeframe  string   `json:"timeframe,omitempty"`
	Interval   string   `json:"interval,omitempty"`
}

type ListClientAccountPerformanceOutput struct {
	Performance []ClientAccountPerformance `json:"performance,omitempty"`
}

// ListClientAccountPerformance lists the historical performance of client accounts.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_client_account_performance",
//	  "payload": {
//	    "accountIds": ["<accountId>", "<accountId>"],
//	    "timeframe": "<timeframe>",
//	    "interval": "<interval>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInvalidParameter]
//   - [ErrInternal]
func (c *Client) ListClientAccountPerformance(ctx context.Context, input *ListClientAccountPerformanceInput) (output *ListClientAccountPerformanceOutput, err error) {
	err = c.query(ctx, "list_client_account_performance", input, &output)
	return output, err
}

type ListPaymentMethodsInput struct {
}

type ListPaymentMethodsOutput struct {
	Duitnow      bool `json:"duitnow"`
	BankTransfer bool `json:"bankTransfer"`
}

// ListPaymentMethods lists the available payment methods.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "list_payment_methods",
//	  "payload": {}
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInternal]
func (c *Client) ListPaymentMethods(ctx context.Context, input *ListPaymentMethodsInput) (output *ListPaymentMethodsOutput, err error) {
	err = c.query(ctx, "list_payment_methods", input, &output)
	return output, err
}

type GetVoucherInput struct {
	AccountID         string  `json:"accountId,omitempty"`
	FundID            string  `json:"fundId,omitempty"`
	FundClassSequence int     `json:"fundClassSequence,omitempty"`
	Amount            float64 `json:"amount,omitempty"`
	VoucherCode       *string `json:"voucherCode,omitempty"`
}

type GetVoucherOutput struct {
	Valid                            bool    `json:"valid"`
	Code                             string  `json:"code"`
	StrokedSubscriptionFeePercentage float64 `json:"strokedSubscriptionFeePercentage"`
	AppliedSubscriptionFeePercentage float64 `json:"appliedSubscriptionFeePercentage"`
	VoucherDiscountPercentage        float64 `json:"voucherDiscountPercentage"`
	FeeAmount                        float64 `json:"feeAmount"`
	PostFeeAmount                    float64 `json:"postFeeAmount"`
}

// GetVoucher retrieves details of a specific voucher.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "get_voucher",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "fundId": "<fundId>",
//	    "fundClassSequence": <fundClassSequence>
//	    "amount": <amount>,
//	    "voucherCode": "<voucherCode>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrMissingResource]
//   - [ErrInternal]
func (c *Client) GetVoucher(ctx context.Context, input *GetVoucherInput) (output *GetVoucherOutput, err error) {
	err = c.query(ctx, "get_voucher", input, &output)
	return output, err
}

type GetPreviewInvestInput struct {
	AccountID         string  `json:"accountId,omitempty"`
	FundID            string  `json:"fundId,omitempty"`
	FundClassSequence int     `json:"fundClassSequence,omitempty"`
	Amount            float64 `json:"amount,omitempty"`
}

type GetPreviewInvestOutput struct {
	StrokedSubscriptionFeePercentage float64           `json:"strokedSubscriptionFeePercentage"`
	AppliedSubscriptionFeePercentage float64           `json:"appliedSubscriptionFeePercentage"`
	PostFeeAmount                    float64           `json:"postFeeAmount"`
	FeeAmount                        float64           `json:"feeAmount"`
	DefaultVoucher                   *GetVoucherOutput `json:"defaultVoucher,omitempty"`
}

// GetPreviewInvest calculates a preview of an investment, including fees.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "get_preview_invest",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "fundId": "<fundId>",
//	    "fundClassSequence": <fundClassSequence>
//	    "amount": <amount>
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrMissingResource]
//   - [ErrInternal]
func (c *Client) GetPreviewInvest(ctx context.Context, input *GetPreviewInvestInput) (output *GetPreviewInvestOutput, err error) {
	err = c.query(ctx, "get_preview_invest", input, &output)
	return output, err
}

type GetProjectedFundPriceInput struct {
	FundID            string `json:"fundId,omitempty"`
	FundClassSequence int    `json:"fundClassSequence,omitempty"`
}

type GetProjectedFundPriceOutput struct {
	NetAssetValuePerUnit float64 `json:"netAssetValuePerUnit"`
}

// GetProjectedFundPrice retrieves the projected price for a fund.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/query" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "get_projected_fund_price",
//	  "payload": {
//	    "fundId": "<fundId>",
//	    "fundClassSequence": <fundClassSequence>
//	  }
//	}'
func (c *Client) GetProjectedFundPrice(ctx context.Context, input *GetProjectedFundPriceInput) (output *GetProjectedFundPriceOutput, err error) {
	err = c.query(ctx, "get_projected_fund_price", input, &output)
	return output, err
}

//
// Commands
//

// CreateInvestmentRequestInput represents the payload for creating a new investment request.
type CreateInvestmentRequestInput struct {
	// AccountID specifies the identifier of the client account for the investment.
	AccountID string `json:"accountId,omitempty"`
	// FundID specifies the identifier of the fund to invest in.
	FundID string `json:"fundId,omitempty"`
	// FundClassSequence specifies the class of the fund to invest in.
	FundClassSequence int `json:"fundClassSequence,omitempty"`
	// Amount specifies the amount to be invested.
	Amount float64 `json:"amount,omitempty"`

	// ConsentFundIM is deprecated, use Consents instead.
	ConsentFundIM bool `json:"consentFundIM,omitempty"`
	// ConsentHighRisk is deprecated, use Consents instead.
	ConsentHighRisk bool `json:"consentHighRisk,omitempty"`

	// Consents specifies a map of consent names to boolean values (true if consented).
	Consents map[string]bool `json:"consents,omitempty"`

	// VoucherCode specifies an optional voucher code to apply to the investment.
	VoucherCode string `json:"voucherCode,omitempty"`
}

// CreateInvestmentRequestOutput represents the response for an investment request.
type CreateInvestmentRequestOutput struct {
	// RequestID specifies the identifier of the created investment request.
	RequestID string `json:"requestId,omitempty"`
}

// CreateInvestmentRequest initiates a new investment request for a specified amount into a fund class.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/command" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "create_investment_request",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "fundId": "<fundId>",
//	    "fundClassSequence": <fundClassSequence>
//	    "amount": <amount>,
//	    "consents": {
//	      "IM": true
//	    }
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInvalidParameter]
//   - [ErrActionOutsideFundHours]
//   - [ErrMissingResource]
//   - [ErrInternal]
func (c *Client) CreateInvestmentRequest(ctx context.Context, input *CreateInvestmentRequestInput) (output *CreateInvestmentRequestOutput, err error) {
	err = c.command(ctx, "create_investment_request", input, &output)
	return output, err
}

// CreateRedeemRequestInput represents the payload for creating a new redemption (withdrawal) request.
type CreateRedemptionRequestInput struct {
	// AccountID specifies the identifier of the client account.
	AccountID string `json:"accountId,omitempty"`
	// FundID specifies the identifier of the fund to redeem from.
	FundID string `json:"fundId,omitempty"`
	// FundClassSequence specifies the class of the fund to redeem from.
	FundClassSequence int `json:"fundClassSequence,omitempty"`
	// RequestedAmount specifies the amount to redeem.
	RequestedAmount float64 `json:"requestedAmount,omitempty"`
	// Units specifies the number of units to redeem.
	Units float64 `json:"units,omitempty"`
	// ToBankAccountNumber specifies the bank account number for the redemption proceeds.
	ToBankAccountNumber string `json:"toBankAccountNumber,omitempty"`
}

// CreateRedeemRequestOutput represents the response for a redemption request.
type CreateRedemptionRequestOutput struct {
	// RequestID specifies the identifier of the created redemption request.
	RequestID string `json:"requestId,omitempty"`
}

// CreateRedemptionRequest initiates a new redemption request (selling units or withdrawing an amount) from a fund class.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/command" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "create_redemption_request",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "fundId": "<fundId>",
//	    "fundClassSequence": <fundClassSequence>
//	    "requestedAmount": <amount>,
//	    "toBankAccountNumber": "<toBankAccountNumber>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInvalidParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInsufficientBalance]
//   - [ErrActionOutsideFundHours]
//   - [ErrMissingResource]
//   - [ErrInternal]
func (c *Client) CreateRedemptionRequest(ctx context.Context, input *CreateRedemptionRequestInput) (output *CreateRedemptionRequestOutput, err error) {
	err = c.command(ctx, "create_redemption_request", input, &output)
	return output, err
}

// CreateSwitchRequestInput represents the payload for creating a new fund switch request.
type CreateSwitchRequestInput struct {
	// AccountID specifies the identifier of the client account.
	AccountID string `json:"accountId,omitempty"`

	// SwitchFromFundID specifies the fund ID to switch units *from*.
	SwitchFromFundID string `json:"switchFromFundId,omitempty"`
	// SwitchFromFundClassSequence specifies the fund class sequence to switch units *from*.
	SwitchFromFundClassSequence int `json:"switchFromFundClassSequence,omitempty"`
	// SwitchToFundID specifies the fund ID to switch units *to*.
	SwitchToFundID string `json:"switchToFundId,omitempty"`
	// SwitchToFundClassSequence specifies the fund class sequence to switch units *to*.
	SwitchToFundClassSequence int `json:"switchToFundClassSequence,omitempty"`

	// RequestedAmount specifies the amount to switch.
	RequestedAmount float64 `json:"requestedAmount,omitempty"`
	// Units specifies the number of units to switch.
	Units float64 `json:"units,omitempty"`
}

// CreateSwitchRequestOutput represents the response for a switch request.
type CreateSwitchRequestOutput struct {
	// RequestID specifies the identifier of the created switch request.
	RequestID string `json:"requestId,omitempty"`
}

// CreateSwitchRequest initiates a new request to switch funds/units within the client account.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/command" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "create_switch_request",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "switchFromFundId": "<switchFromFundId>",
//	    "switchFromFundClassSequence": <fundClassSequence>
//	    "switchToFundId": "<switchToFundId>",
//	    "switchToFundClassSequence": <switchToFundClassSequence>
//	    "requestedAmount": <amount>
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInvalidParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInsufficientBalance]
//   - [ErrActionOutsideFundHours]
//   - [ErrMissingResource]
//   - [ErrInternal]
func (c *Client) CreateSwitchRequest(ctx context.Context, input *CreateSwitchRequestInput) (output *CreateSwitchRequestOutput, err error) {
	err = c.command(ctx, "create_switch_request", input, &output)
	return output, err
}

// CreateRequestCancellationInput represents the payload for canceling an existing request.
type CreateRequestCancellationInput struct {
	// AccountID specifies the identifier of the client account associated with the request.
	AccountID string `json:"accountId,omitempty"`
	// RequestID specifies the identifier of the request to cancel.
	RequestID string `json:"requestId,omitempty"`
}

// CreateRequestCancellationOutput represents the response for a cancel request command (empty upon success).
type CreateRequestCancellationOutput struct {
}

// CreateRequestCancellation cancels a pending request (e.g., investment, redemption, switch).
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/command" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "create_request_cancellation",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "requestId": "<requestId>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrRequestCannotBeCancelled]
//   - [ErrInsufficientAccess]
//   - [ErrMissingResource]
//   - [ErrInternal]
func (c *Client) CreateRequestCancellation(ctx context.Context, input *CreateRequestCancellationInput) (output *CreateRequestCancellationOutput, err error) {
	err = c.command(ctx, "create_request_cancellation", input, &output)
	return output, err
}

// CreateWithdrawalRequestInput represents the payload for creating a withdrawal request (DIM experience).
type CreateWithdrawalRequestInput struct {
	// AccountID specifies the identifier of the DIM client account.
	AccountID string `json:"accountId,omitempty"`
	// Amount specifies the amount to withdraw.
	Amount float64 `json:"amount,omitempty"`
}

// CreateWithdrawalRequestOutput represents the response for a withdrawal request.
type CreateWithdrawalRequestOutput struct {
	// RequestID specifies the identifier of the created withdrawal request.
	RequestID string `json:"requestId,omitempty"`
}

// CreateWithdrawalRequest initiates a new withdrawal request for a DIM account.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/command" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "create_withdrawal_request",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "amount": <amount>
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrActionNotAllowedForAccountType]
//   - [ErrInsufficientAccess]
//   - [ErrInternal]
func (c *Client) CreateWithdrawalRequest(ctx context.Context, input *CreateWithdrawalRequestInput) (output *CreateWithdrawalRequestOutput, err error) {
	err = c.command(ctx, "create_withdrawal_request", input, &output)
	return output, err
}

// CreateDepositRequestInput represents the payload for creating a deposit request (DIM experience).
type CreateDepositRequestInput struct {
	// AccountID specifies the identifier of the DIM client account.
	AccountID string `json:"accountId,omitempty"`
	// Amount specifies the amount to deposit.
	Amount float64 `json:"amount,omitempty"`
}

// CreateDepositRequestOutput represents the response for a deposit request.
type CreateDepositRequestOutput struct {
	// RequestID specifies the identifier of the created deposit request.
	RequestID string `json:"requestId,omitempty"`
}

// CreateDepositRequest initiates a new deposit request for a DIM account.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/command" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "create_deposit_request",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "amount": <amount>
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrActionNotAllowedForAccountType]
//   - [ErrInternal]
func (c *Client) CreateDepositRequest(ctx context.Context, input *CreateDepositRequestInput) (output *CreateDepositRequestOutput, err error) {
	err = c.command(ctx, "create_deposit_request", input, &output)
	return output, err
}

// CreateSuitabilityAssessmentInput represents the payload for submitting a new suitability assessment.
type CreateSuitabilityAssessmentInput struct {
	// SuitabilityAssessment contains the details of the assessment being submitted.
	SuitabilityAssessment *SuitabilityAssessment `json:"suitabilityAssessment,omitempty"`
}

// CreateSuitabilityAssessmentOutput represents the response for creating a suitability assessment.
type CreateSuitabilityAssessmentOutput struct {
	// SuitabilityAssessmentID specifies the identifier of the created assessment.
	SuitabilityAssessmentID string `json:"suitabilityAssessmentId,omitempty"`
}

// CreateSuitabilityAssessment submits a new suitability assessment for the client.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/command" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "create_suitability_assessment",
//	  "payload": {
//	    "suitabilityAssessment": {
//	      "riskTolerance": "<riskTolerance>",
//	      "totalScore": <totalScore>
//	    }
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInvalidParameter]
//   - [ErrInternal]
func (c *Client) CreateSuitabilityAssessment(ctx context.Context, input *CreateSuitabilityAssessmentInput) (output *CreateSuitabilityAssessmentOutput, err error) {
	err = c.command(ctx, "create_suitability_assessment", input, &output)
	return output, err
}

// CreateClientBankAccountInput represents the payload for adding a new bank account.
type CreateClientBankAccountInput struct {
	// BankAccount contains the details of the bank account to be created.
	BankAccount *BankAccount `json:"bankAccount,omitempty"`
}

// CreateClientBankAccountOutput represents the response for adding a bank account (empty upon success).
type CreateClientBankAccountOutput struct {
}

// CreateClientBankAccount adds a new bank account to the client's profile.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/command" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "create_client_bank_account",
//	  "payload": {
//	    "bankAccount": {
//	      "accountNumber": "<accountNumber>",
//	      "bankName": "<bankName>"
//	    }
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInvalidParameter]
//   - [ErrAlreadyExists]
//   - [ErrInternal]
func (c *Client) CreateClientBankAccount(ctx context.Context, input *CreateClientBankAccountInput) (output *CreateClientBankAccountOutput, err error) {
	err = c.command(ctx, "create_client_bank_account", input, &output)
	return output, err
}

// UpdateDisplayCurrencyInput represents the payload for changing the client's display currency.
type UpdateDisplayCurrencyInput struct {
	// DisplayCurrency specifies the new currency ID to be used for display.
	DisplayCurrency string `json:"displayCurrency,omitempty"`
}

// UpdateDisplayCurrencyOutput represents the response for updating the display currency (empty upon success).
type UpdateDisplayCurrencyOutput struct {
}

// UpdateDisplayCurrency sets the preferred display currency for the client's accounts.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/command" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "update_display_currency",
//	  "payload": {
//	    "displayCurrency": "<displayCurrency>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInvalidParameter]
//   - [ErrInternal]
func (c *Client) UpdateDisplayCurrency(ctx context.Context, input *UpdateDisplayCurrencyInput) (output *UpdateDisplayCurrencyOutput, err error) {
	err = c.command(ctx, "update_display_currency", input, &output)
	return output, err
}

// UpdateAccountNameInput represents the payload for changing a client account's name.
type UpdateAccountNameInput struct {
	// AccountID specifies the ID of the account to update.
	AccountID string `json:"accountId,omitempty"`
	// AccountName specifies the new name for the account.
	AccountName string `json:"accountName,omitempty"`
}

// UpdateAccountNameOutput represents the response for updating an account name (empty upon success).
type UpdateAccountNameOutput struct {
}

// UpdateAccountName updates the friendly name of a client account.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/command" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "update_account_name",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "accountName": "<accountName>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInvalidParameter]
//   - [ErrInternal]
func (c *Client) UpdateAccountName(ctx context.Context, input *UpdateAccountNameInput) (output *UpdateAccountNameOutput, err error) {
	err = c.command(ctx, "update_account_name", input, &output)
	return output, err
}

// CreateDuitnowPaymentInput represents the payload for initiating a DuitNow payment.
type CreateDuitnowPaymentInput struct {
	// AccountID specifies the client account ID related to the payment.
	AccountID string `json:"accountId,omitempty"`
	// RequestID specifies the related request ID (e.g., deposit or investment) for this payment.
	RequestID string `json:"requestId,omitempty"`
	// BankCode specifies the code of the bank from which the DuitNow payment will be initiated.
	BankCode string `json:"bankCode,omitempty"`
}

// CreateDuitnowPaymentOutput represents the response for initiating a DuitNow payment.
type CreateDuitnowPaymentOutput struct {
	// Url specifies the redirect URL to the bank's payment gateway or instruction page.
	Url string `json:"url,omitempty"`
}

// CreateDuitnowPayment creates a payment instruction and provides a redirect URL for DuitNow payment.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/command" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "create_duitnow_payment",
//	  "payload": {
//	    "accountId": "<accountId>",
//	    "requestId": "<requestId>",
//	    "bankCode": "<bankCode>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrDuitNowInvalidParameter]
//   - [ErrDuitNowUnavailable]
//   - [ErrMissingResource]
//   - [ErrInternal]
func (c *Client) CreateDuitnowPayment(ctx context.Context, input *CreateDuitnowPaymentInput) (output *CreateDuitnowPaymentOutput, err error) {
	err = c.command(ctx, "create_duitnow_payment", input, &output)
	return output, err
}

// UpdatePersonaTitleInput represents the payload for updating a client's persona title (e.g., Mr., Ms.).
type UpdatePersonaTitleInput struct {
	// Title specifies the new title.
	Title string `json:"title,omitempty"`
}

// UpdatePersonaTitleOutput represents the response for updating the persona title (empty upon success).
type UpdatePersonaTitleOutput struct {
}

// UpdatePersonaTitle updates the title of the client's persona/profile.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/command" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "update_persona_title",
//	  "payload": {
//	    "title": "<title>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInternal]
func (c *Client) UpdatePersonaTitle(ctx context.Context, input *UpdatePersonaTitleInput) (output *UpdatePersonaTitleOutput, err error) {
	err = c.command(ctx, "update_persona_title", input, &output)
	return output, err
}

// UpdateClientProfileInput represents the payload for updating specific fields on the client's profile.
type UpdateClientProfileInput struct {
	// Ethnicity specifies the client's ethnicity. Value is one of "bumiputera", "chinese", "indian" or "other".
	Ethnicity string `json:"ethnicity,omitempty"`
	// OtherEthnicity is used if Ethnicity is "other" to specify the exact ethnicity.
	OtherEthnicity string `json:"otherEthnicity,omitempty"`

	// DomesticRinggitBorrowing specifies the client's domestic ringgit borrowing status.
	DomesticRinggitBorrowing string `json:"domesticRinggitBorrowing,omitempty"`
	// TaxResidency specifies the client's tax residency status. Value is one of "onlyMalaysia", "multiple" or "nonMalaysia".
	TaxResidency string `json:"taxResidency,omitempty"`
	// CountryTax specifies the country where the client pays tax.
	CountryTax string `json:"countryTax,omitempty"`
	// TaxIdentificationNo specifies the client's tax account number.
	TaxIdentificationNo string `json:"taxIdentificationNo,omitempty"`
}

// UpdateClientProfileOutput represents the response for updating the client profile (empty upon success).
type UpdateClientProfileOutput struct {
}

// UpdateClientProfile updates the client's demographic and tax-related profile details.
//
// cURL:
//
//	curl -X "POST" "https://external-api.wallet.halogen.my/command" \
//	  -H 'Authorization: Bearer <JWT>' \
//	  -H 'Content-Type: application/json; charset=utf-8' \
//	  -d $'{
//	  "name": "update_client_profile",
//	  "payload": {
//	    "ethnicity": "<ethnicity>",
//	    "taxResidency": "<taxResidency>"
//	  }
//	}'
//
// Errors:
//   - [ErrMissingParameter]
//   - [ErrInsufficientAccess]
//   - [ErrInvalidParameter]
//   - [ErrInternal]
func (c *Client) UpdateClientProfile(ctx context.Context, input *UpdateClientProfileInput) (output *UpdateClientProfileOutput, err error) {
	err = c.command(ctx, "update_client_profile", input, &output)
	return output, err
}
