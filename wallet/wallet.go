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
func (c *Client) ListClientAccounts(ctx context.Context, input *ListClientAccountsInput) (*ListClientAccountsOutput, error) {
	output := ListClientAccountsOutput{}
	err := c.query(ctx, "list_client_accounts", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) GetClientProfile(ctx context.Context, input *GetClientProfileInput) (*GetClientProfileOutput, error) {
	output := GetClientProfileOutput{}
	err := c.query(ctx, "get_client_profile", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
}

type Fund struct {
	ID                   string                 `json:"id,omitempty"`
	Type                 string                 `json:"type,omitempty"`
	Name                 string                 `json:"name,omitempty"`
	ShortName            string                 `json:"shortName,omitempty"`
	BaseCurrency         string                 `json:"baseCurrency,omitempty"`
	Category             string                 `json:"category,omitempty"`
	Code                 string                 `json:"code,omitempty"`
	InvestmentObjective  string                 `json:"investmentObjective,omitempty"`
	InvestorType         string                 `json:"investorType,omitempty"`
	RiskRating           string                 `json:"riskRating,omitempty"`
	RiskScore            int                    `json:"riskScore,omitempty"`
	PrimaryFundManager   string                 `json:"primaryFundManager,omitempty"`
	SecondaryFundManager string                 `json:"secondaryFundManager,omitempty"`
	ShariahCompliant     bool                   `json:"shariahCompliant,omitempty"`
	Status               string                 `json:"status,omitempty"`
	TagLine              string                 `json:"tagLine,omitempty"`
	Trustee              string                 `json:"trustee,omitempty"`
	ImageUrl             string                 `json:"imageUrl,omitempty"`
	CreatedAt            string                 `json:"createdAt,omitempty"`
	Classes              []FundClass            `json:"classes,omitempty"`
	IsOutOfService       bool                   `json:"isOutOfService"`
	OutOfServiceMessage  string                 `json:"outOfServiceMessage,omitempty"`
	Metadata             map[string]interface{} `json:"metadata,omitempty"`
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

func (c *Client) GetFund(ctx context.Context, input *GetFundInput) (*GetFundOutput, error) {
	output := GetFundOutput{}
	err := c.query(ctx, "get_fund", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
}

type GetRequestByDuitNowEndToEndIDInput struct {
	AccountID  string `json:"accountId,omitempty"`
	EndToEndID string `json:"endToEndId,omitempty"`
}

type GetRequestByDuitNowEndToEndIDOutput struct {
	RequestID string `json:"requestId,omitempty"`
}

func (c *Client) GetRequestByDuitNowEndToEndID(ctx context.Context, input *GetRequestByDuitNowEndToEndIDInput) (*GetRequestByDuitNowEndToEndIDOutput, error) {
	output := GetRequestByDuitNowEndToEndIDOutput{}
	err := c.query(ctx, "get_request_by_duitnow_endToEndId", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) GetClientAccountAllocationPerformance(ctx context.Context, input *GetClientAccountAllocationPerformanceInput) (*GetClientAccountAllocationPerformanceOutput, error) {
	output := GetClientAccountAllocationPerformanceOutput{}
	err := c.query(ctx, "get_client_account_allocation_performance", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) GetClientAccountStatement(ctx context.Context, input *GetClientAccountStatementInput) (*GetClientAccountStatementOutput, error) {
	output := GetClientAccountStatementOutput{}
	err := c.query(ctx, "get_client_account_statement", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) GetClientAccountRequestConfirmation(ctx context.Context, input *GetClientAccountRequestConfirmationInput) (*GetClientAccountRequestConfirmationOutput, error) {
	output := GetClientAccountRequestConfirmationOutput{}
	err := c.query(ctx, "get_client_account_request_confirmation", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
}

type GetClientReferralInput struct {
}

type GetClientReferralOutput struct {
	ReferralCode         string `json:"referralCode,omitempty"`
	ReferredClientsCount int    `json:"referredClientsCount"`
}

func (c *Client) GetClientReferral(ctx context.Context, input *GetClientReferralInput) (*GetClientReferralOutput, error) {
	output := GetClientReferralOutput{}
	err := c.query(ctx, "get_client_referral", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) GetClientAccountRequestPolicy(ctx context.Context, input *GetClientAccountRequestPolicyInput) (*GetClientAccountRequestPolicyOutput, error) {
	output := GetClientAccountRequestPolicyOutput{}
	err := c.query(ctx, "get_client_account_request_policy", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
}

type ListFundsForSubscriptionInput struct {
	AccountID string `json:"accountId,omitempty"`
}

type ListFundsForSubscriptionOutput struct {
	Funds []Fund `json:"funds"`
}

func (c *Client) ListFundsForSubscription(ctx context.Context, input *ListFundsForSubscriptionInput) (*ListFundsForSubscriptionOutput, error) {
	output := ListFundsForSubscriptionOutput{}
	err := c.query(ctx, "list_funds_for_subscription", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) ListClientAccountBalance(ctx context.Context, input *ListClientAccountBalanceInput) (*ListClientAccountBalanceOutput, error) {
	output := ListClientAccountBalanceOutput{}
	err := c.query(ctx, "list_client_account_balance", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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
	ClientID  string  `json:"clientId,omitempty"`
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

func (c *Client) ListClientAccountRequests(ctx context.Context, input *ListClientAccountRequestsInput) (*ListClientAccountRequestsOutput, error) {
	output := ListClientAccountRequestsOutput{}
	err := c.query(ctx, "list_client_account_requests", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
}

type ListClientBankAccountsInput struct {
}

type ListClientBankAccountsOutput struct {
	BankAccounts []BankAccount `json:"bankAccounts"`
}

func (c *Client) ListClientBankAccounts(ctx context.Context, input *ListClientBankAccountsInput) (*ListClientBankAccountsOutput, error) {
	output := ListClientBankAccountsOutput{}
	err := c.query(ctx, "list_client_bank_accounts", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) ListDisplayCurrencies(ctx context.Context, input *ListDisplayCurrenciesInput) (*ListDisplayCurrenciesOutput, error) {
	output := ListDisplayCurrenciesOutput{}
	err := c.query(ctx, "list_display_currencies", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) ListClientSuitabilityAssessments(ctx context.Context, input *ListClientSuitabilityAssessmentsInput) (*ListClientSuitabilityAssessmentsOutput, error) {
	output := ListClientSuitabilityAssessmentsOutput{}
	err := c.query(ctx, "list_client_suitability_assessments", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) ListDuitNowBanks(ctx context.Context, input *ListDuitNowBanksInput) (*ListDuitNowBanksOutput, error) {
	output := ListDuitNowBanksOutput{}
	err := c.query(ctx, "list_duitnow_banks", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) ListInvestConsents(ctx context.Context, input *ListInvestConsentsInput) (*ListInvestConsentsOutput, error) {
	output := ListInvestConsentsOutput{}
	err := c.query(ctx, "list_invest_consents", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) ListBanks(ctx context.Context, input *ListBanksInput) (*ListBanksOutput, error) {
	output := ListBanksOutput{}
	err := c.query(ctx, "list_banks", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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
	ClientID   string    `json:"clientId,omitempty"`
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

func (c *Client) ListClientAccountMandateRequests(ctx context.Context, input *ListClientAccountMandateRequestsInput) (*ListClientAccountMandateRequestsOutput, error) {
	output := ListClientAccountMandateRequestsOutput{}
	err := c.query(ctx, "list_client_account_mandate_requests", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) ListClientPromos(ctx context.Context, input *ListClientPromosInput) (*ListClientPromosOutput, error) {
	output := ListClientPromosOutput{}
	err := c.query(ctx, "list_client_promos", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) ListClientAccountPerformance(ctx context.Context, input *ListClientAccountPerformanceInput) (*ListClientAccountPerformanceOutput, error) {
	output := ListClientAccountPerformanceOutput{}
	err := c.query(ctx, "list_client_account_performance", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
}

type ListPaymentMethodsInput struct {
}

type ListPaymentMethodsOutput struct {
	Duitnow      bool `json:"duitnow"`
	BankTransfer bool `json:"bankTransfer"`
}

func (c *Client) ListPaymentMethods(ctx context.Context, input *ListPaymentMethodsInput) (*ListPaymentMethodsOutput, error) {
	output := ListPaymentMethodsOutput{}
	err := c.query(ctx, "list_payment_methods", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) GetVoucher(ctx context.Context, input *GetVoucherInput) (*GetVoucherOutput, error) {
	output := GetVoucherOutput{}
	err := c.query(ctx, "get_voucher", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
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

func (c *Client) GetPreviewInvest(ctx context.Context, input *GetPreviewInvestInput) (*GetPreviewInvestOutput, error) {
	output := GetPreviewInvestOutput{}
	err := c.query(ctx, "get_preview_invest", input, &output)
	if err != nil {
		return nil, err
	}
	return &output, nil
}

//
// Commands
//
