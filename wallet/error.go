package wallet

const (
	// Error codes returned by the Wallet SDK
	//
	// ================================
	// AUTHENTICATION & AUTHORIZATION
	// ================================
	//
	// ErrExpiredApiKey is returned when the API key used in the request has expired.
	ErrExpiredApiKey string = "ErrExpiredApiKey"

	// ErrExpiredAuthToken is returned when the provided authentication token has expired.
	ErrExpiredAuthToken string = "ErrExpiredAuthToken"

	// ErrInsufficientAccess is returned when the client does not have sufficient permissions to perform this action.
	ErrInsufficientAccess string = "ErrInsufficientAccess"

	// ErrInvalidAuthSignature is returned when the request signature is invalid or cannot be verified.
	ErrInvalidAuthSignature string = "ErrInvalidAuthSignature"

	// ErrInvalidAuthToken is returned when the provided authentication token is malformed or invalid.
	ErrInvalidAuthToken string = "ErrInvalidAuthToken"

	// ErrInvalidPublicKey is returned when the supplied public key is invalid or does not match the expected format.
	ErrInvalidPublicKey string = "ErrInvalidPublicKey"

	// ErrUnauthorizedIPAddress is returned when the request originated from an IP address that is not authorized.
	ErrUnauthorizedIPAddress string = "ErrUnauthorizedIPAddress"

	// ================================
	// REQUEST VALIDATION
	// ================================
	//
	// ErrInvalidApiName is returned when the API name provided in the request is invalid.
	ErrInvalidApiName string = "ErrInvalidApiName"

	// ErrInvalidBodyFormat is returned when the request body is malformed or not in the expected format.
	ErrInvalidBodyFormat string = "ErrInvalidBodyFormat"

	// ErrInvalidHeader is returned when one or more required headers are missing or invalid.
	ErrInvalidHeader string = "ErrInvalidHeader"

	// ErrInvalidMethod is returned when the HTTP method used for the request is not supported for this endpoint.
	ErrInvalidMethod string = "ErrInvalidMethod"

	// ErrInvalidParameter is returned when a provided request parameter is invalid, incorrectly formatted, or violates constraints.
	ErrInvalidParameter string = "ErrInvalidParameter"

	// ErrInvalidPayload is returned when the payload structure or content does not meet the API requirements.
	ErrInvalidPayload string = "ErrInvalidPayload"

	// ErrMissingHeader is returned when a required request header is missing.
	ErrMissingHeader string = "ErrMissingHeader"

	// ErrMissingParameter is returned when a required request parameter is missing.
	ErrMissingParameter string = "ErrMissingParameter"

	// ================================
	// CSR (CERTIFICATE SIGNING REQUEST)
	// ================================
	//
	// ErrInvalidCSR is returned when the CSR is invalid or cannot be parsed.
	ErrInvalidCSR string = "ErrInvalidCSR"

	// ErrInvalidCSRFormat is returned when the CSR is not in a recognized or valid format.
	ErrInvalidCSRFormat string = "ErrInvalidCSRFormat"

	// ErrInvalidCSREllipticCurve is returned when the CSR contains an unsupported or invalid elliptic curve.
	ErrInvalidCSREllipticCurve string = "ErrInvalidCSREllipticCurve"

	// ErrInvalidCSRKeyLength is returned when the key length in the CSR does not meet the required security constraints.
	ErrInvalidCSRKeyLength string = "ErrInvalidCSRKeyLength"

	// ErrInvalidCSRKeyType is returned when the CSR contains an unsupported or invalid key type.
	ErrInvalidCSRKeyType string = "ErrInvalidCSRKeyType"

	// ErrInvalidCSRSignature is returned when the CSR signature cannot be verified or is invalid.
	ErrInvalidCSRSignature string = "ErrInvalidCSRSignature"

	// ================================
	// RESOURCE & ROUTING
	// ================================
	//
	// ErrAlreadyExists is returned when the requested resource already exists and cannot be created again.
	ErrAlreadyExists string = "ErrAlreadyExists"

	// ErrInvalidRoute is returned when the endpoint or route being called is invalid or not recognized.
	ErrInvalidRoute string = "ErrInvalidRoute"

	// ErrMissingResource is returned when the requested resource does not exist or cannot be found.
	ErrMissingResource string = "ErrMissingResource"

	// ================================
	// BUSINESS / DOMAIN RULES
	// ================================
	//
	// ErrActionNotAllowedForAccountType is returned when the account type does not support the requested action.
	ErrActionNotAllowedForAccountType string = "ErrActionNotAllowedForAccountType"

	// ErrActionOutsideFundHours is returned when the requested action cannot be performed outside of fund operating hours.
	ErrActionOutsideFundHours string = "ErrActionOutsideFundHours"

	// ErrDuitNow is returned when a DuitNow-specific error occurs (payment failed or unsupported scenario).
	ErrDuitNow string = "ErrDuitNow"

	// ErrInsufficientBalance is returned when the account does not have sufficient balance to complete the operation.
	ErrInsufficientBalance string = "ErrInsufficientBalance"

	// ErrInvalidAccountExperience is returned when the account’s experience level does not meet the requirements for this action.
	ErrInvalidAccountExperience string = "ErrInvalidAccountExperience"

	// ErrInvalidRequestPolicy is returned when the request violates one or more policy constraints.
	ErrInvalidRequestPolicy string = "ErrInvalidRequestPolicy"

	// ErrRequestCannotBeCancelled is returned when the request cannot be cancelled due to its current state or business rules.
	ErrRequestCannotBeCancelled string = "ErrRequestCannotBeCancelled"

	// ErrSuitabilityAssessmentMissingForAccountCreation is returned when a suitability assessment is required but missing during account creation.
	ErrSuitabilityAssessmentMissingForAccountCreation string = "ErrSuitabilityAssessmentMissingForAccountCreation"

	// ErrSuitabilityAssessmentRequired is returned when a suitability assessment must be completed before this action is allowed.
	ErrSuitabilityAssessmentRequired string = "ErrSuitabilityAssessmentRequired"

	// ================================
	// RATE LIMITING & CANCELLATIONS
	// ================================
	//
	// ErrCancelledRequest is returned when the request was cancelled before completion.
	ErrCancelledRequest string = "ErrCancelledRequest"

	// ErrRateLimitExceeded is returned when too many requests were made in a short period; rate limit exceeded.
	ErrRateLimitExceeded string = "ErrRateLimitExceeded"

	// ================================
	// SERVER / INFRASTRUCTURE
	// ================================
	//
	// ErrInternal is returned when an unexpected internal server error occurs.
	ErrInternal string = "ErrInternal"

	// ErrServiceUnavailable is returned when a 3rd-party service is temporarily unavailable; try again later.
	ErrServiceUnavailable string = "ErrServiceUnavailable"
)

type Error struct {
	StatusCode int    `json:"statusCode"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

func (e Error) Error() string {
	return e.Message
}
