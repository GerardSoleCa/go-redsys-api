package redsys

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// SignatureVersionSHA512 is the Ds_SignatureVersion value for the current
// Redsys signing standard (AES-128-CBC key diversification + HMAC-SHA512),
// produced by CreateMerchantSignature512 / CreateMerchantSignatureNotif512.
const SignatureVersionSHA512 = "HMAC_SHA512_V2"

// TransactionTypePayGold is the Ds_Merchant_TransactionType value that
// requests a PayGold payment link via a REST request to trataPeticionREST,
// instead of a normal authorization.
const TransactionTypePayGold = "F"

// Redsys signs and verifies Ds_MerchantParameters payloads using a merchant's
// terminal key. Key is the base64-encoded key Redsys's Admin Portal gives you
// for a merchant code + terminal pair. The zero value is usable directly
// (Redsys{Key: "..."}); NewRedsys additionally validates the key up front,
// trading a possible later panic for an early, explicit error.
//
// A single Redsys value works for both signature versions - which one you
// get depends only on which method you call (CreateMerchantSignature512 vs
// the legacy CreateMerchantSignature).
type Redsys struct {
	Key string
}

// NewRedsys validates key up front and returns an error instead of the panic
// that a malformed key would otherwise cause later, inside a signing call.
// It does not change the behavior of the Redsys{Key: ...} literal form.
func NewRedsys(key string) (*Redsys, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}

	return &Redsys{Key: key}, nil
}

// CreateMerchantParameters marshals data to JSON and base64url-encodes it,
// ready to send as Ds_MerchantParameters. Sign the returned string with
// CreateMerchantSignature512 (or CreateMerchantSignature for the legacy
// scheme) to get the accompanying Ds_Signature.
func (r *Redsys) CreateMerchantParameters(data *MerchantParametersRequest) string {
	merchantMarshalledParams, _ := json.Marshal(data)
	return base64.URLEncoding.EncodeToString(merchantMarshalledParams)
}

// DecodeMerchantParameters decodes a Ds_MerchantParameters payload (from a
// response or an online notification) into a MerchantParametersResponse.
// Decode/unmarshal errors are swallowed, silently returning a zero-value
// response - use TryDecodeMerchantParameters when you need to detect them.
func (r *Redsys) DecodeMerchantParameters(data string) MerchantParametersResponse {
	merchantParameters := MerchantParametersResponse{}
	decodedB64, _ := decodeBase64Either(data)
	json.Unmarshal(decodedB64, &merchantParameters)
	unescapeInPlace(&merchantParameters)
	return merchantParameters
}

// TryDecodeMerchantParameters is DecodeMerchantParameters, but surfaces
// base64/JSON decode failures instead of silently returning a zero-value
// MerchantParametersResponse.
func (r *Redsys) TryDecodeMerchantParameters(data string) (MerchantParametersResponse, error) {
	merchantParameters := MerchantParametersResponse{}

	decodedB64, err := decodeBase64Either(data)
	if err != nil {
		return MerchantParametersResponse{}, fmt.Errorf("redsys: decode base64: %w", err)
	}

	if err := json.Unmarshal(decodedB64, &merchantParameters); err != nil {
		return MerchantParametersResponse{}, fmt.Errorf("redsys: unmarshal merchant parameters: %w", err)
	}

	unescapeInPlace(&merchantParameters)
	return merchantParameters, nil
}

// decodeBase64Either decodes data as base64url first, falling back to
// standard base64. Redsys documents Ds_MerchantParameters as Base64URL for
// what a merchant sends, but real inbound notifications have been observed
// using the standard alphabet - and since a ~300+ char base64 string almost
// always contains a '+' or '/' (or '-'/'_'), guessing wrong reliably breaks
// decoding rather than occasionally. This only affects parsing the JSON
// fields (used here to extract Ds_Order for key diversification); it must
// never be used on the string that gets signed/verified - Redsys's own docs
// are explicit that the signature covers the base64 parameter exactly as
// transmitted, undecoded.
//
// Padding is optional too: HMAC_SHA512_V2 notifications arrive without the
// trailing '=' (like the V2 signature itself), so a padded-only decode fails
// whenever the length is not a multiple of 4 and the signature can then never
// be verified. The trailing '=' are dropped and the raw (unpadded) encodings
// used, which accept both forms.
func decodeBase64Either(data string) ([]byte, error) {
	unpadded := strings.TrimRight(data, "=")

	if decoded, err := base64.RawURLEncoding.DecodeString(unpadded); err == nil {
		return decoded, nil
	}

	return base64.RawStdEncoding.DecodeString(unpadded)
}

// unescapeInPlace reverses Redsys's per-field percent-encoding (seen on fields
// like Ds_Date "09%2F11%2F2015" and Ds_Hour "18%3A03"). It must run per-field,
// after JSON parsing, not on the whole blob beforehand: some fields legitimately
// contain a literal "%" that is not a valid escape sequence (e.g. DCC's
// Ds_Markup_DCC "0.0%"), and unescaping the whole JSON string at once lets one
// such field corrupt every other field silently.
func unescapeInPlace(m *MerchantParametersResponse) {
	fields := []*string{
		&m.Date, &m.Hour, &m.SecurePayment, &m.CardCountry, &m.Amount,
		&m.Currency, &m.Order, &m.MerchantCode, &m.Terminal, &m.Response,
		&m.MerchantData, &m.TransactionType, &m.ConsumerLanguage, &m.AuthorisationCode,
	}
	for _, f := range fields {
		if unescaped, err := url.QueryUnescape(*f); err == nil {
			*f = unescaped
		}
	}
}

// CreateMerchantSignature generates a merchant signature from
// MerchantParametersRequest using the legacy Redsys signing standard
// (3DES key diversification + HMAC-SHA256, Ds_SignatureVersion
// HMAC_SHA256_V1). Prefer CreateMerchantSignature512 for new integrations;
// this is kept for merchants not yet migrated to HMAC_SHA512_V2.
func (r *Redsys) CreateMerchantSignature(data *MerchantParametersRequest) string {
	stringMerchantParameters := r.CreateMerchantParameters(data)

	orderID := data.MerchantOrder

	encrypted := r.encrypt3DES(orderID)
	return r.mac256(stringMerchantParameters, encrypted)
}

// CreateMerchantSignatureNotif generates the legacy HMAC_SHA256_V1 signature
// for a MerchantParametersResponse-representing string (a response or online
// notification's Ds_MerchantParameters), for verification against a received
// Ds_Signature via MerchantSignatureIsValid.
func (r *Redsys) CreateMerchantSignatureNotif(data string) string {
	merchantParametersResponse := r.DecodeMerchantParameters(data)

	orderID := merchantParametersResponse.Order
	encrypted := r.encrypt3DES(orderID)
	mac := r.mac256(data, encrypted)

	decodedMac, _ := base64.StdEncoding.DecodeString(mac)
	return base64.URLEncoding.EncodeToString(decodedMac)
}

// MerchantSignatureIsValid reports whether a received Ds_Signature matches
// one you computed (via CreateMerchantSignatureNotif or
// CreateMerchantSignatureNotif512, matching whichever Ds_SignatureVersion the
// sender used), using a constant-time comparison. Order of arguments does
// not matter.
func (r *Redsys) MerchantSignatureIsValid(mac1 string, mac2 string) bool {
	return hmac.Equal([]byte(mac1), []byte(mac2))
}

// CreateMerchantSignature512 generates a merchant signature from
// MerchantParametersRequest using the current Redsys signing standard
// (AES-128-CBC key diversification + HMAC-SHA512, Ds_SignatureVersion
// HMAC_SHA512_V2), verified against Redsys's own published worked example.
// Send it alongside Ds_SignatureVersion: SignatureVersionSHA512.
func (r *Redsys) CreateMerchantSignature512(data *MerchantParametersRequest) (string, error) {
	stringMerchantParameters := r.CreateMerchantParameters(data)

	diversifiedKey, err := diversifyKeyAES(r.Key, data.MerchantOrder)
	if err != nil {
		return "", fmt.Errorf("redsys: diversify key: %w", err)
	}

	return mac512(stringMerchantParameters, diversifiedKey), nil
}

// CreateMerchantSignatureNotif512 generates a signature for a
// MerchantParametersResponse representing string using the current Redsys
// signing standard (AES-128-CBC key diversification + HMAC-SHA512), for
// verifying an inbound notification signed with Ds_SignatureVersion
// HMAC_SHA512_V2.
func (r *Redsys) CreateMerchantSignatureNotif512(data string) (string, error) {
	merchantParametersResponse, err := r.TryDecodeMerchantParameters(data)
	if err != nil {
		return "", err
	}

	diversifiedKey, err := diversifyKeyAES(r.Key, merchantParametersResponse.Order)
	if err != nil {
		return "", fmt.Errorf("redsys: diversify key: %w", err)
	}

	return mac512(data, diversifiedKey), nil
}
