package redsys

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test3DESEncryptionAndDecryption(t *testing.T) {
	const KEY = "Mk9m98IfEblmPfrpsawt7BmxObt98Jev"
	const DS_MERCHANT_ORDER = "1"
	const ENCRYPTED_TEXT = "Lr6bLJYWKrk="

	redsys := Redsys{Key: KEY}

	assert.Equal(t, ENCRYPTED_TEXT, redsys.encrypt3DES(DS_MERCHANT_ORDER), "Encryption result should be qual to "+ENCRYPTED_TEXT)

	assert.Equal(t, DS_MERCHANT_ORDER, redsys.decrypt3DES(ENCRYPTED_TEXT), "Decryption result should be qual to "+DS_MERCHANT_ORDER)

}

func TestSHA256Algorithm(t *testing.T) {
	const PARAMS = "eyJEU19NRVJDSEFOVF9BTU9VTlQiOiIxNDUiLCJEU19NRVJDSEFOVF9PUkRFUiI6IjEiLCJEU19NRVJDSEFOVF9NRVJDSEFOVENPREUiOiI5OTkwMDg4ODEiLCJEU19NRVJDSEFOVF9DVVJSRU5DWSI6Ijk3OCIsIkRTX01FUkNIQU5UX1RSQU5TQUNUSU9OVFlQRSI6IjAiLCJEU19NRVJDSEFOVF9URVJNSU5BTCI6Ijg3MSIsIkRTX01FUkNIQU5UX01FUkNIQU5UVVJMIjoiIiwiRFNfTUVSQ0hBTlRfVVJMT0siOiIiLCJEU19NRVJDSEFOVF9VUkxLTyI6IiJ9"
	const SIGNATURE = "3TEI5WyvHf1D/whByt1ENgFH/HPIP9UFuB6LkCYgj+E="
	const ENCRYPTED_KEY = "Lr6bLJYWKrk="

	redsys := Redsys{}
	assert.Equal(t, SIGNATURE, redsys.mac256(PARAMS, ENCRYPTED_KEY), "SHA256 result should be qual to "+SIGNATURE)
}

func TestMechantEncodingAndDecoding(t *testing.T) {
	const PARAMS = "eyJEc19NZXJjaGFudF9NZXJjaGFudENvZGUiOiI5OTkwMDg4ODEiLCJEc19NZXJjaGFudF9UZXJtaW5hbCI6Ijg3MSIsIkRzX01lcmNoYW50X1RyYW5zYWN0aW9uVHlwZSI6IjAiLCJEc19NZXJjaGFudF9BbW91bnQiOiIxNDUiLCJEc19NZXJjaGFudF9DdXJyZW5jeSI6Ijk3OCIsIkRzX01lcmNoYW50X09yZGVyIjoiMSJ9"
	// Uses Ds_Language, not Ds_ConsumerLanguage: confirmed against two
	// independent real Redsys payloads (a captured production refund
	// response, and Redsys's own PayGold REST documentation) that this is
	// the field name Redsys actually sends.
	const DS_MERCHANT_PARAMETERS = "eyJEc19EYXRlIjoiMDklMkYxMSUyRjIwMTUiLCJEc19Ib3VyIjoiMTglM0EwMyIsIkRzX1NlY3VyZVBheW1lbnQiOiIwIiwiRHNfQ2FyZF9Db3VudHJ5IjoiNzI0IiwiRHNfQW1vdW50IjoiMTQ1IiwiRHNfQ3VycmVuY3kiOiI5NzgiLCJEc19PcmRlciI6IjAwNjkiLCJEc19NZXJjaGFudENvZGUiOiI5OTkwMDg4ODEiLCJEc19UZXJtaW5hbCI6Ijg3MSIsIkRzX1Jlc3BvbnNlIjoiMDAwMCIsIkRzX01lcmNoYW50RGF0YSI6IiIsIkRzX1RyYW5zYWN0aW9uVHlwZSI6IjAiLCJEc19MYW5ndWFnZSI6IjEiLCJEc19BdXRob3Jpc2F0aW9uQ29kZSI6IjA4MjE1MCJ9"

	merchantParamsRequest := &MerchantParametersRequest{
		MerchantAmount:          "145",
		MerchantOrder:           "1",
		MerchantMerchantCode:    "999008881",
		MerchantCurrency:        "978",
		MerchantTransactionType: "0",
		MerchantTerminal:        "871",
		MerchantMerchantUrl:     "",
		MerchantUrlOK:           "",
		MerchantUrlKO:           "",
	}

	merchantParams := MerchantParametersResponse{
		Date:              "09/11/2015",
		Hour:              "18:03",
		SecurePayment:     "0",
		CardCountry:       "724",
		Amount:            "145",
		Currency:          "978",
		Order:             "0069",
		MerchantCode:      "999008881",
		Terminal:          "871",
		Response:          "0000",
		MerchantData:      "",
		TransactionType:   "0",
		ConsumerLanguage:  "1",
		AuthorisationCode: "082150",
	}

	redsys := Redsys{}

	assert.Equal(t, PARAMS, redsys.CreateMerchantParameters(merchantParamsRequest), "Create Merchant Parameters "+PARAMS)
	assert.Equal(t, merchantParams, redsys.DecodeMerchantParameters(DS_MERCHANT_PARAMETERS), "Decode Merchant Parameters "+PARAMS)
}

func TestDecodeMerchantParameters_DCCLiteralPercentDoesNotCorruptOtherFields(t *testing.T) {
	// Captured from a real Redsys refund response for a foreign-currency
	// (DCC) card. Ds_Markup_DCC contains a literal "0.0%" - a bare "%" not
	// followed by two hex digits - which previously made url.QueryUnescape
	// fail on the whole payload and silently zero out every field, including
	// Ds_Response (masking a successful refund as a failure).
	const dccMerchantParameters = "eyJEc19BbW91bnQiOiIzNjAwIiwiRHNfQ3VycmVuY3kiOiI5NzgiLCJEc19PcmRlciI6IjI2MDYwMWJrazdwZyIsIkRzX01lcmNoYW50Q29kZSI6IjM2MzE0NzU1NCIsIkRzX1Rlcm1pbmFsIjoiMiIsIkRzX1Jlc3BvbnNlIjoiMDkwMCIsIkRzX0F1dGhvcmlzYXRpb25Db2RlIjoiMDIxMDc2IiwiRHNfVHJhbnNhY3Rpb25UeXBlIjoiMyIsIkRzX1NlY3VyZVBheW1lbnQiOiIyIiwiRHNfTGFuZ3VhZ2UiOiIxIiwiRHNfTWVyY2hhbnREYXRhIjoiIiwiRHNfQ2FyZF9Db3VudHJ5IjoiODI2IiwiRHNfQ2FyZF9UeXBvbG9neSI6IkNPTlNVTU8iLCJEc19DYXJkX0JyYW5kIjoiMiIsIkRzX1Byb2Nlc3NlZFBheU1ldGhvZCI6Ijc5IiwiRHNfQ3VycmVuY3lfRENDIjoiODI2IiwiRHNfQW1vdW50X0RDQyI6IjMyODIiLCJEc19DdXJyZW5jeU5hbWVfRENDIjoiUE9VTkQgU1RFUkxJTkciLCJEc19NYXJrdXBfRENDIjoiMC4wJSIsIkRzX0V4Y2hhbmdlUmF0ZV9EQ0MiOiIxLjA5Njk1MSJ9"

	redsys := Redsys{}
	result := redsys.DecodeMerchantParameters(dccMerchantParameters)

	assert.Equal(t, "0900", result.Response, "a successful refund must decode with its real response code")
	assert.Equal(t, "260601bkk7pg", result.Order)
	assert.Equal(t, "021076", result.AuthorisationCode)
	assert.Equal(t, "3", result.TransactionType)
	assert.Equal(t, "3600", result.Amount)
	assert.Equal(t, "978", result.Currency)
}

func TestMerchantSignature(t *testing.T) {
	const KEY = "Mk9m98IfEblmPfrpsawt7BmxObt98Jev"

	merchantParamsRequest := &MerchantParametersRequest{
		MerchantAmount:          "145",
		MerchantOrder:           "1",
		MerchantMerchantCode:    "999008881",
		MerchantCurrency:        "978",
		MerchantTransactionType: "0",
		MerchantTerminal:        "871",
		MerchantMerchantUrl:     "",
		MerchantUrlOK:           "",
		MerchantUrlKO:           "",
	}
	redsys := Redsys{Key: KEY}
	const SIGNATURE = "FyetupQY42l5OuaBpazgN//z9veH6txWsUiYIAKE4FY="
	assert.Equal(t, SIGNATURE, redsys.CreateMerchantSignature(merchantParamsRequest), "Create Merchant Signature "+SIGNATURE)

	const RESPONSE_DS_MERCHANT_PARAMETERS = "eyJEc19EYXRlIjoiMDklMkYxMSUyRjIwMTUiLCJEc19Ib3VyIjoiMTglM0EwMyIsIkRzX1NlY3VyZVBheW1lbnQiOiIwIiwiRHNfQ2FyZF9Db3VudHJ5IjoiNzI0IiwiRHNfQW1vdW50IjoiMTQ1IiwiRHNfQ3VycmVuY3kiOiI5NzgiLCJEc19PcmRlciI6IjAwNjkiLCJEc19NZXJjaGFudENvZGUiOiI5OTkwMDg4ODEiLCJEc19UZXJtaW5hbCI6Ijg3MSIsIkRzX1Jlc3BvbnNlIjoiMDAwMCIsIkRzX01lcmNoYW50RGF0YSI6IiIsIkRzX1RyYW5zYWN0aW9uVHlwZSI6IjAiLCJEc19MYW5ndWFnZSI6IjEiLCJEc19BdXRob3Jpc2F0aW9uQ29kZSI6IjA4MjE1MCJ9"
	const RESPONSE_DS_SIGNATURE = "qhEoh2tAh4HowkMaEvfga-axsK0ytFFwv5YZ6Lx6Rjk="
	assert.Equal(t, RESPONSE_DS_SIGNATURE, redsys.CreateMerchantSignatureNotif(RESPONSE_DS_MERCHANT_PARAMETERS), "Create Merchant Signature Notification "+RESPONSE_DS_SIGNATURE)

	assert.Equal(t, bool(true), redsys.MerchantSignatureIsValid(RESPONSE_DS_SIGNATURE, RESPONSE_DS_SIGNATURE), "Create Merchant Signature Notification")
}

// TestDiversifyKeyAES_RedsysPublishedExample is a known-answer test using the
// exact worked example published on Redsys's "Firmar una operación" page:
// https://pagosonline.redsys.es/desarrolladores-inicio/documentacion-operativa/firmar-una-operacion/
func TestDiversifyKeyAES_RedsysPublishedExample(t *testing.T) {
	const KEY = "sq7HjrUOBfKmC576ILgskD5srU870gJ7"
	const ORDER = "1234567890"
	const EXPECTED_DIVERSIFIED_KEY = "RWt3/IPTzYRMXsQtkiGRKg=="

	diversifiedKey, err := diversifyKeyAES(KEY, ORDER)

	assert.NoError(t, err)
	assert.Equal(t, EXPECTED_DIVERSIFIED_KEY, diversifiedKey)
}

// TestMAC512_RedsysPublishedExample is a known-answer test for the
// HMAC_SHA512_V2 signature, using the same page's full worked example
// (a REST refund request, using the diversified key from the test above).
// This intentionally calls mac512 directly with the doc's own literal
// Ds_MerchantParameters string, rather than going through
// CreateMerchantSignature512(*MerchantParametersRequest): that function signs
// whatever CreateMerchantParameters produces, which uses padded base64url
// (base64.URLEncoding) — Redsys's own example string is unpadded, so the two
// won't byte-match even with a correct implementation.
func TestMAC512_RedsysPublishedExample(t *testing.T) {
	const DIVERSIFIED_KEY = "RWt3/IPTzYRMXsQtkiGRKg=="
	const MERCHANT_PARAMETERS = "eyJEU19NRVJDSEFOVF9BTU9VTlQiOiI5OTkiLCJEU19NRVJDSEFOVF9PUkRFUiI6IjEyMzQ1Njc4OTAiLCJEU19NRVJDSEFOVF9NRVJDSEFOVENPREUiOiI5OTkwMDg4ODEiLCJEU19NRVJDSEFOVF9DVVJSRU5DWSI6Ijk3OCIsIkRTX01FUkNIQU5UX1RSQU5TQUNUSU9OVFlQRSI6IjAiLCJEU19NRVJDSEFOVF9URVJNSU5BTCI6IjEiLCJEU19NRVJDSEFOVF9NRVJDSEFOVFVSTCI6Imh0dHA6XC9cL3d3dy5wcnVlYmEuY29tXC91cmxOb3RpZmljYWNpb24ucGhwIiwiRFNfTUVSQ0hBTlRfVVJMT0siOiJodHRwOlwvXC93d3cucHJ1ZWJhLmNvbVwvdXJsT0sucGhwIiwiRFNfTUVSQ0hBTlRfVVJMS08iOiJodHRwOlwvXC93d3cucHJ1ZWJhLmNvbVwvdXJsS08ucGhwIn0"
	const EXPECTED_SIGNATURE = "Vjo02eSWq249IeZZp3R-ArFnGLhKY0OuzDDlx1BuVtZDC2yhczA7_11uZhsYzLZBCMFAz8u8uzGDX3AErHKmmw"

	assert.Equal(t, EXPECTED_SIGNATURE, mac512(MERCHANT_PARAMETERS, DIVERSIFIED_KEY))
}

// TestCreateMerchantSignature512_IsDeterministicAndErrorFree is a
// self-consistency check for the full public API (see the KATs above for
// why this can't be a known-answer test against the doc example directly).
func TestCreateMerchantSignature512_IsDeterministicAndErrorFree(t *testing.T) {
	redsys := Redsys{Key: "Mk9m98IfEblmPfrpsawt7BmxObt98Jev"}
	params := &MerchantParametersRequest{
		MerchantAmount:          "145",
		MerchantOrder:           "1",
		MerchantMerchantCode:    "999008881",
		MerchantCurrency:        "978",
		MerchantTransactionType: "0",
		MerchantTerminal:        "871",
	}

	signature1, err := redsys.CreateMerchantSignature512(params)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature1)

	signature2, err := redsys.CreateMerchantSignature512(params)
	assert.NoError(t, err)
	assert.Equal(t, signature1, signature2)
}

func TestTryDecodeMerchantParameters_ErrorsOnMalformedInput(t *testing.T) {
	redsys := Redsys{}

	_, err := redsys.TryDecodeMerchantParameters("not-valid-base64!!!")
	assert.Error(t, err)

	// Valid base64url, but not valid JSON once decoded.
	notJSON := base64.URLEncoding.EncodeToString([]byte("this is not json"))
	_, err = redsys.TryDecodeMerchantParameters(notJSON)
	assert.Error(t, err)
}

func TestMerchantParametersRequest_XPayFieldsOmittedWhenEmpty(t *testing.T) {
	redsys := Redsys{}
	params := &MerchantParametersRequest{
		MerchantAmount:       "145",
		MerchantOrder:        "1",
		MerchantMerchantCode: "999008881",
	}

	decoded, err := base64.URLEncoding.DecodeString(redsys.CreateMerchantParameters(params))
	assert.NoError(t, err)
	assert.NotContains(t, string(decoded), "DS_XPAYDATA")
	assert.NotContains(t, string(decoded), "DS_XPAYTYPE")
	assert.NotContains(t, string(decoded), "DS_XPAYORIGEN")

	params.XPayData = "encrypted-token"
	params.XPayType = "Apple"
	params.XPayOrigen = "WEB"

	decoded, err = base64.URLEncoding.DecodeString(redsys.CreateMerchantParameters(params))
	assert.NoError(t, err)
	assert.Contains(t, string(decoded), `"DS_XPAYDATA":"encrypted-token"`)
	assert.Contains(t, string(decoded), `"DS_XPAYTYPE":"Apple"`)
	assert.Contains(t, string(decoded), `"DS_XPAYORIGEN":"WEB"`)
}

// TestDecodeMerchantParameters_AcceptsStandardBase64 covers a real gap: Redsys
// documents Ds_MerchantParameters as Base64URL, but inbound notifications have
// been observed using the standard alphabet ('+'/'/' instead of '-'/'_').
// Since a base64 string of realistic length (~300+ chars) almost always
// contains one of those characters, guessing the wrong alphabet doesn't fail
// occasionally - it fails on nearly every real payload. This fixture is
// base64.StdEncoding-encoded and deliberately contains both '+' and '/', so a
// URLEncoding-only decode (the previous behavior) cannot parse it.
func TestDecodeMerchantParameters_AcceptsStandardBase64(t *testing.T) {
	const jsonPayload = `{"Ds_Order": "k9k>9d?ai", "Ds_Response": "0000", "Ds_Amount": "999999999999999999"}`
	stdEncoded := base64.StdEncoding.EncodeToString([]byte(jsonPayload))

	if !strings.Contains(stdEncoded, "+") && !strings.Contains(stdEncoded, "/") {
		t.Fatal("fixture must exercise the standard base64 alphabet")
	}

	_, urlDecodeErr := base64.URLEncoding.DecodeString(stdEncoded)
	assert.Error(t, urlDecodeErr, "fixture must be unparseable as base64url, or this test proves nothing")

	redsys := Redsys{}
	result, err := redsys.TryDecodeMerchantParameters(stdEncoded)

	assert.NoError(t, err)
	assert.Equal(t, "k9k>9d?ai", result.Order)
	assert.Equal(t, "0000", result.Response)
	assert.Equal(t, "999999999999999999", result.Amount)
}

// TestMerchantParametersRequest_PayGold covers the fields confirmed against
// Redsys's PayGold-vía-REST documentation: https://pagosonline.redsys.es/desarrolladores-inicio/documentacion-tipos-de-integracion/desarrolladores-paygold/paygold-rest/
func TestMerchantParametersRequest_PayGold(t *testing.T) {
	redsys := Redsys{}
	params := &MerchantParametersRequest{
		MerchantAmount:          "145",
		MerchantOrder:           "1",
		MerchantMerchantCode:    "999008881",
		MerchantTransactionType: TransactionTypePayGold,
	}

	decoded, err := base64.URLEncoding.DecodeString(redsys.CreateMerchantParameters(params))
	assert.NoError(t, err)
	assert.Contains(t, string(decoded), `"Ds_Merchant_TransactionType":"F"`)
	assert.NotContains(t, string(decoded), "Ds_Merchant_Customer_Mobile")
	assert.NotContains(t, string(decoded), "Ds_Merchant_Identifier")

	params.MerchantCustomerMobile = "666555444"
	params.MerchantCustomerMail = "cliente@example.com"
	params.MerchantP2FExpiryDate = "2014-12-26-16.31.35.318"
	params.MerchantCustomerSMSText = "Pay here: @URL@"
	params.MerchantP2FXMLData = "<nombreComprador>Jane Doe</nombreComprador>"
	params.MerchantIdentifier = "REQUIRED"

	decoded, err = base64.URLEncoding.DecodeString(redsys.CreateMerchantParameters(params))
	assert.NoError(t, err)
	assert.Contains(t, string(decoded), `"Ds_Merchant_Customer_Mobile":"666555444"`)
	assert.Contains(t, string(decoded), `"Ds_Merchant_Customer_Mail":"cliente@example.com"`)
	assert.Contains(t, string(decoded), `"Ds_Merchant_P2F_ExpiryDate":"2014-12-26-16.31.35.318"`)
	assert.Contains(t, string(decoded), `"Ds_Merchant_Customer_Sms_Text":"Pay here: @URL@"`)
	assert.Contains(t, string(decoded), `"Ds_Merchant_P2F_XMLData"`)
	assert.Contains(t, string(decoded), `"Ds_Merchant_Identifier":"REQUIRED"`)
}

// TestDecodeMerchantParameters_PayGoldResponse decodes a PayGold link
// generation response shaped after Redsys's own documented example, checking
// URLPago2Fases (the payment link) decodes correctly. Ds_AuthorisationCode is
// blank in this example because the link has been generated but not yet paid.
// TestMerchantParametersRequest_InSite covers the InSite operation-id field
// used to finalize an InSite payment via a REST request: the field is only
// present in the encoded payload when set (an InSite REST call needs it, a
// plain authorization/refund/PayGold call does not), and signing goes
// through the same CreateMerchantSignature512 path as every other request.
func TestMerchantParametersRequest_InSite(t *testing.T) {
	redsys := Redsys{}
	params := &MerchantParametersRequest{
		MerchantAmount:          "145",
		MerchantOrder:           "1",
		MerchantMerchantCode:    "999008881",
		MerchantCurrency:        "978",
		MerchantTerminal:        "1",
		MerchantTransactionType: "0",
	}

	decoded, err := base64.URLEncoding.DecodeString(redsys.CreateMerchantParameters(params))
	assert.NoError(t, err)
	assert.NotContains(t, string(decoded), "DS_MERCHANT_IDOPER")

	params.MerchantIdOper = "0123456789abcdef0123456789abcdef01234567"

	decoded, err = base64.URLEncoding.DecodeString(redsys.CreateMerchantParameters(params))
	assert.NoError(t, err)
	assert.Contains(t, string(decoded), `"DS_MERCHANT_IDOPER":"0123456789abcdef0123456789abcdef01234567"`)
}

func TestDecodeMerchantParameters_PayGoldResponse(t *testing.T) {
	redsys := Redsys{}
	payload := `{"Ds_Amount":"145","Ds_AuthorisationCode":"","Ds_Currency":"978","Ds_MerchantCode":"999008881","Ds_MerchantData":"","Ds_Order":"1453971987","Ds_Response":"9998","Ds_SecurePayment":"0","Ds_Terminal":"1","Ds_TransactionType":"F","Ds_UrlPago2Fases":"http://sis-d.redsys.es/sis/p2f?t=B8792FD81101EDE46101FC154918EFDD0FDE4CD7"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))

	result, err := redsys.TryDecodeMerchantParameters(encoded)

	assert.NoError(t, err)
	assert.Equal(t, "http://sis-d.redsys.es/sis/p2f?t=B8792FD81101EDE46101FC154918EFDD0FDE4CD7", result.URLPago2Fases)
	assert.Equal(t, "F", result.TransactionType)
	assert.Equal(t, "", result.AuthorisationCode)
}

// TestDecodeMerchantParameters_PayGoldPaidNotification decodes the online
// notification Redsys sends once a customer actually pays a PayGold link,
// verbatim from Redsys's PayGold-via-REST documentation. Confirms
// Ds_CardNumber/Ds_Card_Brand/Ds_ExpiryDate (missing before this fix) and
// Ds_Language (previously mistagged as Ds_ConsumerLanguage) all decode.
func TestDecodeMerchantParameters_PayGoldPaidNotification(t *testing.T) {
	redsys := Redsys{}
	payload := `{"Ds_Amount":"145","Ds_AuthorisationCode":"630117","Ds_CardNumber":"454881******0003","Ds_Card_Brand":"1","Ds_Card_Country":"724","Ds_Currency":"978","Ds_ExpiryDate":"3912","Ds_Language":"1","Ds_MerchantCode":"999008881","Ds_Merchant_Identifier":"01903f9b923895767228066924f23b5892e88fdb","Ds_Order":"0281WjRq","Ds_Response":"0000","Ds_SecurePayment":"0","Ds_Terminal":"1","Ds_TransactionType":"F"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))

	result, err := redsys.TryDecodeMerchantParameters(encoded)

	assert.NoError(t, err)
	assert.Equal(t, "0000", result.Response)
	assert.Equal(t, "630117", result.AuthorisationCode)
	assert.Equal(t, "454881******0003", result.CardNumber)
	assert.Equal(t, "1", result.CardBrand)
	assert.Equal(t, "3912", result.ExpiryDate)
	assert.Equal(t, "1", result.ConsumerLanguage)
	assert.Equal(t, "01903f9b923895767228066924f23b5892e88fdb", result.MerchantIdentifier)
}

// TestCreateMerchantSignatureNotif512_UnpaddedNotification covers HMAC_SHA512_V2
// notifications, which Redsys sends with Ds_MerchantParameters in unpadded
// base64 (like its own published example above). A padded-only decode cannot
// read Ds_Order from them whenever the length is not a multiple of 4, so the
// key could not be diversified and every such notification was rejected.
func TestCreateMerchantSignatureNotif512_UnpaddedNotification(t *testing.T) {
	const KEY = "sq7HjrUOBfKmC576ILgskD5srU870gJ7"
	const ORDER = "261114a5ikq0"

	payload := `{"Ds_Order":"` + ORDER + `","Ds_Response":"0000","Ds_Amount":"33000","Ds_Hour":"10%3A42"}`
	data := base64.RawURLEncoding.EncodeToString([]byte(payload))

	if len(data)%4 == 0 {
		t.Fatal("fixture must need padding, or this test proves nothing")
	}

	_, paddedErr := base64.URLEncoding.DecodeString(data)
	assert.Error(t, paddedErr, "fixture must be unparseable as padded base64url")

	redsys := Redsys{Key: KEY}

	decoded, err := redsys.TryDecodeMerchantParameters(data)
	assert.NoError(t, err)
	assert.Equal(t, ORDER, decoded.Order)
	assert.Equal(t, "10:42", decoded.Hour)

	diversifiedKey, err := diversifyKeyAES(KEY, ORDER)
	assert.NoError(t, err)

	signature, err := redsys.CreateMerchantSignatureNotif512(data)
	assert.NoError(t, err)
	assert.Equal(t, mac512(data, diversifiedKey), signature, "the signature covers the string as transmitted")
}

// TestDecodeMerchantParameters_AcceptsUnpaddedStandardBase64 covers the
// standard alphabet without padding.
func TestDecodeMerchantParameters_AcceptsUnpaddedStandardBase64(t *testing.T) {
	const jsonPayload = `{"Ds_Order": "k9k>9d?ai", "Ds_Response": "0000", "Ds_Amount": "99999999999999999"}`
	data := base64.RawStdEncoding.EncodeToString([]byte(jsonPayload))

	if len(data)%4 == 0 || !strings.ContainsAny(data, "+/") {
		t.Fatal("fixture must be unpadded standard base64")
	}

	redsys := Redsys{}
	result, err := redsys.TryDecodeMerchantParameters(data)

	assert.NoError(t, err)
	assert.Equal(t, "k9k>9d?ai", result.Order)
}
