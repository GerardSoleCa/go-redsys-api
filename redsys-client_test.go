package redsys

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test3DESEncryptionAndDecryption(t *testing.T) {
	const KEY = "Mk9m98IfEblmPfrpsawt7BmxObt98Jev"
	const DS_MERCHANT_ORDER = "1"
	const ENCRYPTED_TEXT = "Lr6bLJYWKrk="

	redsys := Redsys{Key:KEY}

	assert.Equal(t, redsys.encrypt3DES(DS_MERCHANT_ORDER), ENCRYPTED_TEXT, "Encryption result should be qual to " + ENCRYPTED_TEXT)

	assert.Equal(t, redsys.decrypt3DES(ENCRYPTED_TEXT), DS_MERCHANT_ORDER, "Decryption result should be qual to " + DS_MERCHANT_ORDER)

}

func TestSHA256Algorithm(t *testing.T) {
	const PARAMS = "eyJEU19NRVJDSEFOVF9BTU9VTlQiOiIxNDUiLCJEU19NRVJDSEFOVF9PUkRFUiI6IjEiLCJEU19NRVJDSEFOVF9NRVJDSEFOVENPREUiOiI5OTkwMDg4ODEiLCJEU19NRVJDSEFOVF9DVVJSRU5DWSI6Ijk3OCIsIkRTX01FUkNIQU5UX1RSQU5TQUNUSU9OVFlQRSI6IjAiLCJEU19NRVJDSEFOVF9URVJNSU5BTCI6Ijg3MSIsIkRTX01FUkNIQU5UX01FUkNIQU5UVVJMIjoiIiwiRFNfTUVSQ0hBTlRfVVJMT0siOiIiLCJEU19NRVJDSEFOVF9VUkxLTyI6IiJ9"
	const SIGNATURE = "3TEI5WyvHf1D/whByt1ENgFH/HPIP9UFuB6LkCYgj+E="
	const ENCRYPTED_KEY = "Lr6bLJYWKrk="

	redsys := Redsys{}
	assert.Equal(t, redsys.mac256(PARAMS, ENCRYPTED_KEY), SIGNATURE, "SHA256 result should be qual to " + SIGNATURE)
}

func TestMechantEncodingAndDecoding(t *testing.T) {
	const PARAMS = "eyJEU19NRVJDSEFOVF9BTU9VTlQiOiIxNDUiLCJEU19NRVJDSEFOVF9PUkRFUiI6IjEiLCJEU19NRVJDSEFOVF9NRVJDSEFOVENPREUiOiI5OTkwMDg4ODEiLCJEU19NRVJDSEFOVF9DVVJSRU5DWSI6Ijk3OCIsIkRTX01FUkNIQU5UX1RSQU5TQUNUSU9OVFlQRSI6IjAiLCJEU19NRVJDSEFOVF9URVJNSU5BTCI6Ijg3MSIsIkRTX01FUkNIQU5UX01FUkNIQU5UVVJMIjoiIiwiRFNfTUVSQ0hBTlRfVVJMT0siOiIiLCJEU19NRVJDSEFOVF9VUkxLTyI6IiJ9"
	const DS_MERCHANT_PARAMETERS = "eyJEc19EYXRlIjoiMDklMkYxMSUyRjIwMTUiLCJEc19Ib3VyIjoiMTglM0EwMyIsIkRzX1NlY3VyZVBheW1lbnQiOiIwIiwiRHNfQ2FyZF9Db3VudHJ5IjoiNzI0IiwiRHNfQW1vdW50IjoiMTQ1IiwiRHNfQ3VycmVuY3kiOiI5NzgiLCJEc19PcmRlciI6IjAwNjkiLCJEc19NZXJjaGFudENvZGUiOiI5OTkwMDg4ODEiLCJEc19UZXJtaW5hbCI6Ijg3MSIsIkRzX1Jlc3BvbnNlIjoiMDAwMCIsIkRzX01lcmNoYW50RGF0YSI6IiIsIkRzX1RyYW5zYWN0aW9uVHlwZSI6IjAiLCJEc19Db25zdW1lckxhbmd1YWdlIjoiMSIsIkRzX0F1dGhvcmlzYXRpb25Db2RlIjoiMDgyMTUwIn0="

	merchantParamsRequest := &MerchantParametersRequest{
		MerchantAmount    :"145",
		MerchantOrder          :"1",
		MerchantMerchantCode   :"999008881",
		MerchantCurrency       :"978",
		MerchantTransactionType:"0",
		MerchantTerminal       :"871",
		MerchantMerchantUrl    :"",
		MerchantURLOK          :"",
		MerchantURLKO          :"",
	}

	merchantParams := MerchantParametersResponse{
		Date: "09/11/2015",
		Hour: "18:03",
		SecurePayment: "0",
		Card_Country: "724",
		Amount: "145",
		Currency: "978",
		Order: "0069",
		MerchantCode: "999008881",
		Terminal: "871",
		Response: "0000",
		MerchantData: "",
		TransactionType: "0",
		ConsumerLanguage: "1",
		AuthorisationCode: "082150",
	}

	redsys := Redsys{}

	assert.Equal(t, redsys.createMerchantParameters(merchantParamsRequest), PARAMS, "Create Merchant Parameters " + PARAMS)
	assert.Equal(t, redsys.decodeMerchantParameters(DS_MERCHANT_PARAMETERS), merchantParams, "Decode Merchant Parameters " + PARAMS)
}

func TestMerchantSignature(t *testing.T) {
	const KEY = "Mk9m98IfEblmPfrpsawt7BmxObt98Jev"

	merchantParamsRequest := &MerchantParametersRequest{
		MerchantAmount    :"145",
		MerchantOrder          :"1",
		MerchantMerchantCode   :"999008881",
		MerchantCurrency       :"978",
		MerchantTransactionType:"0",
		MerchantTerminal       :"871",
		MerchantMerchantUrl    :"",
		MerchantURLOK          :"",
		MerchantURLKO          :"",
	}
	redsys := Redsys{Key: KEY}
	const SIGNATURE = "3TEI5WyvHf1D/whByt1ENgFH/HPIP9UFuB6LkCYgj+E="
	assert.Equal(t, redsys.createMerchantSignature(merchantParamsRequest), SIGNATURE, "Create Merchant Signature " + SIGNATURE)

	const RESPONSE_DS_MERCHANT_PARAMETERS = "eyJEc19EYXRlIjoiMDklMkYxMSUyRjIwMTUiLCJEc19Ib3VyIjoiMTglM0EwMyIsIkRzX1NlY3VyZVBheW1lbnQiOiIwIiwiRHNfQ2FyZF9Db3VudHJ5IjoiNzI0IiwiRHNfQW1vdW50IjoiMTQ1IiwiRHNfQ3VycmVuY3kiOiI5NzgiLCJEc19PcmRlciI6IjAwNjkiLCJEc19NZXJjaGFudENvZGUiOiI5OTkwMDg4ODEiLCJEc19UZXJtaW5hbCI6Ijg3MSIsIkRzX1Jlc3BvbnNlIjoiMDAwMCIsIkRzX01lcmNoYW50RGF0YSI6IiIsIkRzX1RyYW5zYWN0aW9uVHlwZSI6IjAiLCJEc19Db25zdW1lckxhbmd1YWdlIjoiMSIsIkRzX0F1dGhvcmlzYXRpb25Db2RlIjoiMDgyMTUwIn0="
	const RESPONSE_DS_SIGNATURE = "6DVpRPAPoChZh2cgaWnLqlfFsKeXdRfAO_tz-UrxJcU="
	assert.Equal(t, redsys.createMerchantSignatureNotif(RESPONSE_DS_MERCHANT_PARAMETERS), RESPONSE_DS_SIGNATURE, "Create Merchant Signature Notification " + RESPONSE_DS_SIGNATURE)

	assert.Equal(t, redsys.merchantSignatureIsValid(RESPONSE_DS_SIGNATURE, RESPONSE_DS_SIGNATURE), bool(true), "Create Merchant Signature Notification")
}