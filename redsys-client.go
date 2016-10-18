package redsys

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
)

var IV = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

type Redsys struct {
	Key string
}

type MerchantParametersResponse struct {
	Date              string `json:"Ds_Date"`
	Hour              string `json:"Ds_Hour"`
	SecurePayment     string `json:"Ds_SecurePayment"`
	Card_Country      string `json:"Ds_Card_Country"`
	Amount            string `json:"Ds_Amount"`
	Currency          string `json:"Ds_Currency"`
	Order             string `json:"Ds_Order"`
	MerchantCode      string `json:"Ds_MerchantCode"`
	Terminal          string `json:"Ds_Terminal"`
	Response          string `json:"Ds_Response"`
	MerchantData      string `json:"Ds_MerchantData"`
	TransactionType   string `json:"Ds_TransactionType"`
	ConsumerLanguage  string `json:"Ds_ConsumerLanguage"`
	AuthorisationCode string `json:"Ds_AuthorisationCode"`
}

type MerchantParametersRequest struct {
	MerchantAmount          string `json:"DS_MERCHANT_AMOUNT"`
	MerchantOrder           string `json:"DS_MERCHANT_ORDER"`
	MerchantMerchantCode    string `json:"DS_MERCHANT_MERCHANTCODE"`
	MerchantCurrency        string `json:"DS_MERCHANT_CURRENCY"`
	MerchantTransactionType string `json:"DS_MERCHANT_TRANSACTIONTYPE"`
	MerchantTerminal        string `json:"DS_MERCHANT_TERMINAL"`
	MerchantMerchantUrl     string `json:"DS_MERCHANT_MERCHANTURL"`
	MerchantURLOK           string `json:"DS_MERCHANT_URLOK"`
	MerchantURLKO           string `json:"DS_MERCHANT_URLKO"`
}

func (r *Redsys) encrypt3DES(str string) string {

	block := getCipher(r.Key)
	cbc := cipher.NewCBCEncrypter(block, IV)

	decrypted := []byte(str)
	decryptedPadded, _ := zeroPad(decrypted, block.BlockSize())
	cbc.CryptBlocks(decryptedPadded, decryptedPadded)

	return base64.StdEncoding.EncodeToString(decryptedPadded)
}

func (r *Redsys) decrypt3DES(str string) string {

	block := getCipher(r.Key)
	cbc := cipher.NewCBCDecrypter(block, IV)

	encrypted, _ := base64.StdEncoding.DecodeString(str)
	cbc.CryptBlocks(encrypted, encrypted)

	unpaddedResult, _ := zeroUnpad(encrypted, block.BlockSize())

	return string(unpaddedResult)
}

func (r *Redsys) mac256(data string, key string) string {
	decodedKey, _ := base64.StdEncoding.DecodeString(key)
	hmac := hmac.New(sha256.New, []byte(decodedKey))
	hmac.Write([]byte(strings.TrimSpace(data)))
	result := hmac.Sum(nil)
	return base64.StdEncoding.EncodeToString(result)
}

func (r *Redsys) createMerchantParameters(data *MerchantParametersRequest) string {
	merchantMarshalledParams, _ := json.Marshal(data)
	return base64.URLEncoding.EncodeToString(merchantMarshalledParams)
}

func (r *Redsys) decodeMerchantParameters(data string) MerchantParametersResponse {
	merchantParameters := MerchantParametersResponse{}
	decodedB64, _ := base64.URLEncoding.DecodeString(data)
	unscaped, _ := url.QueryUnescape(string(decodedB64))
	json.Unmarshal([]byte(unscaped), &merchantParameters)
	return merchantParameters
}

func (r *Redsys) createMerchantSignature(data *MerchantParametersRequest) string {
	stringMerchantParameters := r.createMerchantParameters(data)

	orderId := data.MerchantOrder

	encrypted := r.encrypt3DES(orderId)
	return r.mac256(stringMerchantParameters, encrypted)
}

func (r *Redsys) createMerchantSignatureNotif(data string) string {
	merchantParametersResponse := r.decodeMerchantParameters(data)

	orderId := merchantParametersResponse.Order
	encrypted := r.encrypt3DES(orderId)
	mac := r.mac256(data, encrypted)

	decodedMac, _ := base64.StdEncoding.DecodeString(mac)
	return base64.URLEncoding.EncodeToString(decodedMac)
}

func (r *Redsys) merchantSignatureIsValid(mac1 string, mac2 string) bool {
	return hmac.Equal([]byte(mac1), []byte(mac2))
}
