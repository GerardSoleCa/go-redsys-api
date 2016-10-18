package redsys

import (
	"encoding/base64"
	"log"
	"crypto/des"
	"crypto/cipher"
	"bytes"
	"crypto/hmac"
	"strings"
	"crypto/sha256"
	"encoding/json"
	"net/url"
)

var IV = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

type Redsys struct {

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
	MerchantAmount    	string `json:"DS_MERCHANT_AMOUNT"`
	MerchantOrder           string `json:"DS_MERCHANT_ORDER"`
	MerchantMerchantCode    string `json:"DS_MERCHANT_MERCHANTCODE"`
	MerchantCurrency        string `json:"DS_MERCHANT_CURRENCY"`
	MerchantTransactionType string `json:"DS_MERCHANT_TRANSACTIONTYPE"`
	MerchantTerminal        string `json:"DS_MERCHANT_TERMINAL"`
	MerchantMerchantUrl     string `json:"DS_MERCHANT_MERCHANTURL"`
	MerchantURLOK           string `json:"DS_MERCHANT_URLOK"`
	MerchantURLKO           string `json:"DS_MERCHANT_URLKO"`
}

func (r *Redsys) encrypt3DES(str string, key string) string {

	block := getCipher(key)
	cbc := cipher.NewCBCEncrypter(block, IV)

	decrypted := []byte(str)
	decryptedPadded, _ := zeroPad(decrypted, block.BlockSize())
	cbc.CryptBlocks(decryptedPadded, decryptedPadded)

	return base64.StdEncoding.EncodeToString(decryptedPadded)
}

func (r *Redsys) decrypt3DES(str string, key string) string {

	block := getCipher(key)
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

func (r *Redsys) decodeMerchantParameters(data string) (MerchantParametersResponse) {
	merchantParameters := MerchantParametersResponse{}
	decodedB64, _ := base64.URLEncoding.DecodeString(data)
	unscaped, _ := url.QueryUnescape(string(decodedB64))
	json.Unmarshal([]byte(unscaped), &merchantParameters)
	return merchantParameters
}

func getCipher(key string) cipher.Block {
	secretKey, err := base64.StdEncoding.DecodeString(key)

	if err != nil {
		log.Panic("Error decoding key", err)
	}

	crypto, err := des.NewTripleDESCipher(secretKey)
	if err != nil {
		log.Panic("Error generating cipher", err)
	}
	return crypto
}

// zeroPad function to terminate blocksize in zeros
func zeroPad(data []byte, blocklen int) ([]byte, error) {
	padlen := (blocklen - (len(data) % blocklen)) % blocklen
	pad := bytes.Repeat([]byte{0x00}, padlen)

	return append(data, pad...), nil
}

// zeroUnpad function to remove trailing zeros
func zeroUnpad(data []byte, blocklen int) ([]byte, error) {
	lastIndex := len(data);
	for (lastIndex >= 0 && lastIndex > len(data) - blocklen - 1) {
		lastIndex--;
		if (data[lastIndex] != 0) {
			break;
		}
	}
	return data[:lastIndex + 1], nil
}
