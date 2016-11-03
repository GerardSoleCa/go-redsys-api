package redsys

// MerchantParametersResponse struct to read Redsys API responses
type MerchantParametersResponse struct {
	Date              string `json:"Ds_Date"`
	Hour              string `json:"Ds_Hour"`
	SecurePayment     string `json:"Ds_SecurePayment"`
	CardCountry       string `json:"Ds_Card_Country"`
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

// MerchantParametersRequest struct to construct Redsys API requests
type MerchantParametersRequest struct {
	MerchantAmount             string `json:"DS_MERCHANT_AMOUNT"`
	MerchantOrder              string `json:"DS_MERCHANT_ORDER"`
	MerchantMerchantCode       string `json:"DS_MERCHANT_MERCHANTCODE"`
	MerchantMerchantName       string `json:"DS_MERCHANT_MERCHANTNAME"`
	MerchantCurrency           string `json:"DS_MERCHANT_CURRENCY"`
	MerchantTransactionType    string `json:"DS_MERCHANT_TRANSACTIONTYPE"`
	MerchantTerminal           string `json:"DS_MERCHANT_TERMINAL"`
	MerchantMerchantUrl        string `json:"DS_MERCHANT_MERCHANTURL"`
	MerchantURLOK              string `json:"DS_MERCHANT_URLOK"`
	MerchantURLKO              string `json:"DS_MERCHANT_URLKO"`
	MerchantConsumerLanguage   string `json:"Ds_Merchant_ConsumerLanguage"`
	MerchantProductDescription string `json:"Ds_Merchant_ProductDescription"`
	MerchantTitular            string `json:"Ds_Merchant_Titular"`
}
