package structs

type RimaRegisterRequest struct {
	CurrentTime    int64  `json:"currentTime"`
	DeviceModel    string `json:"deviceModel"`
	DeviceSerial   string `json:"deviceSerial"`
	DeviceType     string `json:"deviceType"`
	IMEI           string `json:"imei"`
	MobileNo       string `json:"mobileNo"`
	OsVersion      string `json:"osVersion"`
	AppVersion     string `json:"appVersion"`
	IdentifierType string `json:"identifierType"`
}

type RimaRegisterResponse struct {
	Code         string  `json:"code"`
	MessageFa    *string `json:"messageFa"`
	MessageEn    *string `json:"messageEn"`
	Trace        *string `json:"trace"`
	RegisterCode int     `json:"registerCode"`
	ExpiryTime   int64   `json:"expiryTime"`
}

type RimaActivateRequest struct {
	ActivationCode string `json:"activationCode"`
	DeviceModel    string `json:"deviceModel"`
	DeviceSerial   string `json:"deviceSerial"`
	OsVersion      string `json:"osVersion"`
	DeviceType     string `json:"deviceType"`
	IMEI           string `json:"imei"`
	MobileNo       string `json:"mobileNo"`
	RegisterCode   string `json:"registerCode"`
}

type RimaActivateResponse struct {
	Code      string  `json:"code"`
	MessageFa *string `json:"messageFa"`
	MessageEn *string `json:"messageEn"`
	Trace     *string `json:"trace"`
	Key       string  `json:"key"`
	IMEI      *string `json:"imei"`
}
