package structs

type GbRamzAuthenticationRequest struct {
	AuthenticationTypeIs int    `json:"AuthenticationTypeIs"`
	MobileNumber         string `json:"MobileNo"`
	Imei                 string `json:"Imei"`
	IPAddress            string `json:"IpAddress"`
	MobileModelName      string `json:"MobileModelName"`
	PublicKey            string `json:"PublicKey"`
}

type GbRamzActivationRequest struct {
	MobileNumber   string `json:"MobileNo"`
	Imei           string `json:"Imei"`
	ActivationCode string `json:"ActivationCode"`
}

type GbRamzOtpGenerateRequest struct {
	MobileNumber          string `json:"MobileNo"`
	Imei                  string `json:"Imei"`
	ActivationCodePrinted string `json:"ActivitionCodePrint"`
	ActivationCodeSmsed   string `json:"ActivitionCodeSm"`
	OtpDuration           int    `json:"OtpDuration"`
	Data                  string `json:"Data"`
	Sign                  string `json:"Sign"`
}

type GbRamzResponse struct {
	ActivationCode interface{} `json:"ActivationCode"`
	TrackNo        interface{} `json:"TrackNo"`
	ResponseCode   int         `json:"ResponseCode"`
	ResponseDesc   string      `json:"ResponseDesc"`
}
