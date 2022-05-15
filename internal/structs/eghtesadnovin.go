package structs

type EghtesadNovinGeneralResponseError struct {
	Key     string `json:"key"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

type EghtesadNovinGeneralResponse struct {
	Error *EghtesadNovinGeneralResponseError `json:"error"`
}

type EghtesadNovinTokenActivationData struct {
	Token            string `json:"token"`
	VerificationCode string `json:"verificationCode"`
}

type EghtesadNovinSignInRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Type       string `json:"type"`
	ChannelKey string `json:"channelKey"`
}

type EghtesadNovinSignInResponse struct {
	Cif                             string   `json:"cif"`
	Username                        string   `json:"username"`
	FullName                        string   `json:"fullName"`
	Gender                          string   `json:"gender"`
	MobileNumber                    string   `json:"mobileNumber"`
	NationalCode                    string   `json:"nationalCode"`
	LastLoginTime                   int64    `json:"lastLoginTime"`
	ForceChangeUsernameInFirstLogin bool     `json:"forceChangeUsernameInFirstLogin"`
	ForceChangePasswordInFirstLogin bool     `json:"forceChangePasswordInFirstLogin"`
	Constraints                     []string `json:"constraints"`
}

type EghtesadNovinGenerateTicketRequestServiceInfoSource struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type EghtesadNovinGenerateTicketRequestServiceInfo struct {
	Source EghtesadNovinGenerateTicketRequestServiceInfoSource `json:"source"`
	Type   string                                              `json:"type"`
}

type EghtesadNovinGenerateTicketRequest struct {
	ServiceInfo EghtesadNovinGenerateTicketRequestServiceInfo `json:"serviceInfo"`
}

type EghtesadNovinTwoFactorRequestConstraints struct {
	Ticket string `json:"ticket"`
}

type EghtesadNovinTwoFactorRequest struct {
	Constraints EghtesadNovinTwoFactorRequestConstraints `json:"constraints"`
}

type EghtesadNovinGenerateTokenRequest struct {
	OtpTokenGenerationType string `json:"otpTokenGenerationType"`
}

type EghtesadNovinOtpConfig struct {
	Cif                    string `json:"cif"`
	Token                  string `json:"token"`
	OtpTokenGenerationType string `json:"otpTokenGenerationType"`
	VerificationCodeLength int    `json:"verificationCodeLength"`
}

type EghtesadNovinOtpActivationRequest struct {
	Username      string `json:"username"`
	Type          string `json:"type"`
	PublicKey     string `json:"publicKey"`
	CipherMessage string `json:"cipherMessage"`
}

type EghtesadNovinOtpActivationResponse struct {
	SecretKey           string `json:"secretKey"`
	OtpGenerationPeriod int    `json:"otpGenerationPeriod"`
	OtpLength           int    `json:"otpLength"`
}
