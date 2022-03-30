package structs

type HamrazGeneralResponse struct {
	Message        string `json:"message"`
	TimeS          int64  `json:"timeS"`
	ResultCode     int    `json:"resultCode"`
	ResponseDescFa string `json:"responseDescFa"`
	ResponseDescEn string `json:"responseDescEn"`
}

type HamrazChannelsResponse struct {
	ChannelPojoList []HamrazChannel `json:"channelPojoList"`
	ResponseCode    int             `json:"responseCode"`
	HamrazGeneralResponse
}

type HamrazChannel struct {
	ChannelID          int     `json:"channelId"`
	UserNameType       string  `json:"userNameType"`
	ChannelNameEN      string  `json:"channelNameEN"`
	ChannelNameFA      string  `json:"channelNameFA"`
	UserNameCharType   string  `json:"userNameCharType"`
	UserNameMinLength  int     `json:"userNameMinLength"`
	UserNameMaxLength  int     `json:"userNameMaxLength"`
	OtpDigitCount      int     `json:"otpDigitCount"`
	OtpTimeStep        int     `json:"otpTimeStep"`
	OtpDisplayTimeStep int     `json:"otpDisplayTimeStep"`
	CurrentTime        float64 `json:"currentTime"`
}

type HamrazVerificationRequest struct {
	ActivationCode string `json:"activationCode"`
	ChannelID      int    `json:"channelId"`
	LoginID        string `json:"loginId"`
	PhoneID        string `json:"phoneId"`
	TokenSerialNo  string `json:"tokenSerialNo"`
	DateAndTimeMil int    `json:"dateAndTimeMil"`
}
