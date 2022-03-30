package structs

type SekehRequest struct {
	CommandParams interface{}  `json:"commandParams"`
	Context       SekehContext `json:"context"`
}

type SekehDeviceInfo struct {
	DeviceID       string `json:"deviceId"`
	DeviceName     string `json:"deviceName"`
	Imei           string `json:"imei"`
	Manufacturer   string `json:"manufacturer"`
	ModelNumber    string `json:"modelNumber"`
	NotificationID string `json:"notificationId"`
	OsVersion      string `json:"osVersion"`
}

type SekehVerifyDeviceRequest struct {
	MobileNumber string `json:"mobileNumber"`
	TrackingCode string `json:"trackingCode"`
}

type SekehProfile struct {
	// deviceId + android id + ("" + Build.SERIAL) + "::" + (Build.PRODUCT.length() % 10) + (Build.BOARD.length() % 10) + (Build.BRAND.length() % 10) + (Build.CPU_ABI.length() % 10) + (Build.DEVICE.length() % 10) + (Build.MANUFACTURER.length() % 10) + (Build.MODEL.length() % 10);
	DeviceId       string `json:"deviceId"`
	InstallationId string `json:"installationId"`
}

type SekehContext struct {
	Profile  SekehProfile `json:"profile"`
	Locale   string       `json:"locale"`
	Platform string       `json:"platform"`
	Version  string       `json:"version"`
}

type SekehResponse struct {
	Code         *int   `json:"code"`
	Message      string `json:"message"`
	Captcha      string `json:"captcha"`
	TrackingCode string `json:"trackingCode"`
}

type SekehActivationCaptchaRequest struct {
	MobileNumber string `json:"mobileNumber"`
	TrackingCode string `json:"trackingCode"`
}
