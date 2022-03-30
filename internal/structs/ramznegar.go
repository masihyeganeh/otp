package structs

type RamznegarRequest struct {
	CommandParams interface{}      `json:"commandParams"`
	Context       RamznegarContext `json:"context"`
}

type RamznegarUpdateDeviceInfoRequest struct {
	DeviceInfo   RamznegarDeviceInfo `json:"deviceInfo"`
	TrackingCode string              `json:"trackingCode"`
}

type RamznegarDeviceInfo struct {
	DeviceID       string `json:"deviceId"`
	DeviceName     string `json:"deviceName"`
	Imei           string `json:"imei"`
	Manufacturer   string `json:"manufacturer"`
	ModelNumber    string `json:"modelNumber"`
	NotificationID string `json:"notificationId"`
	OsVersion      string `json:"osVersion"`
}

type RamznegarVerifyDeviceRequest struct {
	CaptchaCode      string              `json:"captchaCode,omitempty"`
	DeviceInfo       RamznegarDeviceInfo `json:"deviceInfo"`
	MobileNumber     string              `json:"mobileNumber"`
	VerificationCode string              `json:"verificationCode,omitempty"`
	TrackingCode     string              `json:"trackingCode"`
}

type RamznegarContact struct {
	Message  string `json:"message"`
	BankLink string `json:"bankLink"`
	HelpLink string `json:"helpLink"`
	Number   string `json:"number"`
	Email    string `json:"email"`
}

type RamznegarGeneralRequest struct {
	TrackingCode string `json:"trackingCode"`
}

type RamznegarDeviceGetConfigResponse struct {
	TrackingCode          string           `json:"trackingCode"`
	Message               string           `json:"message"`
	Today                 string           `json:"today"`
	ValidTimes            string           `json:"validTimes"`
	CardVersion           int              `json:"cardVersion"`
	SecondPassText        string           `json:"secondPassText"`
	SecondPassHint        string           `json:"secondPassHint"`
	ShowSecondPassField   bool             `json:"showSecondPassField"`
	EnablePin2StaticMode  bool             `json:"enablePin2StaticMode"`
	EnablePin2SpecialMode bool             `json:"enablePin2specialMode"`
	Contact               RamznegarContact `json:"contact"`
	EnableSetting         bool             `json:"enableSetting"`
}

type RamznegarContext struct {
	APIKey   string `json:"apiKey"`
	Locale   string `json:"locale"`
	Platform string `json:"platform"`
	Version  string `json:"version"`
}

// TODO: Split it
type RamznegarGeneralResponse struct {
	Code         *int   `json:"code"`
	Message      string `json:"message"`
	Captcha      string `json:"captcha"`
	TrackingCode string `json:"trackingCode"`
	NewAccount   bool   `json:"newAccount"`
	APIKey       string `json:"apiKey"`
}

type RamznegarActivationCaptchaRequest struct {
	MobileNumber string `json:"mobileNumber"`
	TrackingCode string `json:"trackingCode"`
}

type RamznegarCard struct {
	PanID        string `json:"panId"`
	MaskedPan    string `json:"maskedPan"`
	Title        string `json:"title"`
	ExpDate      string `json:"expDate"` // YYMM
	Pin1AuthType int    `json:"pin1AuthType"`
	Pin2AuthType int    `json:"pin2AuthType"`
}

type RamznegarCardInput struct {
	Cvv2    string `json:"cvv2"`
	ExpDate string `json:"expDate"` // YYMM
	Pan     string `json:"pan"`
	Pin     string `json:"pin"`
}

type RamznegarCardsListResponse struct {
	Code         *int            `json:"code"`
	TrackingCode string          `json:"trackingCode"`
	Message      string          `json:"message"`
	CardModels   []RamznegarCard `json:"cardModels"`
	CardVersion  int             `json:"cardVersion"`
}

type RamznegarAddCardRequest struct {
	RamznegarCardInput
	TrackingCode string `json:"trackingCode"`
}

type RamznegarAddCardResponse struct {
	Code         *int           `json:"code"`
	TrackingCode string         `json:"trackingCode"`
	Message      string         `json:"message"`
	CardModel    *RamznegarCard `json:"cardModel"`
}

type RamznegarRemoveCardRequest struct {
	PanID        string `json:"panId"`
	TrackingCode string `json:"trackingCode"`
}

type RamznegarSmsActivationStatusResponse struct {
	Code         *int   `json:"code"`
	TrackingCode string `json:"trackingCode"`
	Message      string `json:"message"`
	Status       string `json:"status"`
}

type RamznegarChangeSmsActivationStatusRequest struct {
	Status       string `json:"status"`
	TrackingCode string `json:"trackingCode"`
}

type RamznegarChangePinAuthTypeRequest struct {
	PanID        string `json:"panId"`
	Pin1AuthType int    `json:"pin1AuthType"`
	Pin2AuthType int    `json:"pin2AuthType"`
	TrackingCode string `json:"trackingCode"`
}

type RamznegarPinRequest struct {
	TrackingCode string  `json:"trackingCode"`
	MaxAmount    float64 `json:"maxAmount"`
	MaxValidTime int     `json:"maxValidTime"`
	PanId        string  `json:"panId"`
}

type RamznegarPinResponse struct {
	Code         *int   `json:"code"`
	TrackingCode string `json:"trackingCode"`
	Message      string `json:"message"`
	MaxValidTime int    `json:"maxValidTime"`
	Pin          string `json:"pin"`
}
