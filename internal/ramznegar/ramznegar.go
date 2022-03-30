package ramznegar

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"log"
	"otp/internal/encryption/asymmetric"
	"otp/internal/encryption/symmetric"
	. "otp/internal/structs"
	. "otp/internal/utils"
	"regexp"
	"strings"
)

var (
	NeedsCaptchaErr                   = errors.New("needs captcha")
	phoneNumberPattern                = regexp.MustCompile("^(09|\\+989|00989)")
	ramznegarPublicKey *rsa.PublicKey = nil
)

type SmsActivationStatus string

var (
	Active   SmsActivationStatus = "ACTIVE"
	Inactive                     = "INACTIVE"
)

type PinAuthType int

var (
	Static           PinAuthType = 0
	Dynamic                      = 1
	StaticAndDynamic             = 2
)

func init() {
	intermediateCA := `
-----BEGIN CERTIFICATE-----
MIIGdTCCBV2gAwIBAgIQTSH/aakC3jN17PoONrSXVjANBgkqhkiG9w0BAQsFADCB
hTELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMu
QS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEpMCcG
A1UEAxMgQ2VydHVtIERvbWFpbiBWYWxpZGF0aW9uIENBIFNIQTIwHhcNMTkwMjI4
MDk1MDAwWhcNMjEwMjI3MDk1MDAwWjAsMQswCQYDVQQGEwJJUjEdMBsGA1UEAwwU
ZHAuYnBtLmJhbmttZWxsYXQuaXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDXsMWqarvhM6NcwNb7pR9FHGiOeA8rFE0H5mKRamlWTx/ufrQbxTo6bgqm
sw/eXj0D8hq4GrFEEE+nNPmCMDM5FHXyUPcbvg1hU16MH8yEqvzWqCpS/3C0cE3v
9ORdVx8b8cZ/eXoyOQMzLZgKdPcQpiDXdA8HLOw1cfJo710iWG7vE/Sf/E3jBIyz
R8UbKc4e++x41FzIQpdBIk5Ymq3MmHc9Fln8j+8tYghPMIwvKUerJdTABD9684Nv
H+hSaogKcWiQnyCtqGe70gk3NV9IA41+9NytOP6658V1s9lCWo0QvybQJHEeF2NP
VGG31dbvPcKul3T+a40s4KJVvCNtAgMBAAGjggM3MIIDMzAMBgNVHRMBAf8EAjAA
MDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6Ly9jcmwuY2VydHVtLnBsL2R2Y2FzaGEy
LmNybDBxBggrBgEFBQcBAQRlMGMwKwYIKwYBBQUHMAGGH2h0dHA6Ly9kdmNhc2hh
Mi5vY3NwLWNlcnR1bS5jb20wNAYIKwYBBQUHMAKGKGh0dHA6Ly9yZXBvc2l0b3J5
LmNlcnR1bS5wbC9kdmNhc2hhMi5jZXIwHwYDVR0jBBgwFoAU5TGtvzoRlvSDvFA8
1LeQm5Du3iUwHQYDVR0OBBYEFF6yocF6WPDOw/Gae7wRqCkX7UqXMB0GA1UdEgQW
MBSBEmR2Y2FzaGEyQGNlcnR1bS5wbDBLBgNVHSAERDBCMAgGBmeBDAECATA2Bgsq
hGgBhvZ3AgUBAzAnMCUGCCsGAQUFBwIBFhlodHRwczovL3d3dy5jZXJ0dW0ucGwv
Q1BTMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAOBgNVHQ8BAf8EBAMC
BaAwHwYDVR0RBBgwFoIUZHAuYnBtLmJhbmttZWxsYXQuaXIwggF+BgorBgEEAdZ5
AgQCBIIBbgSCAWoBaAB2AKS5CZC0GFgUh7sTosxncAo8NZgE+RvfuON3zQ7IDdwQ
AAABaTN+MpMAAAQDAEcwRQIhAOOrkWF/aaVzR9FbHbZJDwmChz9xSsxH8CUZbMYm
6GRUAiBcPF9miHm/jqkOOZ+epphb5g7m46CG40K00hgIuJRs0wB2AO5Lvbd1zmC6
4UJpH6vhnmajD35fsHLYgwDEe4l6qP3LAAABaTN+Mo8AAAQDAEcwRQIhAI5q0G8O
uS6ayLxNr5xAdOHCQ3xnvOKO/SwRMoNIXvghAiAvXheBu+UmSNujkyUKqFpB1OIG
g1l/x8T4i/p2EmmdTwB2AESUZS6w7s6vxEAH2Kj+KMDa5oK+2MsxtT/TM5a1toGo
AAABaTN+MwIAAAQDAEcwRQIhANvjosWPog4qjgHw6mZMqBj8Yoy98/zmaj+vI/ME
j+xqAiBDUwhqjPMWOyPnv4LP3ymldTtun/TfxIgSUj6WCz62VTANBgkqhkiG9w0B
AQsFAAOCAQEAJf1dEyVdeYVF0lC41H2IfIdAluFd9uKq2OXJq9oB8bCqH7HUd39X
vltoOu19gEfqP8/Y8Rstt+JDcD0t6yS/TnmFypL1mqGrzyYN22XsKvuH/hHDYcye
apIfiWafCWTpmKqZ+rzABwx9I3a1oGDYoddScAvsPqktgtF1y3XBpt1JlJLHDSIs
Jq9qsXAqhnqqoV4kXQ9uhR1yCMVDFZJ6j0WN7U0T95MwKGVB5mbsVubU8yBn4z1L
XynDoq7L8gA+1ZYHz8q5wNScUcwPaQ/wfr7YVX3AbvJeNB1YNIZKJqmmrc6qbChE
8aap/1uT45etsDaj+aBCqFYvpgG4mQ4mOg==
-----END CERTIFICATE-----
`
	if err := AddCustomCA([]byte(intermediateCA)); err != nil {
		log.Fatalf("Could not add intermediate CA for RamzNegar")
	}

	pubPem := `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz4HJWa0icBa27D7yjqgD
Di4ZqtcB3WMsMcTYWxFgmcq/s3yEKQ2h0iUtFxiOw8Pg4ivDM7jlUdz40wKsxHOT
3106rX2ZctiMsOEs2jGhd7YMtGLw/X0RXapiw4ysAOkwVXE6iSUzqhddHJxmRguI
VQZZSVgQdof8EesibSK6VYj7AeGxIZeW/5TiztF6lNPas2PqXA1fhZpZwU9YnmU8
/ZR7ZSpaEgWNsvvrLfd2RgxDLzT0EmHqL+nTOxJZuubZDSN40IanEtuBFT0a4vwx
YCcQwDe414GvzOF9/ofEO4jRG4luqx/o9oOcNaLljvVMNC4KNK2YRJ6ktLGaqZN4
jwIDAQAB
-----END PUBLIC KEY-----
`

	var err error
	ramznegarPublicKey, err = asymmetric.RsaPublicKeyFromPem([]byte(strings.TrimSpace(pubPem)))
	if err != nil {
		log.Fatal(err)
	}
}

type Ramznegar struct {
	imei         string
	deviceName   string
	manufacturer string
	modelNumber  string
	osVersion    string
	tokenId      string
	androidId    string
	mobileNumber string
	apiKey       string
}

func New(mobileNumber string) (*Ramznegar, error) {
	return NewWithDevice(mobileNumber, "ABABABABABABABAB", "Xiaomi", "Mi 9T", "29")
}

func NewWithDevice(mobileNumber, androidId, buildManufacturer, buildModel, osVersion string) (*Ramznegar, error) {
	mobileNumber = phoneNumberPattern.ReplaceAllString(mobileNumber, "989")

	h := sha256.New()
	h.Write([]byte(androidId))
	androidId = hex.EncodeToString(h.Sum(nil))[:16]

	return &Ramznegar{
		imei:         androidId,
		deviceName:   buildManufacturer + " " + buildModel,
		manufacturer: buildManufacturer,
		modelNumber:  buildModel,
		osVersion:    osVersion,
		androidId:    androidId,
		mobileNumber: mobileNumber,
		apiKey:       "",
	}, nil
}

func generateSessionKey() ([]byte, string, error) {
	sessionKey := []byte(uuid.New().String())

	key, err := rsa.EncryptPKCS1v15(rand.Reader, ramznegarPublicKey, sessionKey)
	if err != nil {
		return nil, "", err
	}

	wrappedKey := base64.StdEncoding.EncodeToString(key)

	return sessionKey, wrappedKey, nil
}

func (r *Ramznegar) SetApiKey(apiKey string) {
	r.apiKey = apiKey
}

func (r *Ramznegar) request(path string, params interface{}, result interface{}) error {
	data := RamznegarRequest{
		CommandParams: params,
		Context: RamznegarContext{
			APIKey:   r.apiKey,
			Locale:   "fa",
			Platform: "ANDROID",
			Version:  "1.3",
		},
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}

	sessionKey, wrappedSessionKey, err := generateSessionKey()
	if err != nil {
		return err
	}

	aes := symmetric.NewAES(sessionKey[:16], symmetric.ECB, symmetric.Pkcs7)
	payload, err = aes.Encrypt(payload, nil)
	if err != nil {
		return err
	}

	payload = []byte(base64.StdEncoding.EncodeToString(payload))

	uri := "https://dp.bpm.bankmellat.ir:1443/dynamic-pin-rest-api/v1/" + path
	bodyBytes, err := Request(uri, map[string]string{"REK": wrappedSessionKey}, payload, &result)
	if err != nil && bodyBytes != nil {
		bodyBytes, err = base64.StdEncoding.DecodeString(string(bodyBytes))
		bodyBytes, err = aes.Decrypt(bodyBytes, nil)
		if err != nil {
			return err
		}
		err = json.Unmarshal(bodyBytes, &result)
	}
	if err != nil {
		return err
	}

	return nil
}

func (r *Ramznegar) GetConfig() (*RamznegarDeviceGetConfigResponse, error) {
	params := RamznegarGeneralRequest{
		TrackingCode: MustGenerateUUID(),
	}

	var result RamznegarDeviceGetConfigResponse

	err := r.request("device/getConfig", params, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (r *Ramznegar) VerifyDevice(verificationCode string) (string, bool, error) {
	return r.VerifyDeviceWithCaptcha(verificationCode, "")
}

func (r *Ramznegar) VerifyDeviceWithCaptcha(verificationCode string, captchaCode string) (string, bool, error) {
	if len(verificationCode) != 6 {
		return "", false, errors.New("verification code should be 6 digits")
	}

	params := RamznegarVerifyDeviceRequest{
		CaptchaCode: captchaCode,
		DeviceInfo: RamznegarDeviceInfo{
			DeviceID:       r.androidId,
			DeviceName:     r.deviceName,
			Imei:           r.imei,
			Manufacturer:   r.manufacturer,
			ModelNumber:    r.modelNumber,
			NotificationID: "fI8Ks48_t1w:APA91bFPKm8rb3L3TdhAR7mrYoaMU2J1-Y4ZH5iIhOxh35XGHhjJX3evXxHyywcysleC4yVovvjZgmt3WafFTr_VM3s7dlpqPnIWN4o8yRdj0fndQ4A3jz26v2pj4Be950Iah9y85uil",
			OsVersion:      r.osVersion,
		},
		MobileNumber:     r.mobileNumber,
		VerificationCode: verificationCode,
		TrackingCode:     MustGenerateUUID(),
	}

	var result RamznegarGeneralResponse

	err := r.request("device/verify", params, &result)
	if err != nil {
		return "", false, err
	}

	if result.Code != nil {
		if *result.Code == 520 {
			return "", false, NeedsCaptchaErr
		}
		return "", false, errors.New(result.Message)
	}

	r.apiKey = result.APIKey

	return result.APIKey, result.NewAccount, nil
}

func (r *Ramznegar) GetCaptcha() ([]byte, error) {
	params := RamznegarActivationCaptchaRequest{
		MobileNumber: r.mobileNumber,
		TrackingCode: MustGenerateUUID(),
	}

	var result RamznegarGeneralResponse

	err := r.request("device/activationCaptcha", params, &result)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(result.Captcha)
}

func (r *Ramznegar) UpdateDeviceInfo(deviceInfo RamznegarDeviceInfo) error {
	params := RamznegarUpdateDeviceInfoRequest{
		DeviceInfo:   deviceInfo,
		TrackingCode: MustGenerateUUID(),
	}

	var result RamznegarGeneralResponse

	err := r.request("device/updateDeviceInfo", params, &result)
	if err != nil {
		return err
	}

	if result.Code != nil {
		return errors.New(result.Message)
	}

	return nil
}

func (r *Ramznegar) ListCards() ([]RamznegarCard, error) {
	params := RamznegarGeneralRequest{
		TrackingCode: MustGenerateUUID(),
	}

	var result RamznegarCardsListResponse

	err := r.request("card/list", params, &result)
	if err != nil {
		return nil, err
	}

	return result.CardModels, nil
}

func (r *Ramznegar) AddCard(card RamznegarCardInput) (*RamznegarCard, error) {
	params := RamznegarAddCardRequest{
		RamznegarCardInput: card,
		TrackingCode:       MustGenerateUUID(),
	}

	var result RamznegarAddCardResponse

	err := r.request("card/add", params, &result)
	if err != nil {
		return nil, err
	}

	if result.Code != nil {
		return nil, errors.New(result.Message)
	}

	return result.CardModel, nil
}

func (r *Ramznegar) RemoveCard(panId string) error {
	params := RamznegarRemoveCardRequest{
		PanID:        panId,
		TrackingCode: MustGenerateUUID(),
	}

	var result RamznegarGeneralResponse

	err := r.request("card/remove", params, &result)
	if err != nil {
		return err
	}

	if result.Code != nil {
		return errors.New(result.Message)
	}

	return nil
}

func (r *Ramznegar) SmsActivationStatus() (SmsActivationStatus, error) {
	params := RamznegarGeneralRequest{
		TrackingCode: MustGenerateUUID(),
	}

	var result RamznegarSmsActivationStatusResponse

	err := r.request("setting/smsActivation/status", params, &result)
	if err != nil {
		return "", err
	}

	return SmsActivationStatus(result.Status), nil
}

func (r *Ramznegar) ChangeSmsActivationStatus(status SmsActivationStatus) error {
	params := RamznegarChangeSmsActivationStatusRequest{
		Status:       string(status),
		TrackingCode: MustGenerateUUID(),
	}

	var result RamznegarGeneralResponse

	err := r.request("setting/smsActivation/changeStatus", params, &result)
	if err != nil {
		return err
	}

	if result.Code != nil {
		return errors.New(result.Message)
	}

	return nil
}

func (r *Ramznegar) ChangePinAuthType(panId string, pin1AuthType, Pin2AuthType PinAuthType) error {
	params := RamznegarChangePinAuthTypeRequest{
		PanID:        panId,
		Pin1AuthType: int(pin1AuthType),
		Pin2AuthType: int(Pin2AuthType),
		TrackingCode: MustGenerateUUID(),
	}

	var result RamznegarGeneralResponse

	err := r.request("card/changePinAuthType", params, &result)
	if err != nil {
		return err
	}

	if result.Code != nil {
		return errors.New(result.Message)
	}

	return nil
}

func (r *Ramznegar) requestPin(pinRequest RamznegarPinRequest, pinType string) (string, int, error) {
	params := pinRequest
	params.TrackingCode = MustGenerateUUID()

	var result RamznegarPinResponse

	err := r.request("card/requestPin"+pinType, params, &result)
	if err != nil {
		return "", 0, err
	}

	if result.Code != nil {
		return "", 0, errors.New(result.Message)
	}

	return result.Pin, result.MaxValidTime, nil
}

func (r *Ramznegar) RequestPin1(pinRequest RamznegarPinRequest) (string, int, error) {
	return r.requestPin(pinRequest, "1")
}

func (r *Ramznegar) RequestPin2(pinRequest RamznegarPinRequest) (string, int, error) {
	return r.requestPin(pinRequest, "2")
}
