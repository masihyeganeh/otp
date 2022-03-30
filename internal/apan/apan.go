package apan

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"otp/internal/encryption/asymmetric"
	"otp/internal/encryption/symmetric"
	. "otp/internal/structs"
	tokenObject "otp/internal/token"
	. "otp/internal/utils"
	"strconv"
	"strings"
	"time"
)

type Apan struct {
	deviceInfo        string
	sessionKey        []byte
	wrappedSessionKey []byte
	tokenId           string
	androidId         string
	mobileNumber      string
}

func New(mobileNumber string) (*Apan, error) {
	return NewWithDevice(mobileNumber, "ABABABABABABABAB", "shamu", "SM-J3110", "Android", "22", "1.0.10")
}

func NewWithDevice(mobileNumber, androidId, buildDevice, buildModel, buildBrand, BuildVersionSdk, appVersion string) (*Apan, error) {
	deviceInfo := fmt.Sprintf("%s|%s|%s|%s|%s", buildDevice, buildModel, buildBrand, BuildVersionSdk, appVersion)
	sessionKey, wrappedSessionKey, err := generateSessionKey()
	if err != nil {
		return nil, err
	}
	return &Apan{
		deviceInfo:        deviceInfo,
		sessionKey:        sessionKey,
		wrappedSessionKey: wrappedSessionKey,
		androidId:         androidId,
		mobileNumber:      mobileNumber,
	}, nil
}

func generateSessionKey() ([]byte, []byte, error) {
	pubPem := `-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBjNogA39gvXafm7R5a8rF+
goEVYFewxgdFWR1UiUn6KrKpRfsDFRIodU0bmlUFBRMyQJEmJbpusZbYIWYrqS5Z
e27uyn1R6WJQM6Ev+ZZXqbxVMdSXpXvN/8X/3BDIhZ3YQ59sNXkNSbDelJf8YF3t
81toub65AaMle82mm3g4Bd07LVbjsz/+uTCF6kl0XrjKW3fQ7WjT4t+iBd1Knla0
08H53Uk+J+jdgHBhFCoV3eyZB1yozo4AphfAvnY+6mJp5pUHs1vAJAOILdzXmfWf
XUaW/oE8L1oku+m4A4sIsQ1iygK+C3uFVKc7IP0JYwcMcAxlb9kbfb+5Fh4j1QtV
AgMBAAE=
-----END PUBLIC KEY-----`

	pub, err := asymmetric.RsaPublicKeyFromPem([]byte(pubPem))
	if err != nil {
		return nil, nil, err
	}

	sessionKey := make([]byte, 32)
	n, err := rand.Read(sessionKey)
	if err != nil {
		return nil, nil, err
	}
	if n != 32 {
		return nil, nil, errors.New("could not generate session key")
	}

	key, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(base64.StdEncoding.EncodeToString(sessionKey)))
	if err != nil {
		return nil, nil, err
	}

	return sessionKey, key, nil
}

func (a *Apan) request(path string, data, result interface{}, stringified bool) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}

	aes := symmetric.NewAES(a.sessionKey, symmetric.CBC, symmetric.Pkcs7)
	iv := make([]byte, 16)
	value, err := aes.Encrypt(payload, iv)
	if err != nil {
		return err
	}

	post := ApanApiRequestModel{
		Key:        base64.StdEncoding.EncodeToString(a.wrappedSessionKey),
		Value:      base64.StdEncoding.EncodeToString(value),
		DeviceInfo: fmt.Sprintf("%s|%s", a.androidId, a.deviceInfo),
	}

	payload, err = json.Marshal(post)
	if err != nil {
		return err
	}

	body := ""
	uri := "https://svccard.ansarbank.ir/OnlineApiDevices/" + path
	_, err = Request(uri, nil, payload, &body)
	if err != nil {
		return err
	}

	response, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return err
	}

	response, err = aes.Decrypt(response, iv)
	if err != nil {
		return err
	}

	if stringified {
		var intermediateResult string
		err = json.Unmarshal(response, &intermediateResult)
		if err != nil {
			return err
		}
		response = []byte(intermediateResult)
	}

	if bytes.Equal(response, []byte("Sms Service Not Work...")) {
		return errors.New("sms service not working")
	}

	return json.Unmarshal(response, &result)
}

func (a *Apan) GetLoginCode() error {
	data := ApanLoginDeviceModel{
		MobileNumber:     a.mobileNumber,
		UserDeviceInfo:   a.deviceInfo,
		AppId:            "1",
		AppCode:          "",
		ActivationCode:   "",
		AppControlTypeId: 2,
	}

	var result ApanMultipleResponse
	err := a.request("api/Applications/FirstLoginPhase", data, &result, true)
	if err != nil {
		return err
	}

	if result[0].MessageModel[0].ErrorCode == 8 {
		a.tokenId = result[0].DataModel[0].Data
		return nil
	}

	if result[0].MessageModel[0].ErrorString == "اطلاعات عضویت با این شماره موبایل پیدا نشد، لطفا ابتدا عضو شده و مجددا امتحان کنید" {
		err = a.register()
		if err != nil {
			return err
		}
		return a.GetLoginCode()
	}

	return errors.New(result[0].MessageModel[0].ErrorString)
}

func (a *Apan) LoginWithCode(activationCode string) error {
	data := ApanLoginDeviceModel{
		MobileNumber:     a.mobileNumber,
		UserDeviceInfo:   a.deviceInfo,
		AppId:            "1",
		AppCode:          "",
		ActivationCode:   strings.TrimSpace(activationCode),
		AppControlTypeId: 1,
		TokenId:          &a.tokenId,
	}

	var result ApanMultipleResponse
	err := a.request("api/Applications/SecondLoginPhase", data, &result, true)
	if err != nil {
		return err
	}

	if result[0].MessageModel[0].ErrorCode == 8 {
		return nil
	}

	return errors.New(result[0].MessageModel[0].ErrorString)
}

func (a *Apan) Activate(token, cif, pin, verificationCode string) (*tokenObject.Token, error) {
	data := ApanOtpModel{
		Mobile:           a.mobileNumber,
		TokenId:          a.tokenId,
		Cif:              cif,
		Pin:              pin,
		Token:            token,
		VerificationCode: verificationCode,
	}

	var result ApanResultFinalOtp
	err := a.request("api/Otp/OtpGenerator", data, &result, false)
	if err != nil {
		return nil, err
	}

	if result.ErrorCode != "8" {
		return nil, errors.New(result.ErrorString)
	}

	if len(result.SecretKey) == 0 || len(result.OtpLen) == 0 || len(result.PeriodOtpSecondPin) == 0 {
		return nil, errors.New("could not activate otp")
	}

	otpLen, err := strconv.Atoi(result.OtpLen)
	if err != nil {
		return nil, err
	}

	periodOtpSecondPin, err := strconv.Atoi(result.PeriodOtpSecondPin)
	if err != nil {
		return nil, err
	}

	return &tokenObject.Token{
		OtpLength:    otpLen,
		TimeInterval: periodOtpSecondPin,
		BankName:     "Ansar",
		AccountId:    cif,
		Seed:         result.SecretKey,
	}, err
}

func (a *Apan) register() error {
	data := ApanSubscriber{
		Address:     nil,
		BirthDate:   time.Now().Add(-20 * 365 * 24 * time.Hour),
		Email:       "",
		FirstName:   "name",
		Gender:      1,
		IsUpdated:   false,
		LastName:    "family",
		Mobile:      a.mobileNumber,
		NidCity:     98,
		NidProvince: 8,
		TokenId:     nil,
	}

	var result ApanMultipleResponse
	err := a.request("api/Applications/SubmitSubscriber", data, &result, true)
	if err != nil {
		return err
	}

	if result[0].MessageModel[0].ErrorCode == 8 {
		// Successful sign up
		return nil
	}

	if result[0].MessageModel[0].ErrorCode == -1 {
		// Already a user, login
		return nil
	}

	return errors.New(result[0].MessageModel[0].ErrorString)
}
