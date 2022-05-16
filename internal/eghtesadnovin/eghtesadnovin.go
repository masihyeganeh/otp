package eghtesadnovin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"otp/internal/encryption/asymmetric"
	"otp/internal/encryption/symmetric"
	. "otp/internal/structs"
	"otp/internal/token"
	. "otp/internal/utils"
)

type OtpType string

const (
	CardFirstPassword   OtpType = "CARD_FIRST_PASSWORD"
	CardSecondPassword  OtpType = "CARD_SECOND_PASSWORD"
	ModernFirstPassword OtpType = "MODERN_FIRST_PASSWORD"
)

func (o OtpType) String() string {
	return string(o)
}

type EghtesadNovin struct {
	baseURL string
	headers map[string]string
}

func New(androidId string) *EghtesadNovin {
	return &EghtesadNovin{
		baseURL: "https://modern.enbank.ir/daraserver/",
		headers: map[string]string{
			"accept":     "application/json",
			"device-dna": androidId,
			"time-zone":  "IRST",
			"platform":   "android",
			"version":    "5.6.23",
			"apptype":    "otp",
			"lang":       "fa_ir",
			"User-Agent": "okhttp/4.9.1",
		},
	}
}

func (e *EghtesadNovin) NewSession() error {
	var resp EghtesadNovinGeneralResponse
	_, err := Request(e.baseURL+"login/session", e.headers, nil, &resp)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("error %s : %s", resp.Error.Key, resp.Error.Message)
	}

	return nil
}

func (e *EghtesadNovin) SignIn(username, password string) (*EghtesadNovinSignInResponse, error) {
	req := EghtesadNovinSignInRequest{
		Username:   username,
		Password:   password,
		Type:       "usernamePassword",
		ChannelKey: "internetBank",
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	var resp EghtesadNovinSignInResponse
	_, err = Request(e.baseURL+"login/signin", e.headers, payload, &resp)
	if err != nil {
		return nil, err
	}

	for _, constraint := range resp.Constraints {
		if constraint == "ticket" {
			err = e.SendTicket()
			if err != nil {
				return nil, err
			}
		}
	}

	return &resp, err
}

func (e *EghtesadNovin) SendTicket() error {
	req := EghtesadNovinGenerateTicketRequest{
		ServiceInfo: EghtesadNovinGenerateTicketRequestServiceInfo{
			Source: EghtesadNovinGenerateTicketRequestServiceInfoSource{
				Type:  "CHANNEL",
				Value: "INTERNET_BANK",
			},
			Type: "TWO_PHASE_LOGIN",
		},
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}

	var resp EghtesadNovinGeneralResponse
	_, err = Request(e.baseURL+"customers/generateTicket", e.headers, payload, &resp)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("error %s : %s", resp.Error.Key, resp.Error.Message)
	}

	return nil
}

func (e *EghtesadNovin) SignInWithPin(pin string) error {
	req := EghtesadNovinTwoFactorRequest{
		Constraints: EghtesadNovinTwoFactorRequestConstraints{
			Ticket: pin,
		},
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}

	var resp EghtesadNovinGeneralResponse
	_, err = Request(e.baseURL+"login/signin/twoFactor", e.headers, payload, &resp)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("error %s : %s", resp.Error.Key, resp.Error.Message)
	}

	return nil
}

func (e *EghtesadNovin) GenerateToken(otpType OtpType) (*EghtesadNovinOtpConfig, error) {
	req := EghtesadNovinGenerateTokenRequest{
		OtpTokenGenerationType: otpType.String(),
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	var resp EghtesadNovinOtpConfig
	_, err = Request(e.baseURL+"otp/generateToken", e.headers, payload, &resp)
	return &resp, err
}

func (e *EghtesadNovin) Activate(token, verificationCode, cif string, otpType OtpType) (*token.Token, error) {
	asymmetricKeys, err := asymmetric.GenerateKeys("AjKuAoul8hkDP9450u+Iqo5bS/rXMcdHR1PJv0vSiGO0")
	if err != nil {
		return nil, err
	}

	tokenActivationData := EghtesadNovinTokenActivationData{
		Token:            token,
		VerificationCode: verificationCode,
	}

	payload, err := json.Marshal(tokenActivationData)
	if err != nil {
		return nil, err
	}

	syncEncryption := symmetric.NewAES(asymmetricKeys.SharedKey, symmetric.CBC, symmetric.Pkcs7)
	iv := make([]byte, 16)
	payload, err = syncEncryption.Encrypt(payload, iv)
	if err != nil {
		return nil, err
	}

	cipherMessage := base64.StdEncoding.EncodeToString(payload)

	responseToken, err := e.activateToken(cif, otpType, asymmetricKeys.PublicKey, cipherMessage)
	if err != nil {
		return nil, err
	}

	secret, err := base64.StdEncoding.DecodeString(responseToken.SecretKey)
	if err != nil {
		return nil, err
	}
	responseToken.SecretKey = ""

	secret, err = syncEncryption.Decrypt(secret, iv)
	if err != nil {
		return nil, err
	}

	responseToken.Seed = string(secret)
	return responseToken, nil
}

func (e *EghtesadNovin) activateToken(cif string, otpType OtpType, publicKey string, cipherMessage string) (*token.Token, error) {
	post := EghtesadNovinOtpActivationRequest{
		Username:      cif,
		Type:          otpType.String(),
		PublicKey:     publicKey,
		CipherMessage: cipherMessage,
	}

	payload, _ := json.Marshal(post)

	var resp EghtesadNovinOtpActivationResponse
	_, err := Request(e.baseURL+"otp/activate", nil, payload, &resp)
	if err != nil {
		return nil, err
	}

	return &token.Token{
		FirstOtpLength:  resp.OtpLength,
		SecondOtpLength: resp.OtpLength,
		OtpLength:       resp.OtpLength,
		SecretKey:       resp.SecretKey,
		TimeInterval:    resp.OtpGenerationPeriod,
		BankName:        "Eghtesad Novin",
		AccountId:       cif,
	}, nil
}

func (e *EghtesadNovin) Logout() error {
	var resp EghtesadNovinGeneralResponse
	_, err := Request(e.baseURL+"logout", e.headers, nil, &resp)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("error %s : %s", resp.Error.Key, resp.Error.Message)
	}

	return nil
}
