package sina

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"otp/internal/encryption/asymmetric"
	"otp/internal/encryption/symmetric"
	. "otp/internal/structs"
	"otp/internal/token"
	. "otp/internal/utils"
)

func Activate(token, verificationCode, pin, cif, channelNameInAAServer string, tokenGeneratedTime int64) (*token.Token, error) {
	urlPath := "activate"
	if channelNameInAAServer == "CARD_SECOND" {
		urlPath = "activateSecondPassword"
	}

	asymmetricKeys, err := asymmetric.GenerateKeys("AzeNaz8WLNMuhvcqh2Yw8ode2YcECc+2odGdjTfhx1G7")
	if err != nil {
		return nil, err
	}

	tokenActivationData := TokenActivationData{
		Pin:              pin,
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

	responseToken, err := activateToken(urlPath, cif, asymmetricKeys.PublicKey, cipherMessage, channelNameInAAServer, tokenGeneratedTime)
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

	responseToken.Seed = string(secret) + pin
	return responseToken, nil
}

func activateToken(urlPath, cif, publicKey, cipherMessage, channelNameInAAServer string, qrGenerationDate int64) (*token.Token, error) {
	post := SinaTokenActivation{
		Cif:                   cif,
		CipherMessage:         cipherMessage,
		ChannelNameInAAServer: channelNameInAAServer,
		QrGenerationDate:      qrGenerationDate,
		PublicKey:             publicKey,
		Version:               2,
		BankName:              "SI",
		MobileOS:              "Android",
		MobileVersion:         "3.2.0",
	}

	payload, _ := json.Marshal(post)

	var resp SinaTokenActivationResponse
	_, err := Request("http://www.sina24h.com:2007/mobilebanking/otpAppServer/otpAppServer/"+urlPath, nil, payload, &resp)
	if err != nil {
		return nil, err
	}

	if len(resp.ErrorCode) > 0 {
		return nil, errors.New(resp.ErrorCode)
	}

	return &resp.Token, nil
}
