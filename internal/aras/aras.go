package aras

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

func Activate(bank Bank, token, verificationCode, pin, cif string, generateFirstOtp, generateSecondOtp bool) (*token.Token, error) {
	asymmetricKeys, err := asymmetric.GenerateKeys("AjKuAoul8hkDP9450u+Iqo5bS/rXMcdHR1PJv0vSiGO0")
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

	responseToken, err := activateToken(bank, cif, asymmetricKeys.PublicKey, cipherMessage, generateFirstOtp, generateSecondOtp)
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

func activateToken(bank Bank, cif string, publicKey string, cipherMessage string, generateFirstOtp bool, generateSecondOtp bool) (*token.Token, error) {
	post := ArasTokenActivation{
		Cif:               cif,
		CipherMessage:     cipherMessage,
		GenerateFirstOtp:  generateFirstOtp,
		GenerateSecondOtp: generateSecondOtp,
		PublicKey:         publicKey,
	}

	payload, _ := json.Marshal(post)

	var resp ArasTokenActivationResponse
	_, err := Request(bank.URL, nil, payload, &resp)
	if err != nil {
		return nil, err
	}

	if len(resp.Exception) > 0 {
		return nil, errors.New(resp.Exception)
	}

	return resp.Result, nil
}
