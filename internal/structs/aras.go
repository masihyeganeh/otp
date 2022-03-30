package structs

import "otp/internal/token"

type TokenActivationData struct {
	Pin              string `json:"pin"`
	Token            string `json:"token"`
	VerificationCode string `json:"verificationCode"`
}

type ArasTokenActivation struct {
	Cif               string `json:"cif"`
	CipherMessage     string `json:"cipherMessage"`
	GenerateFirstOtp  bool   `json:"generateFirstOtp"`
	GenerateSecondOtp bool   `json:"generateSecondOtp"`
	PublicKey         string `json:"publicKey"`
}

type ArasTokenActivationResponse struct {
	Exception string       `json:"exception"`
	Success   bool         `json:"success"`
	Result    *token.Token `json:"result"`
}

type QrData struct {
	ChannelNameInAAServer  string `json:"channelNameInAAServer"`
	ServiceChannelOtpType  string `json:"serviceChannelOtpType"`
	Cif                    string `json:"cif"`
	PinLength              int    `json:"pinLength"`
	Token                  string `json:"token"`
	TokenGeneratedTime     int64  `json:"tokenGeneratedTime"`
	TokenTimeToLiveSeconds int64  `json:"tokenTimeToLiveSeconds"`
	VerificationCodeLength int    `json:"verificationCodeLength"`
	Version                int    `json:"version"`
}
