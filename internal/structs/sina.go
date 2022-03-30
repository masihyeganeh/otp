package structs

import "otp/internal/token"

type SinaTokenActivation struct {
	Cif                   string `json:"cif"`
	CipherMessage         string `json:"cipherMessage"`
	ChannelNameInAAServer string `json:"channelNameInAAServer"`
	QrGenerationDate      int64  `json:"qrGenerationDate"`
	PublicKey             string `json:"publicKey"`
	Version               int    `json:"version"`
	BankName              string `json:"bankName"`
	MobileOS              string `json:"mobileOS"`
	MobileVersion         string `json:"mobileVesion"`
}

type SinaTokenActivationResponse struct {
	ErrorCode string `json:"errorCode"`
	Version   int    `json:"version"`
	token.Token
}
