package token

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"math"
	"otp/pkg/otpauth"
	"time"
)

type Token struct {
	FirstOtpLength  int    `json:"firstOtpLength"`
	SecondOtpLength int    `json:"secondOtpLength"`
	OtpLength       int    `json:"otpLength"`
	SecretKey       string `json:"secretKey,omitempty"`
	TimeInterval    int    `json:"otpGenerationPeriodInSeconds"`
	BankName        string
	AccountId       string
	Seed            string
}

func (t *Token) GenerateOtp1() (string, error) {
	return t.generateOtp(t.Seed, t.TimeInterval/1000, t.FirstOtpLength, sha1.New)
}

func (t *Token) GenerateOtp2() (string, error) {
	return t.generateOtp(t.Seed, t.TimeInterval/1000, t.SecondOtpLength, sha1.New)
}

func (t *Token) generateOtp(seed string, interval int, otpLength int, hashFunction func() hash.Hash) (string, error) {
	key, err := hex.DecodeString(seed)
	if err != nil {
		return "", err
	}

	now := make([]byte, 8)
	binary.BigEndian.PutUint64(now, uint64(time.Now().Unix()/int64(interval)))

	h := hmac.New(hashFunction, key)
	h.Write(now)
	hmacBytes := h.Sum(nil)

	offset := int(hmacBytes[len(hmacBytes)-1] & 15)
	otpNumber := binary.BigEndian.Uint32(hmacBytes[offset : offset+4])
	otpNumber &= 0x7FFFFFFF
	otpNumber %= uint32(math.Pow10(otpLength))
	otp := fmt.Sprintf("%d", otpNumber)
	// TODO: Should zeros be appended or prepended?
	for len(otp) < otpLength {
		otp += "0"
	}
	return otp, nil
}

func (t *Token) GeneralOtp1UrlFromToken() (string, error) {
	return t.generalOtpUrlWithUsername(t.BankName, t.AccountId, t.FirstOtpLength)
}

func (t *Token) GeneralOtp2UrlFromToken() (string, error) {
	return t.generalOtpUrlWithUsername(t.BankName, t.AccountId, t.SecondOtpLength)
}

func (t *Token) GeneralOtp1Url(title string) (string, error) {
	return t.generalOtpUrlWithUsername(title, "", t.FirstOtpLength)
}

func (t *Token) GeneralOtp1UrlWithUsername(title, username string) (string, error) {
	return t.generalOtpUrlWithUsername(title, username, t.FirstOtpLength)
}

func (t *Token) GeneralOtp2Url(title string) (string, error) {
	return t.generalOtpUrlWithUsername(title, "", t.SecondOtpLength)
}

func (t *Token) GeneralOtp2UrlWithUsername(title, username string) (string, error) {
	return t.generalOtpUrlWithUsername(title, username, t.SecondOtpLength)
}

func (t *Token) generalOtpUrlWithUsername(title, username string, digits int) (string, error) {
	key, err := hex.DecodeString(t.Seed)
	if err != nil {
		return "", err
	}

	secret := base32.StdEncoding.EncodeToString(key)

	otpAuth, err := otpauth.New(title, secret)
	if err != nil {
		return "", err
	}

	otpAuth.SetAccountName(username)
	otpAuth.SetDigit(digits)
	otpAuth.SetPeriod(t.TimeInterval / 1000)

	return otpAuth.String(), nil
}
