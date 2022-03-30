package rima

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"otp/internal/encryption/symmetric"
	. "otp/internal/structs"
	. "otp/internal/utils"
	"otp/pkg/otpauth"
	"regexp"
	"strconv"
	"strings"
)

type Rima struct {
	DeviceModel  string
	DeviceSerial string
	OsVersion    string
	DeviceType   string
	IMEI         string
	MobileNo     string
	AppVersion   string
}

var nonAlphaNumericPattern = regexp.MustCompile("[[:^alnum:]]")
var plainTextPattern = regexp.MustCompile("(\\w*)/(\\d)/(\\d{8})")
var accountInfoPattern = regexp.MustCompile("(\\d{6})-(\\d{4})-(\\d)")
var smsCodePattern = regexp.MustCompile("(\\d{6})-(\\d{4})-(\\w{96})")
var banks = map[string]string{
	"507677": "NOOR",
	"627488": "KARAFARIN",
	"636795": "MARKAZI",
	"603769": "SADERAT",
	"603770": "KESHAVARZI",
	"636214": "AYANDEH",
	"603799": "MELI",
	"627648": "EDB",
}

func init() {
	intermediateCA := `
-----BEGIN CERTIFICATE-----
MIIGaTCCBVGgAwIBAgIQESI12sqgf7X27zPdLUSqTjANBgkqhkiG9w0BAQsFADCB
hTELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMu
QS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEpMCcG
A1UEAxMgQ2VydHVtIERvbWFpbiBWYWxpZGF0aW9uIENBIFNIQTIwHhcNMTkwOTA3
MDcwNjA1WhcNMjEwOTA2MDcwNjA1WjAmMRcwFQYDVQQDDA5zb3RwLmlzYy5jby5p
cjELMAkGA1UEBhMCSVIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDH
kWqKPJk9NugFYoSZvjf/jMjx3PUhiPLtBJEB9JcruOzMcVMBElQfMMvHrI0S8L+6
nHC5AHpCwm0JCcpW9AucCC85UrRv6G5rG9VSSUB26IXviHrsKUtpbphVL3qydp6S
37tv23GDYpRoneKqlj9CfUXdPbpQ1mxGM1OIeOZ9lp7o9MTZL2NHBfDI2G9dqlUE
jorTH5y040EyVheMUCoSuzLcCjjiPWz39R/6PRfsdd3KQ9QYVpOSc26KqR9Jrazp
pgfDuV51usbngIfCq0xxnXI8bTyUzcHL5WYv/OQ+Xa0aasEW2axo48iEIu0dajza
KJhEJTi/0uTf8428dCFHAgMBAAGjggMxMIIDLTAMBgNVHRMBAf8EAjAAMDIGA1Ud
HwQrMCkwJ6AloCOGIWh0dHA6Ly9jcmwuY2VydHVtLnBsL2R2Y2FzaGEyLmNybDBx
BggrBgEFBQcBAQRlMGMwKwYIKwYBBQUHMAGGH2h0dHA6Ly9kdmNhc2hhMi5vY3Nw
LWNlcnR1bS5jb20wNAYIKwYBBQUHMAKGKGh0dHA6Ly9yZXBvc2l0b3J5LmNlcnR1
bS5wbC9kdmNhc2hhMi5jZXIwHwYDVR0jBBgwFoAU5TGtvzoRlvSDvFA81LeQm5Du
3iUwHQYDVR0OBBYEFMikY5muE5TvDOAGjt8vViHp4PWnMB0GA1UdEgQWMBSBEmR2
Y2FzaGEyQGNlcnR1bS5wbDBLBgNVHSAERDBCMAgGBmeBDAECATA2BgsqhGgBhvZ3
AgUBAzAnMCUGCCsGAQUFBwIBFhlodHRwczovL3d3dy5jZXJ0dW0ucGwvQ1BTMB0G
A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAOBgNVHQ8BAf8EBAMCBaAwGQYD
VR0RBBIwEIIOc290cC5pc2MuY28uaXIwggF+BgorBgEEAdZ5AgQCBIIBbgSCAWoB
aAB1AO5Lvbd1zmC64UJpH6vhnmajD35fsHLYgwDEe4l6qP3LAAABbQqG9fUAAAQD
AEYwRAIgPUgI/7UwM+aWkwW3XYClrk5pu92q1fMhwbaZYKbisd4CIFddP2IDv4XX
ndyiC0eQIukYPlJouw+l9hU3nTB/9qv9AHYApLkJkLQYWBSHuxOizGdwCjw1mAT5
G9+443fNDsgN3BAAAAFtCobz5wAABAMARzBFAiEA23Fn7fnqo5/u5bAuw8vq7hrB
NuFK4PTCIb3umyCygRACIHAdXywnztfdVJXS9J27ceQX7w9Gn3CUD5BFGucIC/3O
AHcAVYHUwhaQNgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0wwAAAFtCob0EwAABAMA
SDBGAiEA8dq0az5I9wcvwv0x0NP/58lTDy2O8MGD08A5m1GqdNICIQC55+RmI+7C
3jLC5AB8SGUWAu7ulXzrEw/LHy3fRslXSzANBgkqhkiG9w0BAQsFAAOCAQEAK90O
ypKYHuMuJFiojczIsuncZRyJIlXkCadkMuPSrstQhaCapthsxxOlo/QJV9z7EVRy
mb29QRklXh3PXzSwjTbLjrJNkLZRewK6x42eAhfEXaLNrYHhEkpHICme5gkMQmy1
ON3TRnvjKH6M4VZSNLygOZ/7B6maVMJJY1wESNzWMQM783WG+HKN13VlRRI11AAm
qa3ej9bo0UQwX6dipDGCAdP3HXdL8sw3OBeSOpRMAFQegLCXclpX1AqrXUs7J+Aj
K3ayvNwLu39WCoHh/z1qlntkitrfGITOWNWtTanvBhwn/tR7kRuNyBB1kgYnhhoe
EjzSqWIGyU8MhicsBQ==
-----END CERTIFICATE-----
`
	if err := AddCustomCA([]byte(intermediateCA)); err != nil {
		log.Fatalf("Could not add intermediate CA for RamzNegar")
	}
}

func New(mobileNumber, imei string) *Rima {
	if len(imei) > 16 {
		imei = imei[0:16]
	} else if len(imei) < 16 {
		imei = fmt.Sprintf("%16s", imei)
		imei = strings.ReplaceAll(imei, " ", "A")
		imei = nonAlphaNumericPattern.ReplaceAllString(imei, "A")
	}

	return &Rima{
		DeviceModel:  "Build.MODEL",           // TODO
		DeviceSerial: "serial",                // TODO
		OsVersion:    "Build.VERSION.RELEASE", // TODO
		DeviceType:   "ANDROID",
		IMEI:         imei,
		MobileNo:     mobileNumber,
		AppVersion:   "1.2",
	}
}

func (r *Rima) Register() (int, error) {
	post := RimaRegisterRequest{
		CurrentTime:    TimestampMs(),
		DeviceModel:    r.DeviceModel,
		DeviceSerial:   r.DeviceSerial,
		DeviceType:     r.DeviceType,
		IMEI:           r.IMEI,
		MobileNo:       r.MobileNo,
		OsVersion:      r.OsVersion,
		AppVersion:     r.AppVersion,
		IdentifierType: "1",
	}

	payload, _ := json.Marshal(post)

	var resp RimaRegisterResponse
	_, err := Request("https://sotp.isc.co.ir/mobile/register", nil, payload, &resp)
	if err != nil {
		return 0, err
	}

	if resp.Code != "ok" && resp.MessageEn != nil {
		return 0, errors.New(*resp.MessageEn)
	}

	return resp.RegisterCode, nil
}

func (r *Rima) Activate(activationCode string, registerCode int) (string, error) {
	post := RimaActivateRequest{
		ActivationCode: activationCode,
		DeviceModel:    r.DeviceModel,
		DeviceSerial:   r.DeviceSerial,
		OsVersion:      r.OsVersion,
		DeviceType:     r.DeviceType,
		IMEI:           r.IMEI,
		MobileNo:       r.MobileNo,
		RegisterCode:   strconv.Itoa(registerCode),
	}

	payload, _ := json.Marshal(post)

	var resp RimaActivateResponse
	_, err := Request("https://sotp.isc.co.ir/mobile/activate", nil, payload, &resp)
	if err != nil {
		return "", err
	}

	if resp.Code != "ok" && resp.MessageEn != nil {
		return "", errors.New(*resp.MessageEn)
	}

	if resp.IMEI != nil {
		r.IMEI = *resp.IMEI
	}

	return resp.Key, nil
}

func (r *Rima) GenerateSeed(activationKey, gatewayCode, smsCode string) (string, error) {
	gatewayCode = strings.TrimSpace(gatewayCode)
	smsCode = strings.TrimSpace(smsCode)

	if !smsCodePattern.MatchString(smsCode) {
		return "", errors.New("sms code is in wrong format")
	}

	accountInfo := accountInfoPattern.FindStringSubmatch(smsCode[0:13])
	if accountInfo == nil || len(accountInfo) == 0 {
		return "", errors.New("sms code is in wrong format")
	}

	key, err := base64.StdEncoding.DecodeString(activationKey)
	if err != nil {
		return "", err
	}

	encryptionDataStr := strings.ToUpper(smsCode[13:]) + strings.ToUpper(gatewayCode)
	encryptedData, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encryptionDataStr)
	if err != nil {
		return "", err
	}

	encryption := symmetric.NewAES(key, symmetric.CBC, symmetric.Pkcs5)
	plainText, err := encryption.Decrypt(encryptedData, []byte(r.IMEI))
	if err != nil {
		return "", err
	}

	data := plainTextPattern.FindStringSubmatch(string(plainText))
	if data == nil || len(data) == 0 {
		return "", errors.New("input data does not match")
	}

	secret := data[1]
	otpType := ""
	digits := 0
	switch data[2] {
	case "1":
		otpType = "OTP1"
		digits = 6
	case "2":
		otpType = "OTP2"
		digits = 7
	default:
		return "", errors.New("cannot handle this type of otp")
	}

	if accountInfo[3] != data[2] {
		return "", errors.New("input data does not match")
	}
	bank, ok := banks[accountInfo[1]]
	if !ok {
		bank = "Bank"
	}

	username := fmt.Sprintf("%s [%s %sXX XXXX %s]", otpType, accountInfo[1][0:4], accountInfo[1][4:6], accountInfo[2])

	otpAuth, err := otpauth.New(bank, secret)
	if err != nil {
		return "", err
	}

	otpAuth.SetAccountName(username)
	otpAuth.SetDigit(digits)
	otpAuth.SetPeriod(60)
	otpAuth.SetAlgorithm(otpauth.AlgorithmSHA256)

	return otpAuth.String(), nil
}
