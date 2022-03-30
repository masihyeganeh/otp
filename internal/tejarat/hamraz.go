package tejarat

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/text/encoding/unicode/utf32"
	"log"
	. "otp/internal/structs"
	"otp/internal/token"
	. "otp/internal/utils"
	"strings"
	"time"
)

func init() {
	intermediateCA := `
-----BEGIN CERTIFICATE-----
MIIG5TCCBc2gAwIBAgIQYpljtSxigodzfcIhbki1cTANBgkqhkiG9w0BAQsFADCB
izELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMu
QS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEvMC0G
A1UEAxMmQ2VydHVtIE9yZ2FuaXphdGlvbiBWYWxpZGF0aW9uIENBIFNIQTIwHhcN
MTkwMjEzMTIyMzEwWhcNMjEwMjEyMTIyMzEwWjCBhzELMAkGA1UEBhMCSVIxLjAs
BgNVBAoMJVRlamFyYXQgQmFuayBDby4gKFB1YmxpYyBKb2ludCBTdG9jaykxCzAJ
BgNVBAsMAklUMQ8wDQYDVQQHDAZUZWhyYW4xDzANBgNVBAgMBlRlaHJhbjEZMBcG
A1UEAwwQKi50ZWphcmF0YmFuay5pcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMZtx32cD7d34gAnV7UZjubn5LC6H00rMyPreVFvMW6+GJcAWxKEGeUc
FcuqB4XzacYNZpAj+BNEHmf+EBEFGOdlLt6+aXzpiK1Wft30TziDueMk93Vo/mFH
AQHxvSVLt8E7YzGXtaxCGQJBq7XeLcEVJJdmf+nNeG/BbZTpdQJlW3rxvnNqYZoL
qBBuIERgamissnXMLi6FNa6fScVlSUhNefB23RmpuMb+yvEGXMKerU+LGW4/AL6P
2ZPEktU+K+L8zfoIl1iD5/NyqkPva6sGCW1P2/otcSXzNqYSzeBufE/WAp7/bDeJ
P36E/Hp2iPV8O5BMcY5ohzWkUqE8hUsCAwEAAaOCA0UwggNBMAwGA1UdEwEB/wQC
MAAwHwYDVR0jBBgwFoAU7u3oVGATCzWDoPprekY69z4wu2YwHQYDVR0OBBYEFJwF
I3YU3oM5bn9tZt3WM9xiPF+LMB0GA1UdEgQWMBSBEm92Y2FzaGEyQGNlcnR1bS5w
bDBxBggrBgEFBQcBAQRlMGMwKwYIKwYBBQUHMAGGH2h0dHA6Ly9vdmNhc2hhMi5v
Y3NwLWNlcnR1bS5jb20wNAYIKwYBBQUHMAKGKGh0dHA6Ly9yZXBvc2l0b3J5LmNl
cnR1bS5wbC9vdmNhc2hhMi5jZXIwSwYDVR0gBEQwQjAIBgZngQwBAgIwNgYLKoRo
AYb2dwIFAQIwJzAlBggrBgEFBQcCARYZaHR0cHM6Ly93d3cuY2VydHVtLnBsL0NQ
UzAyBgNVHR8EKzApMCegJaAjhiFodHRwOi8vY3JsLmNlcnR1bS5wbC9vdmNhc2hh
Mi5jcmwwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA4GA1UdDwEB/wQE
AwIFoDArBgNVHREEJDAighAqLnRlamFyYXRiYW5rLmlygg50ZWphcmF0YmFuay5p
cjCCAYAGCisGAQQB1nkCBAIEggFwBIIBbAFqAHcApLkJkLQYWBSHuxOizGdwCjw1
mAT5G9+443fNDsgN3BAAAAFo5ssJqAAABAMASDBGAiEA8KWvc40WEgOl6N8QFLTE
Apq8nWrV5lAzDfZP/3p6sh4CIQCKNpscUAu9r6m21rPFxOwTC3bhXvqb8NRl8YPI
rFUwwwB3AO5Lvbd1zmC64UJpH6vhnmajD35fsHLYgwDEe4l6qP3LAAABaObLCaYA
AAQDAEgwRgIhAMuiRVAKPU10zr9aBCbtHk4NwapyKCKm4ywodW3htPdaAiEApe/G
mioz9LW51jnoyMP+SYy2hEH5I4PAte36ijKIJGYAdgCHdb/nWXz4jEOZX73zbv9W
jUdWNv9KtWDBtOr/XqCDDwAAAWjmyws3AAAEAwBHMEUCIQDMhHaE+KdLS19PsSy8
Qs20EmXR6JyrDOKvxyvUyeZ4/gIgZ/7XNmId2/3/kPkJYvjHFL6WCeIptAx0GQew
z2feiEMwDQYJKoZIhvcNAQELBQADggEBAB/3fjIL4VU4f/I+8kZWbLrsvstHTfmV
NL5tESFfC0wb/wbzZrv98znyFREc6TUp9QzpU6T/37nmgNkttYkrKv0Qs+72LI3S
nEjk13HjwWIMm8XSGs7OJHVxa1SgqOI13ZHplwN49OVAVxAqSKM7vQxO25GmYwJr
Gl09EaszJT1bqsw1ehhSkKtbr2gLVqI1P5S5FBqNUvqSPBsftG6PodBLllp8o2aL
M4anrBgZDNlQxvkCTorKUycyWjYZhJBcqWpriAHgri47kSVgNTzQYcMAlhqwJyB7
uK7k5pVUSk4RvZhxVgLBs9A3v0US0ujehtlQd5GE72kItldjP9rcV4A=
-----END CERTIFICATE-----
`
	if err := AddCustomCA([]byte(intermediateCA)); err != nil {
		log.Fatalf("Could not add intermediate CA for RamzNegar")
	}
}

type Hamraz struct {
	imei         string
	deviceName   string
	manufacturer string
	modelNumber  string
	osVersion    string
	tokenId      string
	androidId    string
	mobileNumber string
	apiKey       string
	headers      map[string]string
}

func New(mobileNumber string) (*Hamraz, error) {
	return NewWithDevice(mobileNumber, "ABABABABABABABAB", "7.1.2")
}

func NewWithDevice(mobileNumber, androidId, osVersion string) (*Hamraz, error) {
	headers := map[string]string{
		"IMEI":       androidId,
		"OSVersion":  osVersion,
		"Agent":      "ANDROID",
		"PushToken":  "cp9szjikl-Y:APA91bEPCXAhClpg94_fHn4RUYP25c2L0ol73lvhs3fi7UZPiry0Kt9L2Eovg5uFhz_8WGtvlqclZM-mCzqM-iB4WEM8PSpAROB41CJDMCphuvG3GL3X6aFOjVAVV-mrd9DLdru1XNci",
		"AppVersion": "1.8.3",
		"api_key":    "",
		"user_id":    "0",
		"Signature":  "ag/bI9aiY4n2lY6C2BRTtg+hFGQmiZeAa1SqctGnlp+KGPfT2p8HCInPCey7oKUyHvxKn9eoLUOk0v6n2NqLnQ==",
	}
	return &Hamraz{
		imei:         androidId,
		osVersion:    osVersion,
		androidId:    androidId,
		mobileNumber: mobileNumber,
		apiKey:       "",
		headers:      headers,
	}, nil
}

/*
func (h *Hamraz) SetApiKey(apiKey string) {
	h.apiKey = apiKey
}
*/

func (h *Hamraz) request(path string, params interface{}, result interface{}) error {
	var payload []byte = nil
	var err error

	if params != nil {
		payload, err = json.Marshal(params)
		if err != nil {
			return err
		}
	}

	uri := "https://otp.tejaratbank.ir/api/" + path
	_, err = Request(uri, h.headers, payload, &result)
	return err
}

func (h *Hamraz) GetChannels() ([]HamrazChannel, error) {
	var result HamrazChannelsResponse

	err := h.request("Totp/getChannelsInfo", nil, &result)
	if err != nil {
		return nil, err
	}

	if result.ResultCode != 0 {
		return nil, errors.New(result.ResponseDescEn)
	}

	return result.ChannelPojoList, nil
}

func (h *Hamraz) AddCard(cardNumber, serialNumber, activationCode string, channel HamrazChannel) (*token.Token, error) {
	params := HamrazVerificationRequest{
		ActivationCode: activationCode,
		ChannelID:      channel.ChannelID,
		LoginID:        cardNumber,
		PhoneID:        h.androidId,
		TokenSerialNo:  serialNumber,
		DateAndTimeMil: int(time.Now().Unix()),
	}

	var result HamrazGeneralResponse

	err := h.request("Totp/Verification", params, &result)
	if err != nil {
		return nil, err
	}

	if result.ResultCode != 0 {
		return nil, errors.New(result.ResponseDescEn)
	}

	seed := []byte(serialNumber + activationCode)
	seed, err = utf32.UTF32(utf32.LittleEndian, utf32.IgnoreBOM).NewEncoder().Bytes(seed)
	if err != nil {
		return nil, err
	}

	hashFunc := sha1.New()
	hashFunc.Write(seed)
	seed = hashFunc.Sum(nil)

	return &token.Token{
		FirstOtpLength:  channel.OtpDigitCount,
		SecondOtpLength: channel.OtpDigitCount,
		OtpLength:       channel.OtpDigitCount,
		SecretKey:       "",
		TimeInterval:    channel.OtpTimeStep * 1000,
		BankName:        "Tejarat",
		AccountId:       cardNumber,
		Seed:            strings.ToUpper(hex.EncodeToString(seed)),
	}, nil
}
