package ghavamin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"log"
	. "otp/internal/structs"
	. "otp/internal/utils"
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

type GbRamz struct {
	deviceInfo   string
	imei         string
	ipAddress    string
	mobileNumber string
	apiKey       string
	headers      map[string]string
	publicKey    string
	uniqueId     string
	signature    string
}

func New(mobileNumber string) (*GbRamz, error) {
	return NewWithDevice(mobileNumber, "ABABABABABABABAB", "shamu", "SM-J3110", "7.1.2", "N", "172.17.100.15")
}

func NewWithDevice(mobileNumber, imei, buildDevice, buildModel, androidVersion, androidVersionCode, ipAddress string) (*GbRamz, error) {
	deviceInfo := fmt.Sprintf("%s %s %s %s", buildDevice, buildModel, androidVersion, androidVersionCode)
	publicKey, uniqueId, signature, err := generateSecrets()
	if err != nil {
		return nil, err
	}

	return &GbRamz{
		deviceInfo:   deviceInfo,
		imei:         imei,
		ipAddress:    ipAddress,
		mobileNumber: mobileNumber,
		publicKey:    publicKey,
		uniqueId:     uniqueId,
		signature:    signature,
		headers:      map[string]string{"Authorization": "Basic YWxpOjEyMzQ1Ng=="}, // ali:123456
	}, nil
}

func generateSecrets() (string, string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}

	Modulus := base64.StdEncoding.EncodeToString(privateKey.PublicKey.N.Bytes())
	//Exponent := base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(privateKey.PublicKey.E)))
	Exponent := "AQAB" // Why java?
	publicKey := `<?xml version="1.0" encoding="UTF-8"?><RSAKeyValue><Modulus>` + Modulus + `</Modulus><Exponent>` + Exponent + `</Exponent></RSAKeyValue>`

	uniqueId := uuid.New().String()

	h := sha256.New()
	h.Write([]byte(uniqueId))
	d := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, d)
	if err != nil {
		panic(err)
	}

	encodedSig := base64.StdEncoding.EncodeToString(signature)

	return publicKey, uniqueId, encodedSig, nil
}

func (g *GbRamz) Authenticate() error {
	post := GbRamzAuthenticationRequest{
		AuthenticationTypeIs: 1,
		MobileNumber:         g.mobileNumber,
		Imei:                 g.imei,
		IPAddress:            g.ipAddress,
		MobileModelName:      g.deviceInfo,
		PublicKey:            g.publicKey,
	}

	payload, _ := json.Marshal(post)

	var resp GbRamzResponse
	_, err := Request("https://otp.ghbi.ir/api/Authentication/", g.headers, payload, &resp)
	if err != nil {
		return err
	}

	if resp.ResponseCode != 0 {
		return errors.New(resp.ResponseDesc)
	}

	return nil
}

func (g *GbRamz) Activate(activationCode string) (interface{}, error) {
	post := GbRamzActivationRequest{
		MobileNumber:   g.mobileNumber,
		Imei:           g.imei,
		ActivationCode: activationCode,
	}

	payload, _ := json.Marshal(post)

	var resp GbRamzResponse
	_, err := Request("https://otp.ghbi.ir/api/Activation", g.headers, payload, &resp)
	if err != nil {
		return nil, err
	}

	if resp.ResponseCode != 0 {
		return nil, errors.New(resp.ResponseDesc)
	}

	return resp.ActivationCode, nil
}

func (g *GbRamz) GenerateOtp(activationCodePrinted, activationCodeSmsed string) (interface{}, error) {
	post := GbRamzOtpGenerateRequest{
		MobileNumber:          g.mobileNumber,
		Imei:                  g.imei,
		ActivationCodePrinted: activationCodePrinted,
		ActivationCodeSmsed:   activationCodeSmsed,
		OtpDuration:           0,
		Data:                  g.uniqueId,
		Sign:                  g.signature,
	}

	payload, _ := json.Marshal(post)

	var resp GbRamzResponse
	_, err := Request("https://otp.ghbi.ir/api/OtpGenerate", g.headers, payload, &resp)
	if err != nil {
		return nil, err
	}

	if resp.ResponseCode != 0 {
		return nil, errors.New(resp.ResponseDesc)
	}

	// Seed : DES/CBC/NoPadding hexDecode(OtpKey) with "rvfnaped" as key and 8 zeros as iv
	// OTP is 4 digits for pass1 and 7 digits for pass2

	return resp.ActivationCode, nil
}
