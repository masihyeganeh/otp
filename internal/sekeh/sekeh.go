package sekeh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"log"
	"otp/internal/encryption/asymmetric"
	"otp/internal/encryption/symmetric"
	. "otp/internal/structs"
	. "otp/internal/utils"
	"regexp"
	"strings"
)

func init() {
	intermediateCA := `
-----BEGIN CERTIFICATE-----
MIIGgzCCBWugAwIBAgIQfrr6ufggnyrESQUDpIKJrTANBgkqhkiG9w0BAQsFADCB
hTELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMu
QS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEpMCcG
A1UEAxMgQ2VydHVtIERvbWFpbiBWYWxpZGF0aW9uIENBIFNIQTIwHhcNMTkwNTI1
MDc0NTAxWhcNMjEwNTI0MDc0NTAxWjArMQswCQYDVQQGEwJJUjEcMBoGA1UEAwwT
Ki5icG0uYmFua21lbGxhdC5pcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAMpsQTXoct2b3dI4yctu4ECWNj1Y1p9TIMO5PyBcTCkLv25ztb6WXa5bippM
CM2WW0oc/EF0dkPZ/Zimx1BqrcCbCMNXstAtDhblgC071HtYxZGMk7Ms5WphMdeI
DgBiX5wWK6XwXUnf5+0hMSBVNusFow/lnnRldvOoXUJn49jq8iZhpUFIMYJhHG1e
qvkOxSfCtobqyuyFquTuZ6Jbi/oH/7EgX6iInQRcRuZxVQKLjLcc2Kkl1NhcvnRH
NhFmZ2Off2NNb3a70UTyfUgeFxk+Ez33lCispqp98zfhPaZ3GgMl9DS+lXMnz2vc
SJppwN4k30k75BPzsX9ywPqKeOUCAwEAAaOCA0YwggNCMAwGA1UdEwEB/wQCMAAw
MgYDVR0fBCswKTAnoCWgI4YhaHR0cDovL2NybC5jZXJ0dW0ucGwvZHZjYXNoYTIu
Y3JsMHEGCCsGAQUFBwEBBGUwYzArBggrBgEFBQcwAYYfaHR0cDovL2R2Y2FzaGEy
Lm9jc3AtY2VydHVtLmNvbTA0BggrBgEFBQcwAoYoaHR0cDovL3JlcG9zaXRvcnku
Y2VydHVtLnBsL2R2Y2FzaGEyLmNlcjAfBgNVHSMEGDAWgBTlMa2/OhGW9IO8UDzU
t5CbkO7eJTAdBgNVHQ4EFgQUdRmXNXjX4cixwouegO+PAxq851kwHQYDVR0SBBYw
FIESZHZjYXNoYTJAY2VydHVtLnBsMEsGA1UdIAREMEIwCAYGZ4EMAQIBMDYGCyqE
aAGG9ncCBQEDMCcwJQYIKwYBBQUHAgEWGWh0dHBzOi8vd3d3LmNlcnR1bS5wbC9D
UFMwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIF
oDAxBgNVHREEKjAoghMqLmJwbS5iYW5rbWVsbGF0LmlyghFicG0uYmFua21lbGxh
dC5pcjCCAXsGCisGAQQB1nkCBAIEggFrBIIBZwFlAHUApLkJkLQYWBSHuxOizGdw
Cjw1mAT5G9+443fNDsgN3BAAAAFq7e6slgAABAMARjBEAiAXRR4Sriospirkm4Ho
9nbXzQ9vJ99DALeA0V/WeLPGjwIgXg6FWfrU+YgUnqNAaEZaLliSzAPTDs2d1qxJ
exLOjqUAdQDuS723dc5guuFCaR+r4Z5mow9+X7By2IMAxHuJeqj9ywAAAWrt7qyX
AAAEAwBGMEQCICFXMTU2wgBkfYKDxY1XZhOOGzwNkUOCUeA0rQVQj8U5AiBl2dXp
4YC6XYgYesXr4IHfTQYCKviK6vuJPoMOM0TXgQB1AId1v+dZfPiMQ5lfvfNu/1aN
R1Y2/0q1YMG06v9eoIMPAAABau3urb4AAAQDAEYwRAIgZPudmVaCGulhPceh+yHS
wRhOJ1K4kPa2o0begXYejCcCIFv0EaCfPR3Z63WDj5KReWKSaLTb/5KC6/LfEC+P
pb24MA0GCSqGSIb3DQEBCwUAA4IBAQCHuEx9AjLhwdzYh4WInASkLrbM2KyuFQ/x
bNw1EkwcwP68V9PkYIiZ2cCNBI08yF0oklqYKKags0AJvdFKXZcVeVMHHod7Wfst
4PQgTzYLHhE5v19txUQ9sNaesU3AzXNkyFxplLN5NZXs03c5RpTGY19sNE6a+fIE
cNWWqcfKI/9VbW02FzJUiNOM0YYoBl24QWH0M6KrleulGf2gwyd1Q6HOd1lNFFzI
Xi0Cj1j5b12awU358eytpdEUHrE97wftEtoccRL+99+rsCD6D+cUqiqLFQwd5ncX
pqbnmSxuULW5jcz4+vdGja1OE+LN3D0ZNgmwlszn5n4qUf9/SojO
-----END CERTIFICATE-----
`
	if err := AddCustomCA([]byte(intermediateCA)); err != nil {
		log.Fatalf("Could not add intermediate CA for Sekeh")
	}
}

var phoneNumberPattern = regexp.MustCompile("^(09|\\+989|00989)")

type Sekeh struct {
	imei              string
	deviceName        string
	manufacturer      string
	modelNumber       string
	osVersion         string
	sessionKey        []byte
	wrappedSessionKey string
	tokenId           string
	androidId         string
	mobileNumber      string
}

func New(mobileNumber string) (*Sekeh, error) {
	return NewWithDevice(mobileNumber, "ABABABABABABABAB", "Xiaomi", "Mi 9T", "29")
}

func NewWithDevice(mobileNumber, androidId, buildManufacturer, buildModel, osVersion string) (*Sekeh, error) {
	mobileNumber = phoneNumberPattern.ReplaceAllString(mobileNumber, "989")
	sessionKey, wrappedSessionKey, err := generateSessionKey()
	if err != nil {
		return nil, err
	}

	h := sha256.New()
	h.Write([]byte(androidId))
	androidId = hex.EncodeToString(h.Sum(nil))[:16]

	return &Sekeh{
		imei:              androidId,
		deviceName:        buildManufacturer + " " + buildModel,
		manufacturer:      buildManufacturer,
		modelNumber:       buildModel,
		osVersion:         osVersion,
		sessionKey:        sessionKey,
		wrappedSessionKey: wrappedSessionKey,
		androidId:         androidId,
		mobileNumber:      mobileNumber,
	}, nil
}

func generateSessionKey() ([]byte, string, error) {
	pubPem := `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVSNDQlVBMy2Wh4J3usrQydpwI
zY6FwqDwV0Dd+Bk6PA5sc3usQ8mmjLiI2Yp1RDv4jjvmAdkXK+HXuxm2fI6XeIQv
gnPRaaj9yNcJnFNViogidcFO7Kg2YYj8yj6DgnCkAugJeUx2DVvyPnv+Vk1q37Tg
4qW0dEFNkWL9hKXGSwIDAQAB
-----END PUBLIC KEY-----
`

	pub, err := asymmetric.RsaPublicKeyFromPem([]byte(strings.TrimSpace(pubPem)))
	if err != nil {
		return nil, "", err
	}

	sessionKey := []byte(uuid.New().String())

	key, err := rsa.EncryptPKCS1v15(rand.Reader, pub, sessionKey)
	if err != nil {
		return nil, "", err
	}

	wrappedKey := base64.StdEncoding.EncodeToString(key)

	return sessionKey, wrappedKey, nil
}

func (s *Sekeh) request(path string, params interface{}) (*SekehResponse, error) {
	data := SekehRequest{
		CommandParams: params,
		Context: SekehContext{
			Profile: SekehProfile{
				DeviceId:       "8643940207831167831C1D6BABA0000864394020783116::5573578",
				InstallationId: s.MustGenerateUUID(),
			},
			Locale:   "fa",
			Platform: "ANDROID",
			Version:  "4.5",
		},
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	aes := symmetric.NewAES(s.sessionKey[:16], symmetric.CBC, symmetric.Pkcs7)
	iv := make([]byte, 16)
	payload, err = aes.Encrypt(payload, iv)
	if err != nil {
		return nil, err
	}

	payload = []byte(base64.StdEncoding.EncodeToString(payload))

	var body SekehResponse
	uri := "https://sekeh.bpm.bankmellat.ir/client-rest-api/v3/" + path
	_, err = Request(uri, map[string]string{"REK": s.wrappedSessionKey}, payload, &body)
	if err != nil {
		return nil, err
	}

	if body.Message == "DynamicPinSecurityException!" {
		fmt.Println("Nope")
		return nil, errors.New(body.Message)
	} else {
		fmt.Println("Yayyyy!")
	}
	return &body, nil
}

func (s *Sekeh) MustGenerateUUID() string {
	trackingCode, err := uuid.NewRandom()
	if err != nil {
		log.Fatal(err)
	}
	return trackingCode.String()
}

func (s *Sekeh) VerifyDevice(verificationCode string) error {
	if len(verificationCode) != 6 {
		return errors.New("verification code should be 6 digits")
	}

	params := SekehVerifyDeviceRequest{
		MobileNumber: s.mobileNumber,
		TrackingCode: s.MustGenerateUUID(),
	}

	result, err := s.request("device/register", params)
	if err != nil {
		return err
	}

	fmt.Println(result.Message)

	return nil
}

func (s *Sekeh) GetCaptcha() error {
	params := SekehActivationCaptchaRequest{
		MobileNumber: s.mobileNumber,
		TrackingCode: s.MustGenerateUUID(),
	}

	result, err := s.request("device/activationCaptcha", params)
	if err != nil {
		return err
	}

	fmt.Printf("Solve this captcha : %s\n", result.Captcha)

	return nil
}
