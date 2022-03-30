package tejarat

import (
	"crypto/sha1"
	"encoding/hex"
	"golang.org/x/text/encoding/unicode/utf32"
	"otp/internal/tejarat"
	"otp/internal/token"
	"strings"
	"testing"
)

func TestHamraz(t *testing.T) {
	h, err := tejarat.New("09126175024")
	if err != nil {
		t.Fatal(err)
	}

	channels, err := h.GetChannels()
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.AddCard("1234567578578678", "123123123", "3423234234", channels[len(channels)-1])
	if err != nil {
		t.Fatal(err)
	}

	t.Log(res)
}

func TestOtp(t *testing.T) {
	// This will only pass for time = 1597087430
	otp := token.Token{
		FirstOtpLength:  8,
		SecondOtpLength: 8,
		OtpLength:       0,
		SecretKey:       "",
		TimeInterval:    30000,
		BankName:        "Tejarat",
		AccountId:       "5859831165750521",
		Seed:            "1003450364" + "2523C3EEAC8052242627", // 30 chars
	}

	b := []byte(otp.Seed)

	b, err := utf32.UTF32(utf32.LittleEndian, utf32.IgnoreBOM).NewEncoder().Bytes(b)
	if err != nil {
		t.Fatal(err)
	}

	s := sha1.New()
	s.Write(b)
	otp.Seed = strings.ToUpper(hex.EncodeToString(s.Sum(nil)))

	//if otp.Seed != "F2298471F9DF484AF05A7D7C47EB1AA19F117B82" {
	//	t.Fatal("Wrong seed")
	//}

	otpToken, err := otp.GenerateOtp1()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("generated : %s", otpToken)
	t.Log("real      : 63212052")

	if otpToken != "63212052" {
		t.Fatal("Wrong implementation")
	}
}
