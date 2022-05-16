package eghtesadnovin

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"otp/internal/token"
	"strings"
	"testing"
)

func TestTokenGeneration(t *testing.T) {
	// 778024 is shown at 1652703737 for 9D5D96988C8D267DD4FD4B5AF7EFB394A493B85A in the app

	otpToken := token.Token{
		FirstOtpLength:  6,
		SecondOtpLength: 6,
		OtpLength:       6,
		Seed:            "9D5D96988C8D267DD4FD4B5AF7EFB394A493B85A",
		TimeInterval:    60000,
		BankName:        "Eghtesad Novin",
	}

	timestamp := int64(1652703737)

	otp, err := otpToken.GenerateOtp1WithTimestamp(timestamp)
	if err != nil {
		t.Fatal(err.Error())
	}

	if otp != "778024" {
		t.Fatal("implementation is wrong")
	}
}

func TestLogin(t *testing.T) {
	enBank := New("7831C1D6BABA0000")

	err := enBank.NewSession()
	if err != nil {
		log.Fatal(err.Error())
	}

	_, err = enBank.SignIn("internet-bank-username", "internet-bank-password")
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println("Enter pin code in sms:")
	reader := bufio.NewReader(os.Stdin)
	pin, _ := reader.ReadString('\n')
	pin = strings.TrimSpace(pin)

	err = enBank.SignInWithPin(pin)
	if err != nil {
		log.Fatal(err.Error())
	}

	otpType := CardSecondPassword

	config, err := enBank.GenerateToken(otpType)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println("Enter verification code in sms:")
	reader = bufio.NewReader(os.Stdin)
	verificationCode, _ := reader.ReadString('\n')
	verificationCode = strings.TrimSpace(verificationCode)

	otpToken, err := enBank.Activate(config.Token, verificationCode, config.Cif, otpType)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println(otpToken)

	err = enBank.Logout()
	if err != nil {
		log.Fatal(err.Error())
	}

	otpUrl, err := otpToken.GeneralOtp1UrlFromToken()
	if err != nil {
		t.Fatal(err.Error())
	}

	otp, err := otpToken.GenerateOtp1()
	if err != nil {
		log.Fatal(err.Error())
	}

	t.Logf("OTP URL:\n%s\n\nOTP Now: %s", otpUrl, otp)
}
