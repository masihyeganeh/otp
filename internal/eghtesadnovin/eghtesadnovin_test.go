package eghtesadnovin

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
)

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

	token, err := enBank.Activate(config.Token, verificationCode, config.Cif, otpType)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println(token)

	err = enBank.Logout()
	if err != nil {
		log.Fatal(err.Error())
	}

	otp, err := token.GenerateOtp1()
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println(otp)
}
