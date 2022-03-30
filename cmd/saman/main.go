package main

import (
	"fmt"
	"log"
	"otp/internal/saman"
	"otp/internal/token"
)

func main() {
	otpToken := &token.Token{
		FirstOtpLength:  4,
		SecondOtpLength: 6,
		TimeInterval:    60000,
		Seed:            "D393B6D94DD94399196823391D47FC327D150968",
	}

	const generateOtp1 = false
	const generateOtp2 = true

	var err error

	if len(otpToken.Seed) == 0 {
		otpToken, err = saman.Activate("478ef684-4338-4df7-9fc8-deb2b624634a", "2306", "150968", "966775", "CARD", "CARD_SECOND_PASSWORD", 1596040489475)
		if err != nil {
			log.Fatal(err)
		}
	}

	url, err := otpToken.GeneralOtp1UrlWithUsername("saman bank", "966775")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("General OTP url : %s\n", url)

	if generateOtp1 {
		otp, err := otpToken.GenerateOtp1()
		if err != nil {
			otp = err.Error()
		}
		log.Printf("OTP1 : %s\n", otp)

		//img, err := qr.ToImage(url, 1, 1)
		//if err != nil {
		//	log.Fatal(err)
		//}
	}

	if generateOtp2 {
		otp, err := otpToken.GenerateOtp2()
		if err != nil {
			otp = err.Error()
		}
		log.Printf("OTP2 : %s\n", otp)

		//img, err := qr.ToImage(url, 1, 1)
		//if err != nil {
		//	log.Fatal(err)
		//}
	}

	fmt.Printf("Save token for next time : %+v\n", *otpToken)
}
