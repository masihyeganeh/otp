package main

import (
	"fmt"
	"log"
	"otp/internal/sina"
	"otp/internal/token"
)

func main() {
	otpToken := &token.Token{
		OtpLength:    8,
		SecretKey:    "",
		TimeInterval: 60000,
		//Seed:            "D2C3E15B8F90E747228BD733A885F6DCEB150968",
	}

	const generateOtp1 = false
	const generateOtp2 = true

	var err error

	if len(otpToken.Seed) == 0 {
		otpToken, err = sina.Activate("5fc33039-0ad1-4920-875d-6fc2a9840ce8", "8836", "150968", "3922880", "MODERN", 1590962082262)
		if err != nil {
			log.Fatal(err)
		}
	}

	url, err := otpToken.GeneralOtp1UrlWithUsername("en bank", "6177236")
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
