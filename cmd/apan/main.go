package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"otp/internal/apan"
)

/*
Interesting errors from server:

The INSERT statement conflicted with the FOREIGN KEY constraint "FK_TokensLogs_AppControlTypes". The conflict occurred in database "CardService", table "dbo.AppControlTypes", column 'IDAppControlType'.eacfdb66-8f6a-46b8-8066-a798df760cd7$213.136.70.203$7831C1D6BABA0000|shamu|SM-J3110|Android|22|1.0.10$

The UPDATE statement conflicted with the FOREIGN KEY constraint "FK_Pers.Person_Common.Location.Cities". The conflict occurred in database "CardService", table "common.Cities", column 'NidCity'.

The INSERT statement conflicted with the FOREIGN KEY constraint "FK_TokensLogs_AppControlTypes". The conflict occurred in database "CardService", table "dbo.AppControlTypes", column 'IDAppControlType'.7f665e72-186f-4ae6-b39a-ed14573f5a23$213.136.70.203$7831C1D6BABA0000|shamu|SM-J3110|Android|22|1.0.10$
*/

func main() {
	api, err := apan.New("09000000002")
	if err != nil {
		log.Fatal(err)
	}

	err = api.GetLoginCode()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Enter validation code sent by sms:")

	reader := bufio.NewReader(os.Stdin)
	code, _ := reader.ReadString('\n')

	err = api.LoginWithCode(code)
	if err != nil {
		log.Fatal(err)
	}

	// {"channelNameInAAServer":"CARD","cif":"5434656","pinLength":6,"token":"ec5518c7-d18d-4c3f-874f-1e77f0703e56","tokenGeneratedTime":1576306174781,"tokenTimeToLiveSeconds":600,"verificationCodeLength":4,"version":3}

	otpToken, err := api.Activate("ec5518c7-d18d-4c3f-874f-1e77f0703e56", "5434656", "123456", "654321")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(otpToken)
	//otpToken := &token.Token{
	//	OtpLength:  8,
	//	SecretKey:       "",
	//	TimeInterval:    60000,
	//	//Seed:            "D2C3E15B8F90E747228BD733A885F6DCEB150968",
	//}
	//
	//const generateOtp1 = false
	//const generateOtp2 = true
	//
	//var err error
	//
	//if len(otpToken.Seed) == 0 {
	//	otpToken, err = sina.Activate("5fc33039-0ad1-4920-875d-6fc2a9840ce8", "8836", "150968", "3922880", "MODERN", 1590962082262)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//}
	//
	//url, err := otpToken.GeneralOtp1UrlWithUsername("en bank", "6177236")
	//if err != nil {
	//	log.Fatal(err)
	//}
	//fmt.Printf("General OTP url : %s\n", url)
	//
	//if generateOtp1 {
	//	otp, err := otpToken.GenerateOtp1()
	//	if err != nil {
	//		otp = err.Error()
	//	}
	//	log.Printf("OTP1 : %s\n", otp)
	//
	//	//img, err := qr.ToImage(url, 1, 1)
	//	//if err != nil {
	//	//	log.Fatal(err)
	//	//}
	//}
	//
	//if generateOtp2 {
	//	otp, err := otpToken.GenerateOtp2()
	//	if err != nil {
	//		otp = err.Error()
	//	}
	//	log.Printf("OTP2 : %s\n", otp)
	//
	//	//img, err := qr.ToImage(url, 1, 1)
	//	//if err != nil {
	//	//	log.Fatal(err)
	//	//}
	//}
	//
	//fmt.Printf("Save token for next time : %+v\n", *otpToken)
}
