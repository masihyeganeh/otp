package main

import (
	"encoding/json"
	"fmt"
	"github.com/eliukblau/pixterm/pkg/ansimage"
	"image/color"
	"image/png"
	"log"
	"os"
	"otp/internal/aras"
	. "otp/internal/structs"
	"otp/internal/token"
	"otp/pkg/qr"
	"time"
)

var banksData = []byte(`[
  {
    "id": "101",
    "phone": "02128930",
    "url": "https://otp.bdi24.com/yaghut/rest/deyOtp/card/activateOtpToken/",
    "publicKey": "A5gYv/W7bZ8p0DYscSPvnE1Nr47/N47+k9Ex4Q0GsVlq",
    "certificates": [
      "sha256/De26Cax4g2OrKcs8H5A8ZRVQuHZVHckr1pY64iyYgQQ=",
      "sha256/S4AbJNGvyS57nzJwv8sPMUML8VHSqH1vbiBftdPcErI=",
      "sha256/qiYwp7YXsE0KKUureoyqpQFubb5gSDeoOoVxn6tmfrU="
    ]
  },
  {
    "id": "102",
    "phone": "02166455876",
    "url": "https://otp.hibank24.ir/yaghut/rest/hekmat/card/activateOtpToken/",
    "publicKey": "AywEUt2KdxmOSXJqnAX9/pqanJTHOMAW55FfX9EqsH/0",
    "certificates": [
      "sha256/ROMyy0Hs5SMXGBVn+fBjDMx7K4ovjcCAp7/SLJ3rJvc=",
      "sha256/S4AbJNGvyS57nzJwv8sPMUML8VHSqH1vbiBftdPcErI=",
      "sha256/qiYwp7YXsE0KKUureoyqpQFubb5gSDeoOoVxn6tmfrU="
    ]
  },
  {
    "id": "103",
    "phone": "02141731",
    "url": "https://otp.sina24h.com/sina/rest/sinagss/card/activateOtpToken/",
    "publicKey": "AzeNaz8WLNMuhvcqh2Yw8ode2YcECc+2odGdjTfhx1G7",
    "certificates": [
      "sha256/gb9iRV1ZqM9nRNU1QS8dBV9bH/ybStSBJRi0i6Edyqg=",
      "sha256/klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY=",
      "sha256/grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME="
    ]
  },
  {
    "id": "104",
    "phone": "02148031000",
    "url": "https://otp.enbank.ir/yaghut/rest/enGSS/card/activateOtpToken/",
    "publicKey": "AjKuAoul8hkDP9450u+Iqo5bS/rXMcdHR1PJv0vSiGO0",
    "certificates": [
      "sha256/LaaFM7i/ZWnQ0V0KwGjr12k4JRuvWmPpZbz501G2jgY=",
      "sha256/S4AbJNGvyS57nzJwv8sPMUML8VHSqH1vbiBftdPcErI=",
      "sha256/qiYwp7YXsE0KKUureoyqpQFubb5gSDeoOoVxn6tmfrU="
    ]
  },
  {
    "id": "105",
    "phone": "096300",
    "url": "https://otp.ansarbank.com/yaghut/rest/ansarGSS/card/activateOtpToken/",
    "publicKey": "A561Ta3+gxYcQzd74CNI7hn8p25Dd1N9qyGGuS7oGx0D",
    "certificates": [
      "sha256/Ul6Pd1pAPwEFxip4RJglrY5mCr1LOLQk4gWucKTIEXg=",
      "sha256/S4AbJNGvyS57nzJwv8sPMUML8VHSqH1vbiBftdPcErI=",
      "sha256/qiYwp7YXsE0KKUureoyqpQFubb5gSDeoOoVxn6tmfrU="
    ]
  },
  {
    "id": "106",
    "phone": "0214322",
    "url": "https://otp.qmb.ir/gharz/rest/gharzmehrOTP/card/activateOtpToken/",
    "publicKey": "Ap7ANr4+XKw2k98ys9mcYFS69k4/UBwJbQXvoY11OU5M",
    "certificates": [
      "sha256/wD9yFLVnbZQQiFS2LLJcICOW+hZ9he8SRnKryVJqWsM=",
      "sha256/S4AbJNGvyS57nzJwv8sPMUML8VHSqH1vbiBftdPcErI=",
      "sha256/qiYwp7YXsE0KKUureoyqpQFubb5gSDeoOoVxn6tmfrU="
    ]
  }
]`)

var banks []Bank

var bankNames = map[string]string{
	"101": "Dey Bank",
	"102": "Hekmat Iranian Bank",
	"103": "Sina Bank",
	"104": "Eghtesade Novin Bank",
	"105": "Ansar Bank",
	"106": "Mehr Bank",
}

func init() {
	err := json.Unmarshal(banksData, &banks)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	bank := banks[3]

	otpToken := &token.Token{
		FirstOtpLength:  4,
		SecondOtpLength: 6,
		TimeInterval:    60000,
		BankName:        "Eghtesade Novin Bank",
		AccountId:       "6177236",
		Seed:            "D2C3E15B8F90E747228BD733A885F6DCEB150968",
	}

	var (
		generateOtp1     = false
		generateOtp2     = true
		qrImageSrc       = "/Users/masihyeganeh/Downloads/download.png"
		verificationCode = "8836"
		pinCode          = "150968"
	)

	if len(otpToken.Seed) == 0 {
		f, err := os.OpenFile(qrImageSrc, os.O_RDONLY, 0)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		img, err := png.Decode(f)
		if err != nil {
			log.Fatal(err)
		}

		imgData, err := qr.FromImage(img)
		if err != nil {
			log.Fatal(err)
		}

		var qrData QrData
		err = json.Unmarshal([]byte(imgData), &qrData)
		if err != nil {
			log.Fatal(err)
		}

		if time.Now().UTC().Unix()-qrData.TokenGeneratedTime/1000 > qrData.TokenTimeToLiveSeconds {
			log.Fatal("QR image is expired")
		}

		if len(verificationCode) != qrData.VerificationCodeLength {
			log.Fatal(fmt.Sprintf("Verification code should be %d digits", qrData.VerificationCodeLength))
		}

		if len(pinCode) != qrData.PinLength {
			log.Fatal(fmt.Sprintf("Pin code should be %d digits", qrData.PinLength))
		}

		if qrData.ServiceChannelOtpType == "CARD_SECOND_PASSWORD" {
			generateOtp1 = false
			generateOtp1 = true
		}

		otpToken, err = aras.Activate(bank, qrData.Token, verificationCode, pinCode, qrData.Cif, generateOtp1, generateOtp2)
		if err != nil {
			log.Fatal(err)
		}

		otpToken.BankName = bankNames[bank.ID]
		otpToken.AccountId = qrData.Cif
	}

	if generateOtp1 {
		otp, err := otpToken.GenerateOtp1()
		if err != nil {
			otp = err.Error()
		}
		log.Printf("OTP1 : %s\n\n", otp)

		url, err := otpToken.GeneralOtp1UrlFromToken()
		if err != nil {
			log.Fatal(err)
		}

		img, err := qr.ToImage(url, 1, 1)
		if err != nil {
			log.Fatal(err)
		}

		ansiImage, err := ansimage.NewFromImage(img, color.Transparent, ansimage.NoDithering)
		if err != nil {
			log.Fatal(err)
		}

		ansiImage.Draw()
	}

	if generateOtp2 {
		otp, err := otpToken.GenerateOtp2()
		if err != nil {
			otp = err.Error()
		}
		log.Printf("OTP2 : %s\n\n", otp)

		url, err := otpToken.GeneralOtp2UrlFromToken()
		if err != nil {
			log.Fatal(err)
		}

		img, err := qr.ToImage(url, 1, 1)
		if err != nil {
			log.Fatal(err)
		}

		ansiImage, err := ansimage.NewFromImage(img, color.Transparent, ansimage.NoDithering)
		if err != nil {
			log.Fatal(err)
		}

		ansiImage.Draw()
	}
}
