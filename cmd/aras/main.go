package main

import (
	"encoding/json"
	"fmt"
	"log"
	"otp/internal/aras"
	. "otp/internal/structs"
	"otp/internal/token"
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

/*


password = 4 digit by sms
pin = 6 digits arbitrary



{"channelNameInAAServer":"CARD","cif":"11429560","pinLength":6,"token":"dfeb00fe-a812-4f9d-8ec7-4feb73205353","tokenGeneratedTime":1576314826793,"tokenTimeToLiveSeconds":900,"verificationCodeLength":4,"version":3}


{"channelNameInAAServer":"CARD","cif":"6177236","pinLength":6,"token":"8534f229-c56f-47b4-977e-7600d000f5a3","tokenGeneratedTime":1575365099770,"tokenTimeToLiveSeconds":15,"verificationCodeLength":4,"version":3}

{"channelNameInAAServer":"CARD","cif":"6177236","pinLength":6,"token":"6be9e24f-bd10-484d-8484-56f5e830117c","tokenGeneratedTime":1575365423088,"tokenTimeToLiveSeconds":15,"verificationCodeLength":4,"version":3}

{"channelNameInAAServer":"CARD","cif":"6177236","pinLength":6,"token":"546fac76-1a2c-4764-97b4-e5bb682bb811","tokenGeneratedTime":1575369617463,"tokenTimeToLiveSeconds":900,"verificationCodeLength":4,"version":3}

{"channelNameInAAServer":"CARD","cif":"6177236","pinLength":6,"token":"351129e4-407c-4bad-ae5f-d624c79e8f62","tokenGeneratedTime":1575369768770,"tokenTimeToLiveSeconds":900,"verificationCodeLength":4,"version":3}

1247

150968

{"channelNameInAAServer":"CARD","cif":"11429560","pinLength":6,"token":"dfeb00fe-a812-4f9d-8ec7-4feb73205353","tokenGeneratedTime":1576314826793,"tokenTimeToLiveSeconds":900,"verificationCodeLength":4,"version":3}
*/

var banks []Bank

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
		SecretKey:       "",
		TimeInterval:    60000,
		Seed:            "D2C3E15B8F90E747228BD733A885F6DCEB150968",
	}

	const generateOtp1 = false
	const generateOtp2 = true

	var err error

	if len(otpToken.Seed) == 0 {
		otpToken, err = aras.Activate(bank, "e1f54cdf-8028-4d82-8f94-0755b95b720c", "8836", "150968", "6177236", generateOtp1, generateOtp2)
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
