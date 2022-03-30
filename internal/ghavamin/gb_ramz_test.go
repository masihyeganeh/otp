package ghavamin

import "testing"

func TestGBRamz(t *testing.T) {
	g, err := New("09126175024")
	if err != nil {
		t.Fatal(err)
	}

	err = g.Authenticate()
	if err != nil {
		t.Fatal(err)
	}

	activation, err := g.Activate("1234")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(activation)

	idk, err := g.GenerateOtp("printed code", "smsed code")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(idk)
}

//func TestGBRamz(t *testing.T) {
//	pub, a, b, err := a()
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	// https://otp.ghbi.ir/api/Authentication/
//	/*
//		Headers = {
//			Content-Type:	application/json
//			Authorization:	Basic ali:123456
//			User-Agent:	Dalvik/2.1.0 (Linux; U; Android 7.1.2; SM-G955N Build/N2G48H)
//		}
//	*/
//	req1 := GbRamzAuthenticationRequest{
//		AuthenticationTypeIs: 1,
//		MobileNumber:         "09126175024",
//		Imei:                 "7831C1D6BABA0000",
//		IPAddress:            "172.17.100.15",
//		MobileModelName:      "samsung SM-G955N 7.1.2 N",
//		PublicKey:            pub,
//	}
//
//	// https://otp.ghbi.ir/api/Activation
//	/*
//		Headers = {
//			Content-Type:	application/json
//			Authorization:	Basic ali:123456
//			User-Agent:	Dalvik/2.1.0 (Linux; U; Android 7.1.2; SM-G955N Build/N2G48H)
//		}
//	*/
//	req2 := GbRamzActivationRequest{
//		MobileNumber:   "09126175024",
//		Imei:           "7831C1D6BABA0000",
//		ActivationCode: "3969",
//	}
//
//	// https://otp.ghbi.ir/api/OtpGenerate
//	/*
//		Headers = {
//			Content-Type:	application/json
//			Authorization:	Basic ali:123456
//			User-Agent:	Dalvik/2.1.0 (Linux; U; Android 7.1.2; SM-G955N Build/N2G48H)
//		}
//	*/
//	req3 := GbRamzOtpGenerateRequest{
//		MobileNumber:          "09126175024",
//		Imei:                  "7831C1D6BABA0000",
//		ActivitionCodePrinted: "printed code",
//		ActivitionCodeSmsed:   "smsed code",
//		OtpDuration:           0,
//		Data:                  a,
//		Sign:                  b,
//	}
//
//	// Seed : DES/CBC/NoPadding hexDecode(OtpKey) with "rvfnaped" as key and 8 zeros as iv
//	// OTP is 4 digits for pass1 and 7 digits for pass2
//
//	t.Log(req1, req2, req3)
//}
