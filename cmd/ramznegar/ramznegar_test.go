package ramznegar

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/eliukblau/pixterm/pkg/ansimage"
	"image/color"
	"image/png"
	"log"
	"os"
	"otp/internal/ramznegar"
	"otp/internal/structs"
	"strings"
	"testing"
)

func TestRamznegar(t *testing.T) {
	r, err := ramznegar.New("09126175024")
	if err != nil {
		t.Fatal(err)
	}

	verificationCode := "882260"

	apiKey, newAccount, err := r.VerifyDevice(verificationCode)
	if err != nil {
		if err != ramznegar.NeedsCaptchaErr {
			t.Fatal(err)
		}

		captchaImgBytes, err := r.GetCaptcha()
		if err != nil {
			t.Fatal(err)
		}

		captchaImg, err := png.Decode(bytes.NewReader(captchaImgBytes))
		if err != nil {
			t.Fatal(err)
		}

		ansiImage, err := ansimage.NewScaledFromImage(captchaImg, 100, 200, color.Transparent, ansimage.ScaleModeFit, ansimage.NoDithering)
		if err != nil {
			log.Fatal(err)
		}

		ansiImage.Draw()

		fmt.Println("Enter code in captcha:")

		reader := bufio.NewReader(os.Stdin)
		captchaCode, _ := reader.ReadString('\n')
		captchaCode = strings.TrimSpace(captchaCode)

		apiKey, newAccount, err = r.VerifyDeviceWithCaptcha(verificationCode, captchaCode)
		if err != nil {
			t.Fatal(err)
		}
	}

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("API Key : %s (is new account? %t)\n", apiKey, newAccount)

	cards, err := r.ListCards()
	if err != nil {
		t.Fatal(err)
	}

	pin, valid, err := r.RequestPin1(structs.RamznegarPinRequest{
		MaxAmount:    1500000,
		MaxValidTime: 120,
		PanId:        cards[0].PanID,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(pin)
	t.Log(valid)

	conf, err := r.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Valid time : %s", conf.ValidTimes)

}
