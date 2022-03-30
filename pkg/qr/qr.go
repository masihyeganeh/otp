package qr

import (
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"image"
)

// FromImage decodes an QR-Code image
func FromImage(qrImage image.Image) (string, error) {
	reader := qrcode.NewQRCodeReader()
	bitmap, err := gozxing.NewBinaryBitmapFromImage(qrImage)
	if err != nil {
		return "", err
	}

	res, err := reader.DecodeWithoutHints(bitmap)

	if err != nil {
		return "", err
	}

	return res.GetText(), nil
}

// ToImage returns an QR-Code image of the specified width and height,
// suitable for use by many clients like Google-Authenticator
// to enroll a user's TOTP/HOTP key.
func ToImage(data string, width int, height int) (image.Image, error) {
	writer := qrcode.NewQRCodeWriter()
	return writer.EncodeWithoutHint(data, gozxing.BarcodeFormat_QR_CODE, width, height)
}
