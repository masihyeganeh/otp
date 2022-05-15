package asymmetric

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"math/big"
	. "otp/internal/structs"
)

type eccKey struct {
	curve   elliptic.Curve
	private []byte
	x, y    *big.Int
}

func newEccKey() (*eccKey, error) {
	curve := elliptic.P256()
	private, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &eccKey{curve, private, x, y}, nil
}

func (e *eccKey) sharedKey(serverPublicKey []byte) []byte {
	serverX, serverY := elliptic.UnmarshalCompressed(e.curve, serverPublicKey)
	x, _ := e.curve.ScalarMult(serverX, serverY, e.private)

	xBytes := x.Bytes()
	if len(xBytes) == 33 {
		xBytes = xBytes[1:]
	}

	h := sha1.New()
	h.Write(xBytes)
	return h.Sum(nil)[:16]
}

func GenerateKeys(serverPoint string) (*EncryptionData, error) {
	ecc, err := newEccKey()
	if err != nil {
		return nil, err
	}

	serverPublicKey, err := base64.StdEncoding.DecodeString(serverPoint)
	if err != nil {
		return nil, err
	}

	return &EncryptionData{
		PublicKey: base64.StdEncoding.EncodeToString(elliptic.MarshalCompressed(ecc.curve, ecc.x, ecc.y)),
		SharedKey: ecc.sharedKey(serverPublicKey),
	}, nil
}
