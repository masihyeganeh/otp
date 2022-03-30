package asymmetric

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func RsaPublicKeyFromPem(data []byte) (*rsa.PublicKey, error) {
	p, rest := pem.Decode(data)
	if p.Type != "PUBLIC KEY" {
		return nil, errors.New("bad public key")
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("has rest : %v", rest)
	}
	pub, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return nil, err
	}

	return pub.(*rsa.PublicKey), nil
}
