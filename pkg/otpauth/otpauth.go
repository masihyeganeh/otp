package otpauth

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"net/url"
	"strconv"
	"strings"
)

// OtpAuth represents an TOTP or HTOP key.
type OtpAuth struct {
	url *url.URL
}

// New creates a new empty OtpAuth.
//
// The URL format is documented here:
//   https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
func New(issuer, secret string) (*OtpAuth, error) {
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   issuer + ":",
		RawQuery: url.Values{
			"secret":    []string{secret},
			"issuer":    []string{issuer},
			"algorithm": []string{"SHA1"},
		}.Encode(),
	}

	return &OtpAuth{
		url: &u,
	}, nil
}

// NewKeyFromURL creates a new OtpAuth from an TOTP or HOTP url.
//
// The URL format is documented here:
//   https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
func NewKeyFromURL(orig string) (*OtpAuth, error) {
	s := strings.TrimSpace(orig)

	u, err := url.Parse(s)

	if err != nil {
		return nil, err
	}

	return &OtpAuth{
		url: u,
	}, nil
}

func (k *OtpAuth) String() string {
	return k.url.String()
}

// Type returns "hotp" or "totp".
func (k *OtpAuth) Type() string {
	return k.url.Host
}

// SetType sets the type of the otp to "hotp" or "totp".
func (k *OtpAuth) SetType(otpType string) {
	k.url.Host = strings.ToLower(otpType)
}

// Issuer returns the name of the issuing organization.
func (k *OtpAuth) Issuer() string {
	q := k.url.Query()

	issuer := q.Get("issuer")

	if issuer != "" {
		return issuer
	}

	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return ""
	}

	return p[:i]
}

// SetIssuer sets the name of the issuing organization.
func (k *OtpAuth) SetIssuer(issuer string) {
	q := k.url.Query()
	q.Set("issuer", issuer)
	k.url.RawQuery = q.Encode()

	accountName := k.AccountName()
	if len(issuer) > 0 {
		issuer += ":"
	}
	k.url.Path = issuer + accountName
}

// AccountName returns the name of the user's account.
func (k *OtpAuth) AccountName() string {
	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return p
	}

	return strings.TrimSpace(p[i+1:])
}

// SetAccountName sets the name of the user's account.
func (k *OtpAuth) SetAccountName(accountName string) {
	issuer := k.Issuer()
	if len(issuer) > 0 {
		issuer += ":"
	}
	k.url.Path = issuer + accountName
}

// Secret returns the opaque secret for this OtpAuth.
func (k *OtpAuth) Secret() string {
	q := k.url.Query()

	return q.Get("secret")
}

// SetSecret sets the opaque secret for this OtpAuth.
func (k *OtpAuth) SetSecret(secret string) {
	q := k.url.Query()

	q.Set("secret", secret)
	k.url.RawQuery = q.Encode()
}

// Period returns a tiny int representing the rotation time in seconds.
func (k *OtpAuth) Period() int {
	q := k.url.Query()

	if u, err := strconv.Atoi(q.Get("period")); err == nil {
		return u
	}

	// If no period is defined 30 seconds is the default per (rfc6238)
	return 30
}

// SetPeriod sets a tiny int representing the rotation time in seconds.
func (k *OtpAuth) SetPeriod(period int) {
	q := k.url.Query()

	q.Set("period", strconv.Itoa(period))
	k.url.RawQuery = q.Encode()
}

// Digit returns the otp length.
func (k *OtpAuth) Digit() int {
	q := k.url.Query()

	if digits, err := strconv.Atoi(q.Get("digits")); err == nil {
		return digits
	}

	return 6
}

// SetDigit sets the otp length.
func (k *OtpAuth) SetDigit(digits int) {
	q := k.url.Query()

	q.Set("digits", strconv.Itoa(digits))
	k.url.RawQuery = q.Encode()
}

// Counter returns the hotp counter value.
func (k *OtpAuth) Counter() int {
	q := k.url.Query()

	if counter, err := strconv.Atoi(q.Get("counter")); err == nil {
		return counter
	}

	return 6
}

// SetCounter sets the hotp counter value.
func (k *OtpAuth) SetCounter(counter int) {
	q := k.url.Query()

	q.Set("counter", strconv.Itoa(counter))
	k.url.RawQuery = q.Encode()
}

// Algorithm returns the hashing algorithm of otp.
func (k *OtpAuth) Algorithm() string {
	q := k.url.Query()

	return q.Get("algorithm")
}

// SetAlgorithm sets the hashing algorithm of otp.
func (k *OtpAuth) SetAlgorithm(algorithm Algorithm) {
	q := k.url.Query()

	q.Set("algorithm", algorithm.String())
	k.url.RawQuery = q.Encode()
}

// URL returns the OTP URL as a string
func (k *OtpAuth) URL() string {
	if k.url.Host != "hotp" {
		k.url.Query().Del("counter")
	}
	return k.url.String()
}

// Algorithm represents the hashing function to use in the HMAC
// operation needed for OTPs.
type Algorithm int

const (
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)

func (a Algorithm) String() string {
	switch a {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	case AlgorithmMD5:
		return "MD5"
	}
	panic("unreached")
}

func (a Algorithm) Hash() hash.Hash {
	switch a {
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	case AlgorithmMD5:
		return md5.New()
	}
	panic("unreached")
}
