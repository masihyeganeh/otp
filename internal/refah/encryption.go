package refah

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"math"
	"strconv"
	"strings"
	"time"
)

type Encryption struct {
	IsAlternateEncryption bool
}

func New() *Encryption {
	return &Encryption{IsAlternateEncryption: true}
}

func (e *Encryption) makeSeed(seed string, seedSaltNumber int, imeiPlusPhoneNumber, appMajorVersion string) []byte {
	hashAlg := sha256.New()
	if e.IsAlternateEncryption {
		hashAlg = sha512.New()
	}

	input := appMajorVersion + strconv.Itoa(seedSaltNumber) + seed + imeiPlusPhoneNumber + strconv.Itoa(seedSaltNumber) + appMajorVersion

	hashAlg.Write([]byte(input))

	return hashAlg.Sum(nil)
}

func (e *Encryption) otp(hashAlg hash.Hash, timeWindow uint64, otpLength int) string {
	var11 := make([]byte, 8)
	binary.BigEndian.PutUint64(var11, timeWindow)

	hashAlg.Write(var11)
	var14 := hashAlg.Sum(nil)

	var6 := var14[len(var14)-1]

	for i := 0; i < 4; i++ {
		var11[i] = var14[i+(int(var6)&15)]
	}

	var15 := binary.BigEndian.Uint32(var11)

	var7 := uint32(1591523992)

	if e.IsAlternateEncryption {
		var7 = 2147483647
	}

	otpNumber := var15 & var7

	otpNumber %= uint32(math.Pow10(otpLength))
	otp := fmt.Sprintf("%d", otpNumber)
	// TODO: Should zeros be appended or prepended?
	for len(otp) < otpLength {
		otp += "0"
	}

	return otp
}

func (e *Encryption) getPassword(otpCode, imeiPlusPhoneNumber /* this.imei + this.phoneNumber */, otpToken string, interval int64, otpLength int, appVersion string) string {
	appMajorVersion := appVersion[0:1]
	halfLength := len(otpToken) / 2
	firstHalf := otpToken[0:halfLength]
	secondHalf := otpToken[halfLength:]

	token := e.decodeToken(firstHalf, secondHalf)
	tokenSaltLocation := len(token) - 6
	tokenSaltNumber, _ := strconv.Atoi(token[tokenSaltLocation:])

	if !e.IsAlternateEncryption {
		tokenSaltNumber += 1
	}

	token = token[0:tokenSaltLocation]

	now := time.Now()

	seed := e.makeSeed(token, tokenSaltNumber, imeiPlusPhoneNumber, appMajorVersion)
	hashAlg := hmac.New(sha256.New, seed)
	otp := e.otp(hashAlg, uint64((now.UnixNano()/int64(time.Millisecond))/interval), otpLength)
	// Make OTP with hex.EncodeToString(seed) as seed, interval as time interval, otpLength as otp length and sha256 as algorithm
	// Note that otpNumber in OTP class should be & with 2147483647
	return otp
}

func (e *Encryption) decodeToken(firstHalf, secondHalf string) string {
	firstHalfBytes, _ := hex.DecodeString(firstHalf)
	secondHalfBytes, _ := hex.DecodeString(secondHalf)
	xorBytes := e.xorBytes(firstHalfBytes, secondHalfBytes)

	result := make([]byte, 67)

	for i := range result {
		index := xorBytes[i] & 255
		result[index] = xorBytes[i+67]
		if !e.IsAlternateEncryption {
			result[index] = result[index] + 1
		}
	}

	return strings.ToUpper(hex.EncodeToString(result))
}

func (e *Encryption) xorBytes(part1, part2 []byte) []byte {
	result := make([]byte, int(math.Min(float64(len(part1)), float64(len(part2)))))

	for i := range result {
		result[i] = part1[i] ^ part2[i]
	}

	return result
}
