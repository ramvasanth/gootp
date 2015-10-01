package gootp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

type HashType uint8

const (
	SHA1 HashType = 1 << iota
	SHA256
	SHA512
)

const (
	DefaultTokenLength        = 6
	DefaultPeriod             = 30
	DefaultRandomSecretLength = 100
	DefaultStepsBack          = 1
	DefaultStepsForward       = 1
	DefaultHashAlgorithm      = SHA1
)

type TOTP struct {
	Secret            []byte
	TokenLength       uint8    `default: 6`
	Period            uint8    `default: 30`
	StepsBack         int      `default: 1`
	StepsForward      int      `default: 1`
	HashFunction      HashType `default: SHA1`
	Issuer, Label     string
	AlgorithmInQRCode bool
}

type OTPParameter struct {
	Secret            string
	HashFunction      HashType
	TokenLength       uint8
	Period            uint8
	StepsBack         int
	StepsForward      int
	Issuer, Label     string
	AlgorithmInQRCode bool
}

func NewTOTP(otpParameter *OTPParameter) (*TOTP, error) {
	key, err := base32.StdEncoding.DecodeString(otpParameter.Secret)
	if nil != err {
		return nil, fmt.Errorf("Error encountered base32 decoding secret: %v", err.Error())
	}

	totp := &TOTP{
		Secret:            key,
		HashFunction:      otpParameter.HashFunction,
		TokenLength:       otpParameter.TokenLength,
		Period:            otpParameter.Period,
		StepsBack:         otpParameter.StepsBack,
		StepsForward:      otpParameter.StepsForward,
		Issuer:            otpParameter.Issuer,
		Label:             otpParameter.Label,
		AlgorithmInQRCode: otpParameter.AlgorithmInQRCode,
	}
	totp.setDefault()
	return totp, nil
}

func (t *TOTP) Now() int32 {
	windowPeriod := (time.Now().Unix() / int64(t.Period))
	return t.get(windowPeriod)
}

func (t *TOTP) int_to_bytestring(val int64) []byte {
	result := make([]byte, 8)
	i := len(result) - 1
	for i >= 0 {
		result[i] = byte(val & 0xff)
		i--
		val = val >> 8
	}
	return result
}

func (t *TOTP) getSHA1(data []byte) []uint8 {
	hmacHash := hmac.New(sha1.New, t.Secret)
	hmacHash.Write(data)
	return hmacHash.Sum(nil)
}

func (t *TOTP) getSHA256(data []byte) []uint8 {
	hmacHash := hmac.New(sha256.New, t.Secret)
	hmacHash.Write(data)
	return hmacHash.Sum(nil)
}

func (t *TOTP) getSHA512(data []byte) []uint8 {
	hmacHash := hmac.New(sha512.New, t.Secret)
	hmacHash.Write(data)
	return hmacHash.Sum(nil)
}

func (t *TOTP) getDigest(data []byte) []uint8 {
	switch t.HashFunction {
	case SHA1:
		return t.getSHA1(data)
	case SHA256:
		return t.getSHA256(data)
	case SHA512:
		return t.getSHA512(data)
	}
	return nil
}

func (t *TOTP) get(windowPeriod int64) int32 {
	data := t.int_to_bytestring(windowPeriod)
	digest := t.getDigest(data)
	offset := int(digest[19] & 0xf)
	code := int32(digest[offset]&0x7f)<<24 |
		int32(digest[offset+1]&0xff)<<16 |
		int32(digest[offset+2]&0xff)<<8 |
		int32(digest[offset+3]&0xff)

	code = int32(int64(code) % int64(math.Pow10(int(t.TokenLength))))
	return code
}

func (t *TOTP) GetCurrentToken() int32 {
	windowPeriod := (time.Now().Unix() / int64(t.Period)) + int64(0)
	return t.get(windowPeriod)
}

func (t *TOTP) GetTokenByStep(step int) int32 {
	windowPeriod := (time.Now().Unix() / int64(t.Period)) + int64(step)
	return t.get(windowPeriod)
}

func (t *TOTP) Verify(token int32) bool {
	for s := t.StepsBack * -1; s <= t.StepsForward; s++ {
		windowPeriod := (time.Now().Unix() / int64(t.Period)) + int64(s)
		if t.get(windowPeriod) == token {
			return true
		}
	}
	return false
}

func (t *TOTP) setDefault() {
	if t.TokenLength == 0 {
		t.TokenLength = DefaultTokenLength
	}
	if t.Period == 0 {
		t.Period = DefaultPeriod
	}
	if t.StepsBack == 0 {
		t.StepsBack = DefaultStepsBack
	}
	if t.StepsForward == 0 {
		t.StepsForward = DefaultStepsForward
	}
	if t.HashFunction == 0 {
		t.HashFunction = SHA1
	}
}

func (t *TOTP) getSecret() string {
	return base32.StdEncoding.EncodeToString(t.Secret)
}

func (t *TOTP) getHashAlgorithm() string {
	switch t.HashFunction {
	case SHA1:
		return "sha1"
	case SHA256:
		return "sha256"
	case SHA512:
		return "sha512"
	}
	return ""
}

func (t *TOTP) urlEncode(text string) string {
	text = url.QueryEscape(text)
	text = strings.Replace(text, "+", " ", -1)
	return text
}

func (t *TOTP) QRCodeData() string {
	label := t.urlEncode(t.Label)
	issuer := t.urlEncode(t.Issuer)
	if t.AlgorithmInQRCode {
		return fmt.Sprintf("otpauth://totp/%v?secret=%v&digits=%v&period=%v&issuer=%v&algorithm=%v", label, t.getSecret(), t.TokenLength, t.Period, issuer, t.getHashAlgorithm())
	}
	return fmt.Sprintf("otpauth://totp/%v?secret=%v&digits=%v&period=%v&issuer=%v", label, t.getSecret(), t.TokenLength, t.Period, issuer)
}

func (t *TOTP) QRCodeGoogleChartsUrl() string {
	return fmt.Sprintf("https://chart.googleapis.com/chart?cht=qr&chs=%vx%v&chl=%v", 200, 200, url.QueryEscape(t.QRCodeData()))
}

func StringToBase32(text string) string {
	bytes := []byte(text)
	return base32.StdEncoding.EncodeToString(bytes)
}

func GetRandomSecret(size int, encodeToBase32 bool) string {
	alphanum := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, size)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	if encodeToBase32 {
		return base32.StdEncoding.EncodeToString(bytes)
	}
	return string(bytes)
}
