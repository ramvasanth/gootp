package gootp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSHA1OTP(t *testing.T) {
	otpParameter := &OTPParameter{}
	otpParameter.Secret = "NM2VG3CRIVBVGMLKMFUWIRDEJJUE4STGKVGW4T2SNJVE6MBWHFWTCUCVOZYWQMLPPJJFQMLJIFEEY23IGNDDSYKNKZTFON3VMNXFC4ZQNVCWE2SXKRRUY6DYO5BWQSBXMNGVETD2KZWUWV2XJBGVOULUKRLU2MLV"

	otpParameter.StepsBack = 1
	otpParameter.StepsForward = 1
	otpParameter.HashFunction = SHA1
	otpParameter.TokenLength = 6
	otpParameter.Label = "My Name"
	otpParameter.Issuer = "My Company"
	totp, err := NewTOTP(otpParameter)
	assert.Nil(t, err, "it should not contain error when creating a new TOTP token")

	currentToken := totp.GetCurrentToken()
	assert.True(t, totp.Verify(currentToken), "the current token shoud be verified to true")

	stepBackToken := totp.GetTokenByStep(-1)

	assert.True(t, totp.Verify(stepBackToken), "allowed step back token shoud be verified to true")

	stepForwardToken := totp.GetTokenByStep(1)
	assert.True(t, totp.Verify(stepForwardToken), "allowed step forward token shoud be verified to true")

	pastToken := totp.GetTokenByStep(-4)
	assert.False(t, totp.Verify(pastToken), "not allowed step back token shoud not be verified")

	futureToken := totp.GetTokenByStep(10)
	assert.False(t, totp.Verify(futureToken), "not allowed step future token shoud not be verified")
}

func TestSHA256OTP(t *testing.T) {
	otpParameter := &OTPParameter{}
	otpParameter.Secret = "NM2VG3CRIVBVGMLKMFUWIRDEJJUE4STGKVGW4T2SNJVE6MBWHFWTCUCVOZYWQMLPPJJFQMLJIFEEY23IGNDDSYKNKZTFON3VMNXFC4ZQNVCWE2SXKRRUY6DYO5BWQSBXMNGVETD2KZWUWV2XJBGVOULUKRLU2MLV"

	otpParameter.StepsBack = 1
	otpParameter.StepsForward = 1
	otpParameter.HashFunction = SHA256
	otpParameter.TokenLength = 6
	otpParameter.Label = "My Name"
	otpParameter.Issuer = "My Company"
	totp, err := NewTOTP(otpParameter)

	assert.Nil(t, err, "it should not contain error when creating a new TOTP token")

	currentToken := totp.GetCurrentToken()
	assert.True(t, totp.Verify(currentToken), "the current token shoud be verified to true")

	stepBackToken := totp.GetTokenByStep(-1)

	assert.True(t, totp.Verify(stepBackToken), "allowed step back token shoud be verified to true")

	stepForwardToken := totp.GetTokenByStep(1)
	assert.True(t, totp.Verify(stepForwardToken), "allowed step forward token shoud be verified to true")

	pastToken := totp.GetTokenByStep(-4)
	assert.False(t, totp.Verify(pastToken), "not allowed step back token shoud not be verified")

	futureToken := totp.GetTokenByStep(10)
	assert.False(t, totp.Verify(futureToken), "not allowed step future token shoud not be verified")
}

func TestSHA512OTP(t *testing.T) {
	otpParameter := &OTPParameter{}
	otpParameter.Secret = "NM2VG3CRIVBVGMLKMFUWIRDEJJUE4STGKVGW4T2SNJVE6MBWHFWTCUCVOZYWQMLPPJJFQMLJIFEEY23IGNDDSYKNKZTFON3VMNXFC4ZQNVCWE2SXKRRUY6DYO5BWQSBXMNGVETD2KZWUWV2XJBGVOULUKRLU2MLV"

	otpParameter.StepsBack = 1
	otpParameter.StepsForward = 1
	otpParameter.HashFunction = SHA512
	otpParameter.TokenLength = 6
	otpParameter.Label = "My Name"
	otpParameter.Issuer = "My Company"
	totp, err := NewTOTP(otpParameter)

	assert.Nil(t, err, "it should not contain error when creating a new TOTP token")

	currentToken := totp.GetCurrentToken()
	assert.True(t, totp.Verify(currentToken), "the current token shoud be verified to true")

	stepBackToken := totp.GetTokenByStep(-1)

	assert.True(t, totp.Verify(stepBackToken), "allowed step back token shoud be verified to true")

	stepForwardToken := totp.GetTokenByStep(1)
	assert.True(t, totp.Verify(stepForwardToken), "allowed step forward token shoud be verified to true")

	pastToken := totp.GetTokenByStep(-4)
	assert.False(t, totp.Verify(pastToken), "not allowed step back token shoud not be verified")

	futureToken := totp.GetTokenByStep(10)
	assert.False(t, totp.Verify(futureToken), "not allowed step future token shoud not be verified")
}

func TestTOTPDefaultConstants(t *testing.T) {
	assert.Equal(t, DefaultPeriod, 30, "TOTP Default period should be 30")
	assert.Equal(t, DefaultTokenLength, 6, "TOTP Default Token Length should be 6")
	assert.Equal(t, DefaultHashAlgorithm, SHA1, "TOTP Default Hash Algorithm should be SHA1")
	assert.Equal(t, DefaultStepsForward, 1, "TOTP Default Steps Forward should be 1")
	assert.Equal(t, DefaultStepsBack, 1, "TOTP Default Steps Back should be 1")
}

func TestTOTPsetDeafultValues(t *testing.T) {
	otpParameter := &OTPParameter{}
	otpParameter.Secret = "NM2VG3CRIVBVGMLKMFUWIRDEJJUE4STGKVGW4T2SNJVE6MBWHFWTCUCVOZYWQMLPPJJFQMLJIFEEY23IGNDDSYKNKZTFON3VMNXFC4ZQNVCWE2SXKRRUY6DYO5BWQSBXMNGVETD2KZWUWV2XJBGVOULUKRLU2MLV"
	totp, _ := NewTOTP(otpParameter)
	assert.Equal(t, totp.Period, uint8(30), "TOTP Default period should be 30")
	assert.Equal(t, totp.TokenLength, uint8(6), "TOTP Default Token Length should be 6")
	assert.Equal(t, totp.HashFunction, SHA1, "TOTP Default Hash Algorithm should be SHA1")
	assert.Equal(t, totp.StepsForward, 1, "TOTP Default Steps Forward should be 1")
	assert.Equal(t, totp.StepsBack, 1, "TOTP Default Steps Back should be 1")
}

func TestTOTPGetSecret(t *testing.T) {
	otpParameter := &OTPParameter{}
	otpParameter.Secret = "NM2VG3CRIVBVGMLKMFUWIRDEJJUE4STGKVGW4T2SNJVE6MBWHFWTCUCVOZYWQMLPPJJFQMLJIFEEY23IGNDDSYKNKZTFON3VMNXFC4ZQNVCWE2SXKRRUY6DYO5BWQSBXMNGVETD2KZWUWV2XJBGVOULUKRLU2MLV"
	totp, _ := NewTOTP(otpParameter)
	assert.Equal(t, totp.getSecret(), otpParameter.Secret, "TOTP Secret should be same")
}

func TestTOTPQRCodeData(t *testing.T) {
	otpParameter := &OTPParameter{}
	otpParameter.Secret = "NM2VG3CRIVBVGMLKMFUWIRDEJJUE4STGKVGW4T2SNJVE6MBWHFWTCUCVOZYWQMLPPJJFQMLJIFEEY23IGNDDSYKNKZTFON3VMNXFC4ZQNVCWE2SXKRRUY6DYO5BWQSBXMNGVETD2KZWUWV2XJBGVOULUKRLU2MLV"
	totp, _ := NewTOTP(otpParameter)
	validQR := "otpauth://totp/?secret=NM2VG3CRIVBVGMLKMFUWIRDEJJUE4STGKVGW4T2SNJVE6MBWHFWTCUCVOZYWQMLPPJJFQMLJIFEEY23IGNDDSYKNKZTFON3VMNXFC4ZQNVCWE2SXKRRUY6DYO5BWQSBXMNGVETD2KZWUWV2XJBGVOULUKRLU2MLV&digits=6&period=30&issuer="
	assert.Equal(t, totp.QRCodeData(), validQR, "TOTP QR code should be valid")
}

func TestTOTPQRCodeDataWithAlgorithm(t *testing.T) {
	otpParameter := &OTPParameter{}
	otpParameter.Secret = "NM2VG3CRIVBVGMLKMFUWIRDEJJUE4STGKVGW4T2SNJVE6MBWHFWTCUCVOZYWQMLPPJJFQMLJIFEEY23IGNDDSYKNKZTFON3VMNXFC4ZQNVCWE2SXKRRUY6DYO5BWQSBXMNGVETD2KZWUWV2XJBGVOULUKRLU2MLV"
	otpParameter.AlgorithmInQRCode = true
	totp, _ := NewTOTP(otpParameter)
	validQR := "otpauth://totp/?secret=NM2VG3CRIVBVGMLKMFUWIRDEJJUE4STGKVGW4T2SNJVE6MBWHFWTCUCVOZYWQMLPPJJFQMLJIFEEY23IGNDDSYKNKZTFON3VMNXFC4ZQNVCWE2SXKRRUY6DYO5BWQSBXMNGVETD2KZWUWV2XJBGVOULUKRLU2MLV&digits=6&period=30&issuer=&algorithm=sha1"
	assert.Equal(t, totp.QRCodeData(), validQR, "TOTP QR code should be valid")
}

func TestStringToBase32(t *testing.T) {
	text := "This is plain simple text"
	assert.Equal(t, StringToBase32(text), "KRUGS4ZANFZSA4DMMFUW4IDTNFWXA3DFEB2GK6DU", "should contain vlaid base32 string")
}

func TestUrlEncode(t *testing.T) {
	otpParameter := &OTPParameter{}
	otpParameter.Secret = "NM2VG3CRIVBVGMLKMFUWIRDEJJUE4STGKVGW4T2SNJVE6MBWHFWTCUCVOZYWQMLPPJJFQMLJIFEEY23IGNDDSYKNKZTFON3VMNXFC4ZQNVCWE2SXKRRUY6DYO5BWQSBXMNGVETD2KZWUWV2XJBGVOULUKRLU2MLV"
	otpParameter.AlgorithmInQRCode = true
	totp, _ := NewTOTP(otpParameter)
	text := "This is ~!@#$%^&*()_+"
	assert.Equal(t, totp.urlEncode(text), "This is ~%21%40%23%24%25%5E%26%2A%28%29_%2B", "URL should be encoded")

}
