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
	if err != nil {
		t.Error("it should not contain error when creating a new TOTP token")
	}

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
	if err != nil {
		t.Error("it should not contain error when creating a new TOTP token")
	}

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
	if err != nil {
		t.Error("it should not contain error when creating a new TOTP token")
	}

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
