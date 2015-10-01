package gootp

import "testing"

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
	if !totp.Verify(currentToken) {
		t.Error("the current token shoud be verified to true")
	}

	stepBackToken := totp.GetTokenByStep(-1)
	if !totp.Verify(stepBackToken) {
		t.Error("allowed step back token shoud be verified to true")
	}

	stepForwardToken := totp.GetTokenByStep(1)
	if !totp.Verify(stepForwardToken) {
		t.Error("allowed step forward token shoud be verified to true")
	}

	pastToken := totp.GetTokenByStep(-4)
	if totp.Verify(pastToken) {
		t.Error("not allowed step back token shoud not be verified to true")
	}

	futureToken := totp.GetTokenByStep(10)
	if totp.Verify(futureToken) {
		t.Error("not allowed step future token shoud not be verified to true")
	}
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
	if !totp.Verify(currentToken) {
		t.Error("the current token shoud be verified to true")
	}

	stepBackToken := totp.GetTokenByStep(-1)
	if !totp.Verify(stepBackToken) {
		t.Error("allowed step back token shoud be verified to true")
	}

	stepForwardToken := totp.GetTokenByStep(1)
	if !totp.Verify(stepForwardToken) {
		t.Error("allowed step forward token shoud be verified to true")
	}

	pastToken := totp.GetTokenByStep(-4)
	if totp.Verify(pastToken) {
		t.Error("not allowed step back token shoud not be verified to true")
	}

	futureToken := totp.GetTokenByStep(10)
	if totp.Verify(futureToken) {
		t.Error("not allowed step future token shoud not be verified to true")
	}
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
	if !totp.Verify(currentToken) {
		t.Error("the current token shoud be verified to true")
	}

	stepBackToken := totp.GetTokenByStep(-1)
	if !totp.Verify(stepBackToken) {
		t.Error("allowed step back token shoud be verified to true")
	}

	stepForwardToken := totp.GetTokenByStep(1)
	if !totp.Verify(stepForwardToken) {
		t.Error("allowed step forward token shoud be verified to true")
	}

	pastToken := totp.GetTokenByStep(-4)
	if totp.Verify(pastToken) {
		t.Error("not allowed step back token shoud not be verified to true")
	}

	futureToken := totp.GetTokenByStep(10)
	if totp.Verify(futureToken) {
		t.Error("not allowed step future token shoud not be verified to true")
	}
}
