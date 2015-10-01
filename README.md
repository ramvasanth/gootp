## GOOTP

This go packages can be used to implemet Google Authenticator's Server Side. This go paackage supports only **TOTP **for the following algorithm 

SHA1 (default)

SHA256

SHA512

Example Usage:

package main

import (
    "fmt"
    "github.com/ramvasanth/gootp"
)

func main() {
    otpParameter := &gootp.OTPParameter{}
    key := "THISISAPLAINKEY12345"
    // key has to be atleast 18 characters length
    otpParameter.Secret = gootp.StringToBase32(key)

    otpParameter.StepsBack = 1
    otpParameter.StepsForward = 1
    otpParameter.HashFunction = gootp.SHA1
    // you can use gootp.SHA256 or gootp.SHA512
    // if you dont use SHA1, you need to use addtional paramter
    //   otpParameter.AlgorithmInQRCode = true

    otpParameter.TokenLength = 6
    otpParameter.Label = "ram.praximo@gmail.com"
    otpParameter.Issuer = "GreenSolutions"
    totp, _ := gootp.NewTOTP(otpParameter)

    //To get the QRCode
    totp.QRCodeData()

    //To get the Google Charts URL for generating QR image
    totp.QRCodeGoogleChartsUrl()

    //To verify the token based on the steps back and forward
    totp.Verify(115455)

    // if you want to get current token
    fmt.Printf("Current token: %d\n", totp.GetCurrentToken())

    // if you want to get the future token
    fmt.Printf("Future token +1: %d\n", totp.GetTokenByStep(1))

    // if you want to get the past token
    fmt.Printf("Past token -1: %d\n", totp.GetTokenByStep(-1))

}