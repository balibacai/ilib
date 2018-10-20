package test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	rawJWT "github.com/dgrijalva/jwt-go"
	"time"
	"ilib/jwt"
)

func init() {
	jwt.SetJWTSecret("123")
	jwt.SetJWTPrivateKey("rsaprivatekey.pem")
	jwt.SetJWTPublicKey("rsapublickey.pem")
}

type LoginClaims struct {
	UserID int64
	rawJWT.StandardClaims
}

// TestGet is a sample to run an endpoint test
func TestJWTBuildAndParseToken(t *testing.T) {
	jwt.SetJWTMode(jwt.JWTSecretMode)

	now := time.Now()
	userID := int64(1234567)
	expiredAt := now.Unix() + 3600

	tokenString, err := jwt.NewJWTTokenStringWithClaims(LoginClaims{
		userID,
		rawJWT.StandardClaims {
			ExpiresAt: expiredAt,
			Issuer: "test",
		},
	})

	Convey("build err should be nil", t, func() {
		So(err, ShouldBeNil)
	})


	// parse token with claims
	token, err := jwt.ParseJWTTokenWithClaims(tokenString, &LoginClaims{})

	Convey("parse err should be nil", t, func() {
		So(err, ShouldBeNil)
	})

	claims, ok := token.Claims.(*LoginClaims)

	Convey("token check", t, func() {
		So(ok, ShouldBeTrue)
		So(token.Valid, ShouldBeTrue)
	})

	Convey("claims check", t, func() {
		So(claims.UserID, ShouldEqual, userID)
		So(claims.StandardClaims.ExpiresAt, ShouldEqual, expiredAt)
	})
}

func TestRSAJWTBuildAndParseToken(t *testing.T) {
	jwt.SetJWTMode(jwt.JWTRSAMode)

	now := time.Now()
	userID := int64(1234567)
	expiredAt := now.Unix() + 3600

	tokenString, err := jwt.NewJWTTokenStringWithClaims(LoginClaims{
		userID,
		rawJWT.StandardClaims {
			ExpiresAt: expiredAt,
			Issuer: "test",
		},
	})

	Convey("build err should be nil", t, func() {
		So(err, ShouldBeNil)
	})

	//fmt.Printf(tokenString)

	// parse token with claims
	token, err := jwt.ParseJWTTokenWithClaims(tokenString, &LoginClaims{})

	Convey("parse err should be nil", t, func() {
		So(err, ShouldBeNil)
	})

	claims, ok := token.Claims.(*LoginClaims)

	Convey("token check", t, func() {
		So(ok, ShouldBeTrue)
		So(token.Valid, ShouldBeTrue)
	})

	//fmt.Printf("%d", claims.UserID)

	Convey("claims check", t, func() {
		So(claims.UserID, ShouldEqual, userID)
		So(claims.StandardClaims.ExpiresAt, ShouldEqual, expiredAt)
	})
}
