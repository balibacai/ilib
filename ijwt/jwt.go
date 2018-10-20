package ijwt

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
)

type JWTMode int

const (
	_ JWTMode = iota
	JWTSecretMode
	JWTRSAMode
)

var (
	mode     JWTMode
	myJwt    = new(JWT)
	myRSAJwt = new(RSAJWT)
)

type JWT struct {
	Secret []byte
}

type RSAJWT struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func (j *JWT) SetSecret(secret string) {
	j.Secret = []byte(secret)
}

func (j *JWT) ParseWithClaims(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	// parse token with claims
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return j.Secret, nil
	})

	return token, err
}

func (j *RSAJWT) SetPrivateKey(pem []byte) {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(pem)
	if err != nil {
		panic(err)
	}
	j.PrivateKey = privateKey
}

func (j *RSAJWT) SetPublicKey(pem []byte) {
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pem)
	if err != nil {
		panic(err)
	}
	j.PublicKey = publicKey
}

func (j *RSAJWT) ParseWithClaims(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	// parse token with claims
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return j.PublicKey, nil
	})

	return token, err
}

func (j *RSAJWT) NewSignatureWithClaims(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, err := token.SignedString(j.PrivateKey)
	return ss, err
}

func (j *JWT) NewSignatureWithClaims(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(j.Secret)

	return ss, err
}

func SetJWTMode(userMode JWTMode) {
	mode = userMode
}

func SetJWTSecret(secret string) {
	myJwt.SetSecret(secret)
}

func SetJWTPublicKey(path string) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	myRSAJwt.SetPublicKey(pemBytes)
}

func SetJWTPrivateKey(path string) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	myRSAJwt.SetPrivateKey(pemBytes)
}

func ParseJWTTokenWithClaims(tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	if mode == JWTSecretMode {
		return myJwt.ParseWithClaims(tokenString, claims)
	} else if mode == JWTRSAMode {
		return myRSAJwt.ParseWithClaims(tokenString, claims)
	} else {
		panic("jwt mode not config")
	}
}

func NewJWTTokenStringWithClaims(claims jwt.Claims) (string, error) {
	if mode == JWTSecretMode {
		return myJwt.NewSignatureWithClaims(claims)
	} else if mode == JWTRSAMode {
		return myRSAJwt.NewSignatureWithClaims(claims)
	} else {
		panic("jwt mode not config")
	}
}
