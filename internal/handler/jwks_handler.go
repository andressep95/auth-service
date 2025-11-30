package handler

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"

	"github.com/gofiber/fiber/v2"
)

type JWKSHandler struct {
	publicKey *rsa.PublicKey
	keyID     string
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"` // Key Type
	Use string `json:"use"` // Public Key Use
	Kid string `json:"kid"` // Key ID
	Alg string `json:"alg"` // Algorithm
	N   string `json:"n"`   // Modulus
	E   string `json:"e"`   // Exponent
}

func NewJWKSHandler(publicKey *rsa.PublicKey, keyID string) *JWKSHandler {
	return &JWKSHandler{
		publicKey: publicKey,
		keyID:     keyID,
	}
}

func (h *JWKSHandler) GetJWKS(c *fiber.Ctx) error {
	// Convertir RSA public key a formato JWK
	n := base64.RawURLEncoding.EncodeToString(h.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(h.publicKey.E)).Bytes())

	jwks := JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: h.keyID,
				Alg: "RS256",
				N:   n,
				E:   e,
			},
		},
	}

	return c.JSON(jwks)
}
