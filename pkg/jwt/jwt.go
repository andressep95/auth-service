package jwt

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/andressep95/auth-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidSigningMethod = errors.New("unexpected signing method")
	ErrInvalidToken         = errors.New("invalid token")
)

type TokenService struct {
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	issuer        string
}

func NewTokenService(privateKeyPEM, publicKeyPEM []byte, accessExpiry, refreshExpiry time.Duration, issuer string) (*TokenService, error) {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, err
	}

	return &TokenService{
		privateKey:    privateKey,
		publicKey:     publicKey,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
		issuer:        issuer,
	}, nil
}

func (s *TokenService) GenerateTokenPair(user *domain.User, roles []string, appID uuid.UUID) (*domain.TokenPair, error) {
	now := time.Now()
	accessExp := now.Add(s.accessExpiry)

	accessClaims := domain.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   user.ID.String(),
			ExpiresAt: jwt.NewNumericDate(accessExp),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		UserID:    user.ID,
		Email:     user.Email,
		Roles:     roles,
		AppID:     appID,
		TokenType: "access",
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(s.privateKey)
	if err != nil {
		return nil, err
	}

	// Refresh token with fewer claims
	refreshClaims := domain.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   user.ID.String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.refreshExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		UserID:    user.ID,
		TokenType: "refresh",
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(s.privateKey)
	if err != nil {
		return nil, err
	}

	return &domain.TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresAt:    accessExp,
		TokenType:    "Bearer",
	}, nil
}

func (s *TokenService) ValidateToken(tokenString string) (*domain.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrInvalidSigningMethod
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*domain.Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// GetPublicKey returns the RSA public key for JWKS endpoint
func (s *TokenService) GetPublicKey() *rsa.PublicKey {
	return s.publicKey
}
