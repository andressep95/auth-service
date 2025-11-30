package service

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// TokenBlacklistService manages blacklisted tokens in Redis
type TokenBlacklistService struct {
	redis *redis.Client
}

// NewTokenBlacklistService creates a new token blacklist service
func NewTokenBlacklistService(redis *redis.Client) *TokenBlacklistService {
	return &TokenBlacklistService{
		redis: redis,
	}
}

// BlacklistToken adds a token to the blacklist with expiration
func (s *TokenBlacklistService) BlacklistToken(ctx context.Context, tokenID string, expiresAt time.Time) error {
	// Calculate TTL (time until token would naturally expire)
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}

	key := fmt.Sprintf("blacklist:token:%s", tokenID)
	return s.redis.Set(ctx, key, "1", ttl).Err()
}

// IsTokenBlacklisted checks if a token is blacklisted
func (s *TokenBlacklistService) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	key := fmt.Sprintf("blacklist:token:%s", tokenID)
	exists, err := s.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// BlacklistAllUserTokens invalidates all tokens for a user
// This is used when password is changed or account is compromised
func (s *TokenBlacklistService) BlacklistAllUserTokens(ctx context.Context, userID string, until time.Time) error {
	// Store a timestamp indicating when all tokens before this time are invalid
	key := fmt.Sprintf("blacklist:user:%s", userID)
	ttl := time.Until(until)
	if ttl <= 0 {
		ttl = 24 * time.Hour // Default 24h if no expiration provided
	}
	
	return s.redis.Set(ctx, key, until.Unix(), ttl).Err()
}

// GetUserTokenInvalidationTime returns the time after which all user tokens are invalid
func (s *TokenBlacklistService) GetUserTokenInvalidationTime(ctx context.Context, userID string) (*time.Time, error) {
	key := fmt.Sprintf("blacklist:user:%s", userID)
	timestamp, err := s.redis.Get(ctx, key).Int64()
	if err == redis.Nil {
		// No invalidation time set
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	
	t := time.Unix(timestamp, 0)
	return &t, nil
}
