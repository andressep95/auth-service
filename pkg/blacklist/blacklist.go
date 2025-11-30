package blacklist

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// TokenBlacklist manages blacklisted JWT tokens in Redis
type TokenBlacklist struct {
	redis *redis.Client
}

// NewTokenBlacklist creates a new token blacklist service
func NewTokenBlacklist(redisClient *redis.Client) *TokenBlacklist {
	return &TokenBlacklist{
		redis: redisClient,
	}
}

// Add adds a token to the blacklist with TTL
// The token will be automatically removed after the TTL expires
func (b *TokenBlacklist) Add(ctx context.Context, token string, ttl time.Duration) error {
	key := fmt.Sprintf("blacklist:token:%s", token)

	err := b.redis.Set(ctx, key, "1", ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to add token to blacklist: %w", err)
	}

	return nil
}

// AddAccessToken adds an access token to the blacklist
// Uses the token's remaining lifetime as TTL
func (b *TokenBlacklist) AddAccessToken(ctx context.Context, token string, expiresAt time.Time) error {
	// Calculate remaining TTL
	ttl := time.Until(expiresAt)

	// If already expired, no need to blacklist
	if ttl <= 0 {
		return nil
	}

	return b.Add(ctx, token, ttl)
}

// IsBlacklisted checks if a token is in the blacklist
func (b *TokenBlacklist) IsBlacklisted(ctx context.Context, token string) (bool, error) {
	key := fmt.Sprintf("blacklist:token:%s", token)

	exists, err := b.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check blacklist: %w", err)
	}

	return exists > 0, nil
}

// Remove removes a token from the blacklist (rarely used)
func (b *TokenBlacklist) Remove(ctx context.Context, token string) error {
	key := fmt.Sprintf("blacklist:token:%s", token)

	err := b.redis.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to remove token from blacklist: %w", err)
	}

	return nil
}

// Clear removes all blacklisted tokens (use with caution)
func (b *TokenBlacklist) Clear(ctx context.Context) error {
	// Get all blacklist keys
	keys, err := b.redis.Keys(ctx, "blacklist:token:*").Result()
	if err != nil {
		return fmt.Errorf("failed to get blacklist keys: %w", err)
	}

	if len(keys) == 0 {
		return nil
	}

	// Delete all keys
	err = b.redis.Del(ctx, keys...).Err()
	if err != nil {
		return fmt.Errorf("failed to clear blacklist: %w", err)
	}

	return nil
}

// Count returns the number of blacklisted tokens
func (b *TokenBlacklist) Count(ctx context.Context) (int64, error) {
	keys, err := b.redis.Keys(ctx, "blacklist:token:*").Result()
	if err != nil {
		return 0, fmt.Errorf("failed to count blacklist: %w", err)
	}

	return int64(len(keys)), nil
}

// BlacklistUser invalidates all tokens issued before the current time
// The invalidation marker expires after ttl (should be longer than max token lifetime)
func (b *TokenBlacklist) BlacklistUser(ctx context.Context, userID string, ttl time.Duration) error {
	key := fmt.Sprintf("blacklist:user:%s", userID)
	
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	
	// Store current timestamp - tokens issued BEFORE this time are invalid
	invalidationTimestamp := time.Now().Unix()
	return b.redis.Set(ctx, key, invalidationTimestamp, ttl).Err()
}

// IsUserBlacklisted checks if a token was issued before the user's invalidation time
func (b *TokenBlacklist) IsUserBlacklisted(ctx context.Context, userID string, tokenIssuedAt time.Time) (bool, error) {
	key := fmt.Sprintf("blacklist:user:%s", userID)
	
	timestamp, err := b.redis.Get(ctx, key).Int64()
	if err == redis.Nil {
		// No invalidation marker exists
		return false, nil
	}
	if err != nil {
		return false, err
	}
	
	// Token is blacklisted if it was issued BEFORE the invalidation time
	invalidationTime := time.Unix(timestamp, 0)
	return tokenIssuedAt.Before(invalidationTime), nil
}
