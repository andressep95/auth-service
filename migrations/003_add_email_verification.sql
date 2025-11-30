-- Migration: Add email verification fields
-- Description: Adds fields for email verification and password reset functionality
-- Created: 2024-11-30

-- Add email verification token and expiry
ALTER TABLE users
ADD COLUMN email_verification_token VARCHAR(255),
ADD COLUMN email_verification_token_expires_at TIMESTAMPTZ,
ADD COLUMN password_reset_token VARCHAR(255),
ADD COLUMN password_reset_token_expires_at TIMESTAMPTZ;

-- Add index for faster token lookups
CREATE INDEX idx_users_email_verification_token ON users(email_verification_token)
WHERE email_verification_token IS NOT NULL;

CREATE INDEX idx_users_password_reset_token ON users(password_reset_token)
WHERE password_reset_token IS NOT NULL;

-- Add comments for documentation
COMMENT ON COLUMN users.email_verification_token IS 'Token sent via email for account verification';
COMMENT ON COLUMN users.email_verification_token_expires_at IS 'Expiration timestamp for verification token (24 hours)';
COMMENT ON COLUMN users.password_reset_token IS 'Token sent via email for password reset';
COMMENT ON COLUMN users.password_reset_token_expires_at IS 'Expiration timestamp for reset token (1 hour)';
