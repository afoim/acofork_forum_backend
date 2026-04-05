-- Add last_seen_at column to users table to track user's last online time
ALTER TABLE users ADD COLUMN last_seen_at TIMESTAMP;
