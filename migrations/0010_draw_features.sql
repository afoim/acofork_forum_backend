-- AI 生图功能：限流表 + 用户 draw_banned 字段
CREATE TABLE IF NOT EXISTS draw_rate_limits (
  user_id INTEGER PRIMARY KEY,
  last_at INTEGER NOT NULL DEFAULT 0
);

ALTER TABLE users ADD COLUMN draw_banned INTEGER NOT NULL DEFAULT 0;
