-- GitHub OAuth 登录所需字段（github_id/github_login/github_avatar_url）
-- 注：这些列在 fa2a4de 之前的实现中已通过历史迁移加入到远程数据库，
-- 当前 schema 中保留此空迁移作为版本占位，避免重复 ALTER 出错。
-- 如需在新环境从零部署，请改回如下语句执行：
--   ALTER TABLE users ADD COLUMN github_id INTEGER;
--   ALTER TABLE users ADD COLUMN github_login TEXT;
--   ALTER TABLE users ADD COLUMN github_avatar_url TEXT;
--   CREATE UNIQUE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id) WHERE github_id IS NOT NULL;
SELECT 1;
