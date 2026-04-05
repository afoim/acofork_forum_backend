# 用户最后上线时间 API 文档

## 概述

新增字段 `last_seen_at`，记录用户最后一次调用需要认证的 API 的时间。每次用户携带有效 JWT Token 请求任何需要认证的接口时，后端会自动更新该字段（非阻塞写入，不影响请求响应速度）。

---

## 数据库变更

### `users` 表新增字段

| 字段名 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `last_seen_at` | `TIMESTAMP` | `NULL` | 用户最后上线时间（UTC），从未登录过的用户为 `null` |

---

## 受影响的 API 接口

### 1. `GET /api/users/:id` — 获取用户公开信息

**认证**: 不需要

**响应示例**:

```json
{
  "id": 1,
  "username": "Alice",
  "avatar_url": "https://...",
  "role": "user",
  "gender": "female",
  "bio": "Hello World",
  "age": 25,
  "region": "Shanghai",
  "created_at": "2025-01-01T00:00:00.000Z",
  "last_seen_at": "2026-04-05T06:30:00.000Z"
}
```

> **新增字段**: `last_seen_at` — 用户最后活跃时间，类型为 ISO 8601 时间戳字符串或 `null`。

---

### 2. `GET /api/user/me` — 获取当前登录用户信息

**认证**: 需要 `Authorization: Bearer <token>`

**响应示例**:

```json
{
  "id": 1,
  "email": "alice@example.com",
  "username": "Alice",
  "avatar_url": "https://...",
  "role": "user",
  "totp_enabled": false,
  "email_notifications": true,
  "article_notifications": false,
  "gender": "female",
  "bio": "Hello World",
  "age": 25,
  "region": "Shanghai",
  "last_seen_at": "2026-04-05T06:30:00.000Z"
}
```

> **新增字段**: `last_seen_at`

---

### 3. `GET /api/admin/users` — 管理员获取用户列表

**认证**: 需要管理员权限

**响应示例** (数组中的每个对象):

```json
{
  "id": 1,
  "email": "alice@example.com",
  "username": "Alice",
  "role": "user",
  "verified": 1,
  "created_at": "2025-01-01T00:00:00.000Z",
  "avatar_url": "https://...",
  "last_seen_at": "2026-04-05T06:30:00.000Z"
}
```

> **新增字段**: `last_seen_at`

---

## 更新机制

- 用户每次发送带有效 `Authorization: Bearer <token>` 的请求时，后端自动更新 `last_seen_at` 为当前时间
- 更新操作通过 `ctx.waitUntil()` 异步执行，**不会阻塞 API 响应**
- 如果更新失败（如数据库短暂不可用），错误会被静默忽略，不影响正常业务

## 前端使用建议

1. **用户资料页**: 在 `GET /api/users/:id` 返回中读取 `last_seen_at` 字段，展示为"最后上线: X分钟前"
2. **管理后台**: 在用户列表中显示每个用户的最后活跃时间
3. **空值处理**: 当 `last_seen_at` 为 `null` 时，表示该用户从未使用过需要认证的功能（新注册但未操作），可显示为"从未上线"

## 时区说明

- `last_seen_at` 存储的是 SQLite 的 `CURRENT_TIMESTAMP`，即 **UTC 时间**
- 前端需要自行转换为用户的本地时区进行展示
