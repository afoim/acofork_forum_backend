# GitHub 登录 / 绑定 — 前端对接

后端已新增三个接口，并在 `/api/user/me` 返回中追加了 GitHub 绑定状态。所有 GitHub OAuth 接口均无需 `X-Timestamp` / `X-Nonce` 头（已加入白名单），但 `link` / `unlink` 仍需 `Authorization: Bearer <token>`。

## 0. GitHub OAuth App 配置

在 GitHub → Settings → Developer settings → OAuth Apps 中新建 / 修改：

| 字段 | 值 |
| --- | --- |
| Authorization callback URL | `https://i.2x.nz/api/auth/github/callback` |
| Homepage URL | `https://2x.nz/forum` |

将 Client ID / Client Secret 写入 Worker 的 secret：

```
wrangler secret put GITHUB_CLIENT_ID
wrangler secret put GITHUB_CLIENT_SECRET
```

> 注：`/api/auth/github/start` 会用 `request.url.origin` 拼接 redirect_uri，所以**前端必须用与 Worker 同源的接口域名**（即 `i.2x.nz`）调用 start，否则交换 token 时 redirect_uri 不一致会失败。

## 1. 发起登录 / 绑定

`GET https://i.2x.nz/api/auth/github/start`

Query：
- `mode`：`login`（默认）或 `link`
- `redirect`：完成后跳回的前端 URL，必须是同源或白名单域（`2x.nz`、`www.2x.nz`、`i.2x.nz`、`localhost`、`127.0.0.1`）。非法值会回退到 `https://2x.nz/forum/auth/login/`。

`link` 模式必须在请求头中带 `Authorization: Bearer <当前用户 token>`。

返回：
```json
{ "authorize_url": "https://github.com/login/oauth/authorize?...", "state": "<jwt>" }
```

前端拿到 `authorize_url` 后直接 `window.location.href = authorize_url` 即可。state 已是签名 JWT（10 分钟内有效），后端校验，前端无需额外存储。

示例（登录按钮）：
```ts
async function loginWithGithub() {
  const res = await fetch('https://i.2x.nz/api/auth/github/start?mode=login&redirect=' +
    encodeURIComponent(window.location.origin + '/forum/auth/github-return/'));
  const { authorize_url } = await res.json();
  window.location.href = authorize_url;
}
```

示例（绑定按钮）：
```ts
async function linkGithub(token: string) {
  const res = await fetch(
    'https://i.2x.nz/api/auth/github/start?mode=link&redirect=' +
      encodeURIComponent(window.location.href),
    { headers: { Authorization: `Bearer ${token}` } }
  );
  const { authorize_url } = await res.json();
  window.location.href = authorize_url;
}
```

## 2. 回调

GitHub 完成授权后会带 `code` & `state` 回到 `https://i.2x.nz/api/auth/github/callback`，后端处理完会 302 跳回你在 step 1 提供的 `redirect`：

### 登录成功（mode=login）
```
{redirect}#token=<jwt>&new=<0|1>
```

`new=1` 表示这是首次通过 GitHub 创建的账号。前端在 `redirect` 页面上读取 `location.hash` 即可：

```ts
// /forum/auth/github-return/ 页面
const hash = new URLSearchParams(window.location.hash.slice(1));
const token = hash.get('token');
const isNew = hash.get('new') === '1';
if (token) {
  localStorage.setItem('token', token);
  // 拉用户信息
  const me = await fetch('/api/user/me', { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json());
  // ... 跳到首页 / 提示绑定邮箱等
}
```

> token 通过 hash 而非 query 回传，避免落入 referer / 服务端日志。

### 绑定成功（mode=link）
```
{redirect}?github_linked=1
```

### 失败
```
{redirect}?github_error=<reason>
```

可能的 `reason`：
- `missing_code_or_state`、`invalid_state`、`token_exchange_failed`、`no_access_token`、`fetch_user_failed`、`invalid_github_user`、`oauth_not_configured`、`internal_error`
- `github_email_unavailable`：GitHub 账号没有任何已验证邮箱（极少数情况）。
- `email_conflict`：GitHub 账号的主邮箱在论坛已被另一个账号占用且未绑定 GitHub。引导用户先用邮箱密码登录后再走「绑定」。
- `github_already_linked_to_other`：该 GitHub 账号已绑定其他论坛账号。
- `invalid_link_state`：link 模式下 state 缺少 userId（通常是用户在 step 1 没带 token）。

前端可统一处理：
```ts
const params = new URLSearchParams(window.location.search);
const err = params.get('github_error');
if (err) toast.error(githubErrorMap[err] ?? err);
```

## 3. 解绑

`POST https://i.2x.nz/api/auth/github/unlink`

Header：`Authorization: Bearer <token>` + `X-Timestamp` / `X-Nonce`（与其它 POST 一致）。

返回：`{ "success": true }`。

错误：
- `400 当前账号未绑定 GitHub`
- `400 请先设置登录密码后再解绑 GitHub，否则将无法登录`：通过 GitHub 创建的账号默认 `password=''`，必须先调用 `/api/auth/reset-password` 流程或后续提供的「设置密码」接口设密码后才能解绑。

## 4. 自动合并已有邮箱账号

login 模式下，如果按 `github_id` 找不到用户，但 GitHub 主邮箱与论坛某个已存在账号一致，后端会**自动把当前 GitHub 账号绑定到该论坛账号**并完成登录，无需手动 link。这避免了用户既用邮箱注册又用 GitHub 注册导致两个孤立账号。

## 5. `/api/user/me` 新字段

```ts
{
  // ...原有字段
  github_id: number | null,
  github_login: string | null,
  github_avatar_url: string | null,
  has_password: boolean // 用于决定是否能直接展示「解绑」按钮
}
```

前端典型逻辑：
- 未绑定 → 显示「绑定 GitHub」按钮 → 调 step 1（mode=link）
- 已绑定且 `has_password=true` → 显示「解绑」按钮
- 已绑定且 `has_password=false` → 显示「请先设置密码」提示，禁用解绑按钮
