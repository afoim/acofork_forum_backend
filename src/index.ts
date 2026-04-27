
import { sendEmail } from './smtp';
import { generateIdenticon } from './identicon';
import { uploadImage, deleteImage, listAllKeys, getPublicUrl, extractImageKey, S3Env } from './s3';
import * as OTPAuth from 'otpauth';
import { Security, UserPayload } from './security';
import { SignJWT, jwtVerify } from 'jose';
export { SSEHub, handleSSEConnection } from './sse-hub';
export { DrawWsProxy } from './draw-ws-proxy';

// Utility to extract image URLs from Markdown content
function extractImageUrls(content: string): string[] {
	if (!content) return [];
	const urls: string[] = [];
	const regex = /!\[.*?\]\((.*?)\)/g;
	let match;
	while ((match = regex.exec(content)) !== null) {
		urls.push(match[1]);
	}
	return urls;
}

function extractManagedImageKey(value: string, env: S3Env): string | null {
	return extractImageKey(env, value);
}

function rewriteMarkdownImageRefs(content: string, transform: (value: string) => string | null): string {
	if (!content) return content;
	return content.replace(/(!\[.*?\]\()(.*?)(\))/g, (_match, prefix, rawValue, suffix) => {
		const nextValue = transform(rawValue.trim());
		return `${prefix}${nextValue ?? rawValue}${suffix}`;
	});
}

function rewriteMarkdownImageRefsToStoredForm(content: string, env: S3Env): string {
	return rewriteMarkdownImageRefs(content, (value) => extractManagedImageKey(value, env));
}

function rewriteMarkdownImageRefsToPublicUrl(content: string, env: S3Env): string {
	return rewriteMarkdownImageRefs(content, (value) => {
		const key = extractManagedImageKey(value, env);
		return key ? getPublicUrl(env, key) : null;
	});
}

function extractManagedImageKeysFromMarkdown(content: string, env: S3Env): string[] {
	return extractImageUrls(content)
		.map((value) => extractManagedImageKey(value, env))
		.filter((value): value is string => !!value);
}

function normalizeAvatarValueForStorage(value: unknown, env: S3Env): string | null {
	if (value === undefined || value === null) return null;
	if (typeof value !== 'string') return null;
	const trimmed = value.trim();
	if (!trimmed) return null;
	if (trimmed.startsWith('data:image/svg+xml')) return trimmed;
	const key = extractManagedImageKey(trimmed, env);
	return key ?? trimmed;
}

function rewriteAvatarValueToPublicUrl(value: unknown, env: S3Env): string | null {
	if (value === undefined || value === null) return null;
	if (typeof value !== 'string') return null;
	const trimmed = value.trim();
	if (!trimmed) return null;
	if (trimmed.startsWith('data:')) return trimmed;
	const key = extractManagedImageKey(trimmed, env);
	return key ? getPublicUrl(env, key) : trimmed;
}

function rewritePostForResponse(post: any, env: S3Env) {
	return {
		...post,
		content: rewriteMarkdownImageRefsToPublicUrl(post.content as string, env),
		author_avatar: rewriteAvatarValueToPublicUrl(post.author_avatar, env)
	};
}

function rewriteCommentForResponse(comment: any, env: S3Env) {
	return {
		...comment,
		content: rewriteMarkdownImageRefsToPublicUrl(comment.content as string, env),
		avatar_url: rewriteAvatarValueToPublicUrl(comment.avatar_url, env)
	};
}

// Utility to hash password
async function hashPassword(password: string): Promise<string> {
	const myText = new TextEncoder().encode(password);
	const myDigest = await crypto.subtle.digest(
		{
			name: 'SHA-256',
		},
		myText
	);
	const hashArray = Array.from(new Uint8Array(myDigest));
	const hashHex = hashArray
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
	return hashHex;
}

// Utility to generate a random token (simple UUID for now) - DEPRECATED for AUTH, used for verification/reset
function generateToken(): string {
	return crypto.randomUUID();
}

// Utility to check for control characters
function hasControlCharacters(str: string): boolean {
	// eslint-disable-next-line no-control-regex
	return /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(str);
}

// Utility to check if string is visually empty (only whitespace or invisible chars)
function isVisuallyEmpty(str: string): boolean {
	if (!str) return true;
	// Replace whitespace and common invisible characters
	// \u200B-\u200F: Zero Width Space, ZWNJ, ZWJ, LRM, RLM
	// \uFEFF: BOM
	// \u2028-\u2029: Line/Paragraph Separator
	// \u180E: Mongolian Vowel Separator
    // \u3164: Hangul Filler
    // \u115F-\u1160: Hangul Choseong/Jungseong Filler
	// \x00-\x1F\x7F: ASCII Control Chars
	const stripped = str.replace(/[\s\u200B-\u200F\uFEFF\u2028\u2029\u180E\u3164\u115F\u1160\x00-\x1F\x7F]+/g, '');
	return stripped.length === 0;
}

// Utility to check for invisible characters
function hasInvisibleCharacters(str: string): boolean {
	return /[\u200B-\u200F\uFEFF\u2028\u2029\u180E\u3164\u115F\u1160]/.test(str);
}

// Utility to check restricted username keywords
function hasRestrictedKeywords(username: string): boolean {
	const restricted = ['管理', 'admin', 'sudo', 'acofork', '二叉树树', '胡丁','huding'];
	const normalized = username.toLowerCase().replace(/\s+/g, '');
	return restricted.some(keyword => normalized.includes(keyword.toLowerCase()));
}

function normalizeOptionalProfileText(value: unknown, maxLength: number, fieldName: string): string | null {
	if (value === undefined || value === null) return null;
	if (typeof value !== 'string') throw new Error(`${fieldName} must be a string`);
	const trimmed = value.trim();
	if (!trimmed) return null;
	if (trimmed.length > maxLength) throw new Error(`${fieldName} too long (Max ${maxLength} chars)`);
	if (hasInvisibleCharacters(trimmed)) throw new Error(`${fieldName} contains invalid invisible characters`);
	if (hasControlCharacters(trimmed)) throw new Error(`${fieldName} contains invalid control characters`);
	return trimmed;
}

function normalizeProfileGender(value: unknown): string | null {
	const normalized = normalizeOptionalProfileText(value, 20, 'Gender');
	if (normalized === null) return null;
	const allowedValues = ['male', 'female', 'other', 'prefer_not_to_say'];
	if (!allowedValues.includes(normalized)) throw new Error('Invalid gender');
	return normalized;
}

function normalizeProfileAge(value: unknown): number | null {
	if (value === undefined || value === null || value === '') return null;
	if (typeof value !== 'number' || !Number.isInteger(value)) throw new Error('Age must be an integer');
	if (value <= 0 || value > 150) throw new Error('Age must be between 1 and 150');
	return value;
}

type EmailTemplatePayload = Record<string, string>;

type EmailTemplateDefinition = {
	key: string;
	label: string;
	requiredFields: string[];
	defaults: (origin: string) => EmailTemplatePayload;
	build: (payload: EmailTemplatePayload) => { subject: string; html: string };
};

function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

const EMAIL_REPLY_HINT = '<p style="margin-top: 20px; padding: 15px; background-color: #f0f9ff; border-left: 4px solid #3b82f6; border-radius: 4px;"><strong>💡 提示：</strong>建议您<a href="mailto:i@2x.nz?subject=%E5%8F%8C%E5%90%91%E9%80%9A%E8%AE%AF%E7%94%B3%E8%AF%B7&body=0" style="color: #3b82f6;">回复该邮件</a>以达成双向通讯，我们的邮件服务对于双向通讯客户无发邮限制。</p>';
function isValidEmail(email: string): boolean {
	return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

const EMAIL_TEMPLATE_DEFINITIONS: EmailTemplateDefinition[] = [
	{
		key: 'smtp_test',
		label: 'SMTP 测试邮件',
		requiredFields: [],
		defaults: () => ({}),
		build: () => ({
			subject: '测试邮件',
			html: `<h1>测试邮件发送成功</h1><p>这是一封用于验证 SMTP 配置的测试邮件。</p>${EMAIL_REPLY_HINT}`
		})
	},
	{
		key: 'reset_password',
		label: '密码重置邮件',
		requiredFields: ['resetLink'],
		defaults: (_origin) => ({
			resetLink: 'https://2x.nz/forum/auth/reset-password/?token=test-reset-token'
		}),
		build: (payload) => ({
			subject: '密码重置请求',
			html: `
					<h1>密码重置请求</h1>
					<p>我们收到了您的密码重置申请，请点击下方链接继续操作：</p>
					<a href="${payload.resetLink}">立即重置密码</a>
					<p>如果这不是您本人操作，请忽略此邮件。</p>
					<p>该链接将在 1 小时后失效。</p>
					${EMAIL_REPLY_HINT}
				`
		})
	},
	{
		key: 'change_email_confirm',
		label: '更换邮箱确认邮件',
		requiredFields: ['newEmail', 'verifyLink'],
		defaults: (origin) => ({
			newEmail: 'new-email@example.com',
			verifyLink: `${origin}/api/verify-email-change?token=test-email-change-token`
		}),
		build: (payload) => ({
			subject: '确认更换邮箱',
			html: `
					<h1>确认更换邮箱</h1>
					<p>您正在将账户邮箱更换为 <strong>${escapeHtml(payload.newEmail)}</strong>。</p>
					<p>请点击下方链接完成确认：</p>
					<a href="${payload.verifyLink}">确认更换邮箱</a>
					<p>如果这不是您本人操作，请忽略此邮件。</p>
					${EMAIL_REPLY_HINT}
				`
		})
	},
	{
		key: 'register_verify',
		label: '注册验证邮件',
		requiredFields: ['username', 'verifyLink'],
		defaults: (origin) => ({
			username: '测试用户',
			verifyLink: `${origin}/api/verify?token=test-register-verify-token`
		}),
		build: (payload) => ({
			subject: '请验证您的邮箱',
			html: `
					<h1>${escapeHtml(payload.username)}，欢迎加入论坛！</h1>
					<p>请点击下方链接验证您的邮箱地址：</p>
					<a href="${payload.verifyLink}">立即验证邮箱</a>
					<p>如果这不是您本人操作，请忽略此邮件。</p>
					${EMAIL_REPLY_HINT}
				`
		})
	},
	{
		key: 'admin_resend_verify',
		label: '后台重发验证邮件',
		requiredFields: ['username', 'verifyLink'],
		defaults: (origin) => ({
			username: '测试用户',
			verifyLink: `${origin}/api/verify?token=test-admin-resend-token`
		}),
		build: (payload) => ({
			subject: '请验证您的邮箱',
			html: `
					<h1>${escapeHtml(payload.username)}，您好！</h1>
					<p>请点击下方链接验证您的邮箱地址：</p>
					<a href="${payload.verifyLink}">立即验证邮箱</a>
					<p>如果这不是您本人操作，请忽略此邮件。</p>
					${EMAIL_REPLY_HINT}
				`
		})
	},
	{
		key: 'admin_avatar_updated',
		label: '后台头像更新通知',
		requiredFields: [],
		defaults: () => ({}),
		build: () => ({
			subject: '您的头像已更新',
			html: `
					<h1>头像已更新</h1>
					<p>管理员已为您更新头像。</p>
					<p>如果这不是您预期的操作，请及时联系管理员。</p>
					${EMAIL_REPLY_HINT}
				`
		})
	},
	{
		key: 'admin_username_updated',
		label: '后台用户名更新通知',
		requiredFields: ['username'],
		defaults: () => ({
			username: '测试用户'
		}),
		build: (payload) => ({
			subject: '您的用户名已修改',
			html: `
					<h1>用户名已修改</h1>
					<p>您的用户名已被管理员修改为 <strong>${escapeHtml(payload.username)}</strong>。</p>
					<p>如有疑问，请联系管理员。</p>
					${EMAIL_REPLY_HINT}
				`
		})
	},
	{
		key: 'admin_manual_verified',
		label: '后台手动验证通知',
		requiredFields: ['username'],
		defaults: () => ({
			username: '测试用户'
		}),
		build: (payload) => ({
			subject: '您的账户已通过验证',
			html: `
					<h1>账户已验证</h1>
					<p>您的账户（用户名：<strong>${escapeHtml(payload.username)}</strong>）已通过管理员手动验证。</p>
					<p>您现在可以登录并使用全部功能。</p>
					${EMAIL_REPLY_HINT}
				`
		})
	},
	{
		key: 'admin_account_deleted',
		label: '后台删号通知',
		requiredFields: ['username'],
		defaults: () => ({
			username: '测试用户'
		}),
		build: (payload) => ({
			subject: '您的账户已被删除',
			html: `
					<h1>账户已删除</h1>
					<p>您的账户（用户名：<strong>${escapeHtml(payload.username)}</strong>）已被管理员删除。</p>
					<p>如果您认为这是误操作，请尽快联系管理员。</p>
					${EMAIL_REPLY_HINT}
				`
		})
	},
	{
		key: 'admin_post_deleted',
		label: '后台删帖通知',
		requiredFields: ['username', 'postTitle', 'postUrl'],
		defaults: (_origin) => ({
			username: '测试用户',
			postTitle: '示例帖子标题',
			postUrl: 'https://2x.nz/forum/post/?id=1'
		}),
build: (payload) => ({
			subject: `您的帖子已被管理员删除：${payload.postTitle}`,
			html: `
					<h1>帖子已删除</h1>
					<p>${escapeHtml(payload.username)}，您好。</p>
					<p>您发布的帖子"<strong>${escapeHtml(payload.postTitle)}</strong>"已被管理员删除。</p>
					<p>如需了解详情，请联系管理员。</p>
					<p><a href="${payload.postUrl}">帖子原链接</a></p>
					${EMAIL_REPLY_HINT}
				`
		})
	},
	{
		key: 'post_new_comment',
		label: '帖子新评论提醒',
		requiredFields: ['commenterName', 'postTitle', 'commentContent', 'postUrl'],
		defaults: (_origin) => ({
			commenterName: '测试评论者',
			postTitle: '示例帖子标题',
			commentContent: '这是一条用于测试的新评论内容。',
			postUrl: 'https://2x.nz/forum/post/?id=1'
		}),
build: (payload) => ({
			subject: `您的帖子有新评论：${payload.postTitle}`,
			html: `
					<h1>您的帖子有新评论</h1>
					<p><strong>${escapeHtml(payload.commenterName)}</strong> 评论了您的帖子"<strong>${escapeHtml(payload.postTitle)}</strong>"：</p>
					<blockquote>${escapeHtml(payload.commentContent)}</blockquote>
					<p><a href="${payload.postUrl}">查看评论</a></p>
					<p style="font-size:0.8em;color:#666;">您收到这封邮件，是因为您已开启帖子相关邮件提醒。</p>
					${EMAIL_REPLY_HINT}
				`
		})
	},
{
		key: 'comment_new_reply',
		label: '评论新回复提醒',
		requiredFields: ['commenterName', 'postTitle', 'replyContent', 'postUrl'],
		defaults: (_origin) => ({
			commenterName: '测试评论者',
			postTitle: '示例帖子标题',
			replyContent: '这是一条用于测试的新回复内容。',
			postUrl: 'https://2x.nz/forum/post/?id=1'
		}),
		build: (payload) => ({
			subject: '您的评论有新回复',
			html: `
					<h1>您的评论有新回复</h1>
					<p><strong>${escapeHtml(payload.commenterName)}</strong> 回复了您在"<strong>${escapeHtml(payload.postTitle)}</strong>"下的评论：</p>
					<blockquote>${escapeHtml(payload.replyContent)}</blockquote>
					<p><a href="${payload.postUrl}">查看回复</a></p>
					<p style="font-size:0.8em;color:#666;">您收到这封邮件，是因为您已开启帖子相关邮件提醒。</p>
					${EMAIL_REPLY_HINT}
				`
		})
	},
	{
		key: 'article_update',
		label: '文章更新通知',
		requiredFields: ['summary', 'articleLinks'],
		defaults: (_origin) => ({
			summary: '文章更新摘要',
			articleLinks: 'https://example.com/article'
		}),
		build: (payload) => ({
			subject: `文章更新：${payload.summary}`,
			html: `
					<h1>文章更新通知</h1>
					<p><strong>摘要：</strong>${escapeHtml(payload.summary)}</p>
					<p><strong>链接：</strong></p>
					<p>${payload.articleLinks}</p>
					<p style="font-size:0.8em;color:#666;">您收到这封邮件，是因为您已开启文章更新邮件提醒。如需更改您的首选项，请前往 <a href="https://2x.nz/forum/me/">https://2x.nz/forum/me/</a></p>
					${EMAIL_REPLY_HINT}
				`
		})
	}
];

const EMAIL_TEMPLATE_MAP = Object.fromEntries(EMAIL_TEMPLATE_DEFINITIONS.map((template) => [template.key, template])) as Record<string, EmailTemplateDefinition>;

function buildEmailTemplate(templateKey: string, origin: string, payload: EmailTemplatePayload = {}) {
	const template = EMAIL_TEMPLATE_MAP[templateKey];
	if (!template) {
		throw new Error('无效的邮件模板');
	}
	const mergedPayload = { ...template.defaults(origin), ...payload };
	for (const field of template.requiredFields) {
		if (!mergedPayload[field]) {
			throw new Error(`模板 ${template.label} 缺少必填字段：${field}`);
		}
	}
	return {
		template,
		payload: mergedPayload,
		message: template.build(mergedPayload)
	};
}

async function verifyTurnstile(token: string, ip: string, secretKey: string): Promise<boolean> {
	try {
		const formData = new FormData();
		formData.append('secret', secretKey);
		formData.append('response', token);
		formData.append('remoteip', ip);

		const url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
		const result = await fetch(url, {
			body: formData,
			method: 'POST',
		});

		const outcome = await result.json() as any;
		return outcome.success === true;
	} catch {
		return false;
	}
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL(request.url);
		const method = request.method;

		// CORS headers helper
		const corsHeaders = {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS, DELETE, PUT',
			'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Timestamp, X-Nonce',
		};

		// Handle OPTIONS (CORS preflight)
		if (method === 'OPTIONS') {
			return new Response(null, {
				headers: corsHeaders,
			});
		}

		// SSE endpoint - using Durable Object with Hibernation WebSocket
		if (url.pathname === '/api/sse') {
			const postId = url.searchParams.get('postId') || undefined;
			const { handleSSEConnection } = await import('./sse-hub');
			return handleSSEConnection(request, env, postId);
		}

		// SSE status endpoint (for debugging)
		if (url.pathname === '/api/sse/status' && method === 'GET') {
			const postId = url.searchParams.get('postId') || 'global';
			const id = env.WS_MANAGER.idFromName(postId);
			const stub = env.WS_MANAGER.get(id);
			const resp = await stub.fetch(new Request('http://internal/status'));
			const data = await resp.json();
			return Response.json(data, { headers: corsHeaders });
		}

		let security: Security;
		try {
			security = new Security(env);
		} catch {
			return Response.json(
				{ error: 'Server misconfigured' },
				{ status: 500, headers: corsHeaders }
			);
		}

		// Helper to return responses with CORS
		const jsonResponse = (data: any, status = 200) => {
			return Response.json(data, {
				status,
				headers: corsHeaders,
			});
		};
		const textResponse = (body: string, status = 200) => {
			return new Response(body, {
				status,
				headers: corsHeaders,
			});
		};
		const redirectResponse = (location: string, status = 302) => {
			return new Response(null, {
				status,
				headers: {
					...corsHeaders,
					Location: location,
				},
			});
		};

		const DEFAULT_SESSION_TTL_DAYS = 7;
		const DEFAULT_HOME_INTRO_MARKDOWN =
			'开源：[https://github.com/afoim/forum_for_cloudflare](https://github.com/afoim/forum_for_cloudflare) 基于 shadcn/ui + Tailwind 的多页应用（非 SPA），由 Cloudflare Workers 在边缘统一提供静态页面与 API。感谢 [https://www.cloudflare.com](https://www.cloudflare.com) 提供的 CDN 与 DDoS 防护服务';
		const DEFAULT_SITE_FOOTER_MARKDOWN = '';
		const SESSION_TTL_SETTING_KEY = 'session_ttl_days';
		const HOME_INTRO_MARKDOWN_SETTING_KEY = 'home_intro_markdown';
		const SITE_FOOTER_MARKDOWN_SETTING_KEY = 'site_footer_markdown';
		const MAX_SESSION_TTL_DAYS = 365;
		const MAX_MARKDOWN_SETTING_LENGTH = 5000;
		const DRAW_COOLDOWN_SETTING_KEY = 'draw_cooldown_seconds';
		const DEFAULT_DRAW_COOLDOWN_SECONDS = 0;
		const BOOLEAN_SETTING_KEYS = new Set([
			'turnstile_enabled',
			'notify_on_user_delete',
			'notify_on_post_delete',
			'notify_on_username_change',
			'notify_on_avatar_change',
			'notify_on_manual_verify'
		]);
		const normalizeSessionTtlDays = (value: unknown): number => {
			const parsed = Number.parseInt(String(value ?? ''), 10);
			if (!Number.isInteger(parsed) || parsed <= 0) return DEFAULT_SESSION_TTL_DAYS;
			return parsed;
		};
		const getSessionTtlDays = async (): Promise<number> => {
			const setting = await env.forum_db.prepare('SELECT value FROM settings WHERE key = ?').bind(SESSION_TTL_SETTING_KEY).first();
			return normalizeSessionTtlDays(setting?.value);
		};
		const normalizeMarkdownSetting = (value: unknown, fallback = ''): string => {
			const next = typeof value === 'string' ? value : String(value ?? '');
			if (!next) return fallback;
			return next.slice(0, MAX_MARKDOWN_SETTING_LENGTH);
		};
		const normalizeDrawCooldownSeconds = (value: unknown): number => {
			const parsed = Number.parseInt(String(value ?? ''), 10);
			if (!Number.isInteger(parsed) || parsed < 0) return DEFAULT_DRAW_COOLDOWN_SECONDS;
			return parsed;
		};
		const getDrawCooldownSeconds = async (): Promise<number> => {
			const setting = await env.forum_db.prepare('SELECT value FROM settings WHERE key = ?').bind(DRAW_COOLDOWN_SETTING_KEY).first();
			return normalizeDrawCooldownSeconds(setting?.value);
		};
		const getSiteConfig = async (): Promise<{
			homeIntroMarkdown: string;
			siteFooterMarkdown: string;
		}> => {
			const settings = await env.forum_db
				.prepare(`SELECT key, value FROM settings WHERE key IN (?, ?)`)
				.bind(HOME_INTRO_MARKDOWN_SETTING_KEY, SITE_FOOTER_MARKDOWN_SETTING_KEY)
				.all<{ key: string; value: string | null }>();
			let homeIntroMarkdown = DEFAULT_HOME_INTRO_MARKDOWN;
			let siteFooterMarkdown = DEFAULT_SITE_FOOTER_MARKDOWN;
			for (const row of settings.results ?? []) {
				if (row.key === HOME_INTRO_MARKDOWN_SETTING_KEY) homeIntroMarkdown = normalizeMarkdownSetting(row.value, DEFAULT_HOME_INTRO_MARKDOWN);
				if (row.key === SITE_FOOTER_MARKDOWN_SETTING_KEY) siteFooterMarkdown = normalizeMarkdownSetting(row.value, DEFAULT_SITE_FOOTER_MARKDOWN);
			}
			return { homeIntroMarkdown, siteFooterMarkdown };
		};
		const getPageTitle = (pathname: string, siteName: string): string => {
			const pageTitle =
				pathname === '/' ? '首页' :
				pathname === '/login' ? '登录' :
				pathname === '/register' ? '注册' :
				pathname === '/forgot' ? '忘记密码' :
				pathname === '/reset' ? '重置密码' :
				pathname === '/settings' ? '设置' :
				pathname === '/admin' ? '管理后台' :
				pathname === '/post' ? '帖子详情' :
				'';
			return pageTitle ? `${pageTitle} - ${siteName}` : siteName;
		};
		const sendEmailByTemplate = async (to: string, templateKey: string, payload: EmailTemplatePayload = {}) => {
			const domain = to.split('@')[1];
			if (!domain) throw new Error('Invalid email address');

			const hasMX = await checkMXRecord(domain);
			if (!hasMX) {
				throw new Error(`No MX record found for domain: ${domain}`);
			}

			const { message } = buildEmailTemplate(templateKey, url.origin, payload);
			await sendEmail(to, message.subject, message.html, env);
		};

		const checkMXRecord = async (domain: string): Promise<boolean> => {
			try {
				const dohUrl = `https://cloudflare-dns.com/dns-query?type=MX&name=${encodeURIComponent(domain)}`;
				const response = await fetch(dohUrl, {
					headers: { 'accept': 'application/dns-json' }
				});
				if (!response.ok) return false;
				const data = await response.json() as any;
				return Array.isArray(data.Answer) && data.Answer.some((r: any) => r.type === 15);
			} catch {
				return false;
			}
		};

		// Helper to handle errors
		const handleError = (e: any) => {
			const errString = String(e);
			if (errString.includes('Unauthorized') || errString.includes('Invalid Token')) {
				return jsonResponse({ error: 'Unauthorized' }, 401);
			}
			return jsonResponse({ error: errString }, 500);
		};


        // --- AUTH MIDDLEWARE HELPER ---
        const authenticate = async (req: Request): Promise<UserPayload> => {
            const authHeader = req.headers.get('Authorization');
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                throw new Error('Unauthorized');
            }
            const token = authHeader.split(' ')[1];
            const payload = await security.verifyToken(token);
            if (!payload) throw new Error('Invalid Token');
            // Update last_seen_at (non-blocking, fire-and-forget)
            ctx.waitUntil(
                env.forum_db.prepare('UPDATE users SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ?')
                    .bind(payload.id).run().catch(() => {})
            );
            return payload;
        };

// --- SECURITY CHECK (Replay + Headers) ---
		// Skip for public GET, Login, Register, Verify, Forgot/Reset Password, Config
		const publicPaths = [
			'/api/config', '/api/login', '/api/register', '/api/verify',
			'/api/auth/forgot-password', '/api/auth/reset-password', '/api/verify-email-change',
			'/api/auth/github/start', '/api/auth/github/callback',
			 // Static/Public GETs
			'/api/posts', '/api/categories', '/api/users',
			 // Webhook endpoints (validated by secret)
			'/api/webhook/posts'
		];
		
		// Relax check for public GETs that don't need nonce
		const isPublicGet = method === 'GET' && (
			publicPaths.includes(url.pathname) || 
			url.pathname.match(/^\/api\/posts\/\d+$/) || 
			url.pathname.match(/^\/api\/posts\/\d+\/comments$/)
		);

		// However, user specifically asked for "Replay protection for sensitive operations".
		// We will apply strict checks for mutation methods (POST, PUT, DELETE)
		// Skip for webhook endpoints (they have their own secret validation)
		if (['POST', 'PUT', 'DELETE'].includes(method) && url.pathname !== '/api/webhook/posts') {
			 const validation = await security.validateRequest(request);
             if (!validation.valid) {
                 return jsonResponse({ error: validation.error || 'Security check failed' }, 400);
             }
        }

		// GET /api/config
		if (url.pathname === '/api/config' && method === 'GET') {
			try {
				const [setting, userCount, siteConfig] = await Promise.all([
					env.forum_db.prepare("SELECT value FROM settings WHERE key = 'turnstile_enabled'").first(),
					env.forum_db.prepare('SELECT COUNT(*) as count FROM users').first('count'),
					getSiteConfig()
				]);

				return jsonResponse({
					turnstile_enabled: setting ? setting.value === '1' : false,
					turnstile_site_key: env.TURNSTILE_SITE_KEY || '',
					home_intro_markdown: siteConfig.homeIntroMarkdown,
					site_footer_markdown: siteConfig.siteFooterMarkdown,
					user_count: userCount || 0
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/admin/settings
		if (url.pathname === '/api/admin/settings' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const [settings, sessionTtlDays] = await Promise.all([
					env.forum_db.prepare("SELECT key, value FROM settings").all<{ key: string; value: string | null }>(),
					getSessionTtlDays()
				]);
				const config: Record<string, unknown> = {
					turnstile_enabled: false,
					notify_on_user_delete: false,
					notify_on_post_delete: false,
					notify_on_username_change: false,
					notify_on_avatar_change: false,
					notify_on_manual_verify: false,
					session_ttl_days: sessionTtlDays,
					draw_cooldown_seconds: DEFAULT_DRAW_COOLDOWN_SECONDS,
					home_intro_markdown: DEFAULT_HOME_INTRO_MARKDOWN,
					site_footer_markdown: DEFAULT_SITE_FOOTER_MARKDOWN
				};

				if (settings.results) {
					for (const row of settings.results) {
						if (row.key === SESSION_TTL_SETTING_KEY) continue;
						if (row.key === DRAW_COOLDOWN_SETTING_KEY) {
							config.draw_cooldown_seconds = normalizeDrawCooldownSeconds(row.value);
							continue;
						}
						if (row.key === HOME_INTRO_MARKDOWN_SETTING_KEY) {
							config.home_intro_markdown = normalizeMarkdownSetting(row.value, DEFAULT_HOME_INTRO_MARKDOWN);
							continue;
 					}
						if (row.key === SITE_FOOTER_MARKDOWN_SETTING_KEY) {
							config.site_footer_markdown = normalizeMarkdownSetting(row.value, DEFAULT_SITE_FOOTER_MARKDOWN);
							continue;
 					}
						if (BOOLEAN_SETTING_KEYS.has(row.key)) {
							config[row.key] = row.value === '1';
 					}
					}
				}

				return jsonResponse(config);
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/settings
		if (url.pathname === '/api/admin/settings' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const body = await request.json() as any;
				const {
					turnstile_enabled,
					notify_on_user_delete,
					notify_on_post_delete,
					notify_on_username_change,
					notify_on_avatar_change,
					notify_on_manual_verify,
					session_ttl_days,
					draw_cooldown_seconds,
					home_intro_markdown,
					site_footer_markdown
				} = body;

				const stmt = env.forum_db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)");
				const batch = [];

				if (turnstile_enabled !== undefined) batch.push(stmt.bind('turnstile_enabled', turnstile_enabled ? '1' : '0'));
				if (notify_on_user_delete !== undefined) batch.push(stmt.bind('notify_on_user_delete', notify_on_user_delete ? '1' : '0'));
				if (notify_on_post_delete !== undefined) batch.push(stmt.bind('notify_on_post_delete', notify_on_post_delete ? '1' : '0'));
				if (notify_on_username_change !== undefined) batch.push(stmt.bind('notify_on_username_change', notify_on_username_change ? '1' : '0'));
				if (notify_on_avatar_change !== undefined) batch.push(stmt.bind('notify_on_avatar_change', notify_on_avatar_change ? '1' : '0'));
				if (notify_on_manual_verify !== undefined) batch.push(stmt.bind('notify_on_manual_verify', notify_on_manual_verify ? '1' : '0'));
				if (session_ttl_days !== undefined) {
					const parsedSessionTtlDays = Number.parseInt(String(session_ttl_days), 10);
					if (!Number.isInteger(parsedSessionTtlDays) || parsedSessionTtlDays < 1 || parsedSessionTtlDays > MAX_SESSION_TTL_DAYS) {
						return jsonResponse({ error: `登录态有效天数必须是 1 到 ${MAX_SESSION_TTL_DAYS} 的整数` }, 400);
					}
					batch.push(stmt.bind(SESSION_TTL_SETTING_KEY, String(parsedSessionTtlDays)));
				}
				if (draw_cooldown_seconds !== undefined) {
					const parsed = Number.parseInt(String(draw_cooldown_seconds), 10);
					if (!Number.isInteger(parsed) || parsed < 0 || parsed > 3600) {
						return jsonResponse({ error: '生图冷却秒数必须是 0 到 3600 的整数' }, 400);
					}
					batch.push(stmt.bind(DRAW_COOLDOWN_SETTING_KEY, String(parsed)));
				}
				if (home_intro_markdown !== undefined) {
					const normalizedHomeIntroMarkdown = typeof home_intro_markdown === 'string' ? home_intro_markdown : String(home_intro_markdown ?? '');
					if (normalizedHomeIntroMarkdown.length > MAX_MARKDOWN_SETTING_LENGTH) {
						return jsonResponse({ error: `首页说明不能超过 ${MAX_MARKDOWN_SETTING_LENGTH} 个字符` }, 400);
					}
					batch.push(stmt.bind(HOME_INTRO_MARKDOWN_SETTING_KEY, normalizedHomeIntroMarkdown));
				}
				if (site_footer_markdown !== undefined) {
					const normalizedSiteFooterMarkdown = typeof site_footer_markdown === 'string' ? site_footer_markdown : String(site_footer_markdown ?? '');
					if (normalizedSiteFooterMarkdown.length > MAX_MARKDOWN_SETTING_LENGTH) {
						return jsonResponse({ error: `页脚内容不能超过 ${MAX_MARKDOWN_SETTING_LENGTH} 个字符` }, 400);
					}
					batch.push(stmt.bind(SITE_FOOTER_MARKDOWN_SETTING_KEY, normalizedSiteFooterMarkdown));
				}

				if (batch.length > 0) await env.forum_db.batch(batch);

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}
		
		// GET /api/session
		if (url.pathname === '/api/session' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				return jsonResponse({
					valid: true,
					user: {
						id: userPayload.id,
						email: userPayload.email,
						role: userPayload.role
					}
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/user/me
		if (url.pathname === '/api/user/me' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				const user = await env.forum_db.prepare(
					`SELECT
						users.*,
						user_profiles.gender,
						user_profiles.bio,
						user_profiles.age,
						user_profiles.region
					 FROM users
					 LEFT JOIN user_profiles ON user_profiles.user_id = users.id
					 WHERE users.id = ?`
				).bind(userPayload.id).first();
				if (!user) return jsonResponse({ error: 'User not found' }, 404);
				return jsonResponse({
					id: user.id,
					email: user.email,
					username: user.username,
					avatar_url: rewriteAvatarValueToPublicUrl(user.avatar_url, env as unknown as S3Env),
					role: user.role || 'user',
					totp_enabled: !!user.totp_enabled,
					email_notifications: user.email_notifications === 1,
					article_notifications: user.article_notifications === 1,
					gender: user.gender ?? null,
					bio: user.bio ?? null,
					age: user.age ?? null,
					region: user.region ?? null,
					last_seen_at: user.last_seen_at ?? null,
					github_id: user.github_id ? Number(user.github_id) : null,
					github_login: user.github_login ?? null,
					github_avatar_url: user.github_avatar_url ?? null,
					has_password: !!(user.password && String(user.password).length > 0)
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/user/me/posts
		if (url.pathname === '/api/user/me/posts' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				const limit = parseInt(url.searchParams.get('limit') || '20');
				const offset = parseInt(url.searchParams.get('offset') || '0');
				const sortByRaw = (url.searchParams.get('sort_by') || 'time').trim().toLowerCase();
				const sortDirRaw = (url.searchParams.get('sort_dir') || 'desc').trim().toLowerCase();
				const sortDir = sortDirRaw === 'asc' ? 'ASC' : 'DESC';

				let query = `SELECT
						posts.*,
						users.username as author_name,
						users.avatar_url as author_avatar,
						users.role as author_role,
						categories.name as category_name,
						(SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) as like_count,
						(SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) as comment_count
					 FROM posts
					 JOIN users ON posts.author_id = users.id
					 LEFT JOIN categories ON posts.category_id = categories.id
					 WHERE posts.author_id = ?`;
				const countQuery = 'SELECT COUNT(*) as total FROM posts WHERE author_id = ?';
				const params: any[] = [userPayload.id];

				const sortExpr =
					sortByRaw === 'likes'
						? `like_count ${sortDir}`
						: sortByRaw === 'comments'
							? `comment_count ${sortDir}`
							: sortByRaw === 'views'
								? `posts.view_count ${sortDir}`
								: `posts.created_at ${sortDir}`;

				query += ` ORDER BY posts.is_pinned DESC, ${sortExpr}, posts.created_at DESC LIMIT ? OFFSET ?`;
				params.push(limit, offset);

				const [postsResult, countResult] = await Promise.all([
					env.forum_db.prepare(query).bind(...params).all(),
					env.forum_db.prepare(countQuery).bind(userPayload.id).first()
				]);

				return jsonResponse({
					posts: postsResult.results.map((post: any) => rewritePostForResponse(post, env as unknown as S3Env)),
					total: countResult ? countResult.total : 0
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/user/avatar
		if (url.pathname === '/api/user/avatar' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				const user = await env.forum_db.prepare('SELECT avatar_url FROM users WHERE id = ?').bind(userPayload.id).first();
				if (!user) return jsonResponse({ error: 'User not found' }, 404);
				return jsonResponse({ avatar_url: rewriteAvatarValueToPublicUrl(user.avatar_url, env as unknown as S3Env) });
			} catch (e) {
				return handleError(e);
			}
		}

		// Helper to check Turnstile if enabled
		const checkTurnstile = async (reqBody: any, ip: string) => {
			const setting = await env.forum_db.prepare("SELECT value FROM settings WHERE key = 'turnstile_enabled'").first();
			if (setting && setting.value === '1') {
				if (!env.TURNSTILE_SECRET_KEY) return false;
				const token = reqBody['cf-turnstile-response'];
				if (typeof token !== 'string' || !token) return false;
				return await verifyTurnstile(token, ip, env.TURNSTILE_SECRET_KEY);
			}
			return true;
		};

		// POST /api/upload (Image Upload)
		if (url.pathname === '/api/upload' && method === 'POST') {
			try {
				const user = await authenticate(request);
				
				const formData = await request.formData();
				const file = formData.get('file');
				const userId = user.id.toString(); // Use verified user ID
				const postId = formData.get('post_id') || 'general';
				const type = formData.get('type') || 'post';

				if (!file || !(file instanceof File)) {
					return jsonResponse({ error: 'No file uploaded' }, 400);
				}

				if (!file.type.startsWith('image/')) {
					return jsonResponse({ error: 'Only images are allowed' }, 400);
				}

				// Check file size (500KB = 500 * 1024 bytes)
				const MAX_SIZE = 500 * 1024;
				if (file.size > MAX_SIZE) {
					return jsonResponse({ error: 'File size too large (Max 500KB)' }, 400);
				}

				const imageKey = await uploadImage(env as unknown as S3Env, file, userId, postId.toString(), type as 'post' | 'avatar' | 'comment');
				const imageUrl = getPublicUrl(env as unknown as S3Env, imageKey);
				await security.logAudit(user.id, 'UPLOAD_IMAGE', 'image', imageKey, { type, postId }, request);

				return jsonResponse({ success: true, key: imageKey, url: imageUrl });
			} catch (e) {
				console.error('Upload error:', e);
				return handleError(e); // 401/403 will be caught here if auth fails
			}
		}

		// --- AUTH ROUTES ---

		// --- GitHub OAuth ---
		const FRONTEND_BASE = 'https://2x.nz/forum';
		const GITHUB_DEFAULT_REDIRECT = `${FRONTEND_BASE}/auth/login/`;
		const GITHUB_OAUTH_STATE_TTL = 600; // seconds

		const getGithubSecretKey = (): Uint8Array | null => {
			const secret = String(env.JWT_SECRET || '');
			if (secret.length < 32) return null;
			return new TextEncoder().encode(secret);
		};

		const getGithubCallbackUrl = (): string => `${url.origin}/api/auth/github/callback`;

		const sanitizeRedirect = (raw: string | null | undefined): string => {
			if (!raw) return GITHUB_DEFAULT_REDIRECT;
			try {
				const parsed = new URL(raw);
				if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return GITHUB_DEFAULT_REDIRECT;
				const allowedHosts = new Set(['2x.nz', 'www.2x.nz', 'i.2x.nz', 'localhost', '127.0.0.1']);
				if (!allowedHosts.has(parsed.hostname)) return GITHUB_DEFAULT_REDIRECT;
				return parsed.toString();
			} catch {
				return GITHUB_DEFAULT_REDIRECT;
			}
		};

		const appendQueryToRedirect = (redirect: string, params: Record<string, string>): string => {
			try {
				const target = new URL(redirect);
				for (const [k, v] of Object.entries(params)) target.searchParams.set(k, v);
				return target.toString();
			} catch {
				const sep = redirect.includes('?') ? '&' : '?';
				const qs = new URLSearchParams(params).toString();
				return `${redirect}${sep}${qs}`;
			}
		};

		const signGithubState = async (payload: { mode: 'login' | 'link'; redirect: string; userId?: number }): Promise<string | null> => {
			const key = getGithubSecretKey();
			if (!key) return null;
			return await new SignJWT(payload)
				.setProtectedHeader({ alg: 'HS256' })
				.setIssuedAt()
				.setExpirationTime(Math.floor(Date.now() / 1000) + GITHUB_OAUTH_STATE_TTL)
				.sign(key);
		};

		const verifyGithubState = async (token: string): Promise<{ mode: 'login' | 'link'; redirect: string; userId?: number } | null> => {
			const key = getGithubSecretKey();
			if (!key) return null;
			try {
				const { payload } = await jwtVerify(token, key);
				const mode = (payload as any).mode;
				const redirect = (payload as any).redirect;
				if (mode !== 'login' && mode !== 'link') return null;
				if (typeof redirect !== 'string' || !redirect) return null;
				return { mode, redirect, userId: typeof (payload as any).userId === 'number' ? (payload as any).userId : undefined };
			} catch {
				return null;
			}
		};

		// GET /api/auth/github/start?mode=login|link&redirect=<url>
		// 对 link 模式需在 Authorization: Bearer 头携带当前用户 token。
		// 返回 { authorize_url, state }。前端 window.location = authorize_url 即可。
		if (url.pathname === '/api/auth/github/start' && method === 'GET') {
			try {
				if (!env.GITHUB_CLIENT_ID) return jsonResponse({ error: 'GitHub OAuth 未配置' }, 500);
				const mode = (url.searchParams.get('mode') || 'login') === 'link' ? 'link' : 'login';
				const redirect = sanitizeRedirect(url.searchParams.get('redirect'));

				let userId: number | undefined;
				if (mode === 'link') {
					const userPayload = await authenticate(request);
					userId = userPayload.id;
				}

				const state = await signGithubState({ mode, redirect, userId });
				if (!state) return jsonResponse({ error: '服务端密钥未配置' }, 500);

				const authorizeUrl = new URL('https://github.com/login/oauth/authorize');
				authorizeUrl.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
				authorizeUrl.searchParams.set('redirect_uri', getGithubCallbackUrl());
				authorizeUrl.searchParams.set('scope', 'read:user user:email');
				authorizeUrl.searchParams.set('state', state);
				authorizeUrl.searchParams.set('allow_signup', 'true');

				return jsonResponse({ authorize_url: authorizeUrl.toString(), state });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/auth/github/callback?code&state
		// GitHub 回调：交换 token、拉取用户信息、按 mode 进行登录或绑定，最后 302 回前端 redirect。
		if (url.pathname === '/api/auth/github/callback' && method === 'GET') {
			const code = url.searchParams.get('code');
			const stateRaw = url.searchParams.get('state');
			const errParam = url.searchParams.get('error');

			const failRedirect = (target: string, msg: string) =>
				redirectResponse(appendQueryToRedirect(target, { github_error: msg }));

			if (errParam) {
				return failRedirect(GITHUB_DEFAULT_REDIRECT, errParam);
			}
			if (!code || !stateRaw) {
				return failRedirect(GITHUB_DEFAULT_REDIRECT, 'missing_code_or_state');
			}

			const state = await verifyGithubState(stateRaw);
			if (!state) {
				return failRedirect(GITHUB_DEFAULT_REDIRECT, 'invalid_state');
			}

			if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
				return failRedirect(state.redirect, 'oauth_not_configured');
			}

			try {
				// 1. Exchange code for access token
				const callbackUrl = getGithubCallbackUrl();
				console.log('[GitHub OAuth] exchanging code, redirect_uri =', callbackUrl, ', client_id =', env.GITHUB_CLIENT_ID);
				const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
					method: 'POST',
					headers: {
						'Accept': 'application/json',
						'Content-Type': 'application/json',
						'User-Agent': 'AcoFork-Forum-Worker'
					},
					body: JSON.stringify({
						client_id: env.GITHUB_CLIENT_ID,
						client_secret: env.GITHUB_CLIENT_SECRET,
						code,
						redirect_uri: callbackUrl,
					})
				});
				const tokenText = await tokenRes.text();
				console.log('[GitHub OAuth] token endpoint status =', tokenRes.status, ', body =', tokenText);
				if (!tokenRes.ok) return failRedirect(state.redirect, `token_http_${tokenRes.status}`);
				let tokenJson: { access_token?: string; error?: string; error_description?: string };
				try {
					tokenJson = JSON.parse(tokenText);
				} catch {
					return failRedirect(state.redirect, 'token_response_not_json');
				}
				if (!tokenJson.access_token) {
					const reason = tokenJson.error_description || tokenJson.error || 'no_access_token';
					return failRedirect(state.redirect, encodeURIComponent(reason).slice(0, 200));
				}

				const accessToken = tokenJson.access_token;
				const ghHeaders = {
					'Authorization': `Bearer ${accessToken}`,
					'Accept': 'application/vnd.github+json',
					'User-Agent': 'AcoFork-Forum-Worker'
				};

				// 2. Fetch user profile
				const userRes = await fetch('https://api.github.com/user', { headers: ghHeaders });
				if (!userRes.ok) return failRedirect(state.redirect, 'fetch_user_failed');
				const ghUser = await userRes.json() as { id: number; login: string; avatar_url?: string; email?: string | null; name?: string | null };
				if (!ghUser.id || !ghUser.login) return failRedirect(state.redirect, 'invalid_github_user');

				// 3. Fetch primary verified email if profile email is null
				let primaryEmail = ghUser.email && ghUser.email.toLowerCase() !== 'null' ? ghUser.email : null;
				if (!primaryEmail) {
					const emailRes = await fetch('https://api.github.com/user/emails', { headers: ghHeaders });
					if (emailRes.ok) {
						const emails = await emailRes.json() as Array<{ email: string; primary: boolean; verified: boolean }>;
						const found = emails.find(e => e.primary && e.verified) || emails.find(e => e.verified);
						if (found) primaryEmail = found.email;
					}
				}

				const ghIdNum = Number(ghUser.id);

				if (state.mode === 'link') {
					if (!state.userId) return failRedirect(state.redirect, 'invalid_link_state');
					// 检查该 GitHub 账号是否已绑定其他用户
					const existing = await env.forum_db.prepare('SELECT id FROM users WHERE github_id = ?').bind(ghIdNum).first();
					if (existing && Number(existing.id) !== state.userId) {
						return failRedirect(state.redirect, 'github_already_linked_to_other');
					}
					await env.forum_db.prepare(
						'UPDATE users SET github_id = ?, github_login = ?, github_avatar_url = ? WHERE id = ?'
					).bind(ghIdNum, ghUser.login, ghUser.avatar_url || null, state.userId).run();
					await security.logAudit(state.userId, 'GITHUB_LINK', 'user', String(state.userId), { github_id: ghIdNum, github_login: ghUser.login }, request);
					return redirectResponse(appendQueryToRedirect(state.redirect, { github_linked: '1' }));
				}

				// === LOGIN mode ===
				// 1) by github_id
				let userRow: any = await env.forum_db.prepare('SELECT * FROM users WHERE github_id = ?').bind(ghIdNum).first();
				let isNewUser = false;

				// 2) fallback: by verified email (auto-link existing email account)
				if (!userRow && primaryEmail) {
					userRow = await env.forum_db.prepare('SELECT * FROM users WHERE email = ?').bind(primaryEmail).first();
					if (userRow) {
						await env.forum_db.prepare(
							'UPDATE users SET github_id = ?, github_login = ?, github_avatar_url = ? WHERE id = ?'
						).bind(ghIdNum, ghUser.login, ghUser.avatar_url || null, userRow.id).run();
					}
				}

				// 3) create new account
				if (!userRow) {
					if (!primaryEmail) return failRedirect(state.redirect, 'github_email_unavailable');

					// username 唯一化（用 github login，冲突追加随机后缀）
					let candidate = ghUser.login.slice(0, 20);
					if (!candidate) candidate = `gh_${ghIdNum}`;
					const existsName = await env.forum_db.prepare('SELECT id FROM users WHERE username = ?').bind(candidate).first();
					if (existsName) {
						candidate = (candidate.slice(0, 14) + '_' + Math.random().toString(36).slice(2, 6)).slice(0, 20);
					}

					// 邮箱冲突再次保护
					const existsEmail = await env.forum_db.prepare('SELECT id FROM users WHERE email = ?').bind(primaryEmail).first();
					if (existsEmail) {
						return failRedirect(state.redirect, 'email_conflict');
					}

					const placeholderPassword = ''; // 通过 GitHub 注册的账号，password 留空，禁止密码登录直到用户设置密码
					const insertRes = await env.forum_db.prepare(
						'INSERT INTO users (email, username, password, role, verified, github_id, github_login, github_avatar_url, avatar_url) VALUES (?, ?, ?, "user", 1, ?, ?, ?, ?)'
					).bind(
						primaryEmail,
						candidate,
						placeholderPassword,
						ghIdNum,
						ghUser.login,
						ghUser.avatar_url || null,
						ghUser.avatar_url || null
					).run();
					const newId = insertRes.meta?.last_row_id;
					if (!newId) return failRedirect(state.redirect, 'create_user_failed');
					if (!ghUser.avatar_url) {
						const identicon = await generateIdenticon(String(newId));
						await env.forum_db.prepare('UPDATE users SET avatar_url = ? WHERE id = ?').bind(identicon, newId).run();
					}
					userRow = await env.forum_db.prepare('SELECT * FROM users WHERE id = ?').bind(newId).first();
					isNewUser = true;
				}

				if (!userRow) return failRedirect(state.redirect, 'login_failed');

				const sessionTtlDays = await getSessionTtlDays();
				const sessionTtlSeconds = sessionTtlDays * 24 * 60 * 60;
				const { token, jti, expiresAt } = await security.generateToken(
					{ id: Number(userRow.id), role: String(userRow.role || 'user'), email: String(userRow.email) },
					sessionTtlSeconds
				);
				await env.forum_db.prepare('INSERT INTO sessions (jti, user_id, expires_at) VALUES (?, ?, ?)').bind(jti, userRow.id, expiresAt).run();
				await security.logAudit(Number(userRow.id), isNewUser ? 'GITHUB_REGISTER_LOGIN' : 'GITHUB_LOGIN', 'user', String(userRow.id), { github_id: ghIdNum, github_login: ghUser.login }, request);

				// 通过 URL fragment 回传 token，避免落入 referer / 服务器日志
				const finalUrl = (() => {
					const base = state.redirect;
					const sep = base.includes('#') ? '&' : '#';
					const qs = new URLSearchParams({ token, new: isNewUser ? '1' : '0' }).toString();
					return `${base}${sep}${qs}`;
				})();
				return redirectResponse(finalUrl);
			} catch (e) {
				console.error('[GitHub OAuth] callback failed', e);
				return failRedirect(state?.redirect || GITHUB_DEFAULT_REDIRECT, 'internal_error');
			}
		}

		// POST /api/auth/github/unlink — 解绑 GitHub。要求账号本身有可登录密码，避免用户被锁出。
		if (url.pathname === '/api/auth/github/unlink' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const user = await env.forum_db.prepare('SELECT id, password, github_id FROM users WHERE id = ?').bind(userPayload.id).first();
				if (!user) return jsonResponse({ error: '用户不存在' }, 404);
				if (!user.github_id) return jsonResponse({ error: '当前账号未绑定 GitHub' }, 400);
				if (!user.password || String(user.password).length === 0) {
					return jsonResponse({ error: '请先设置登录密码后再解绑 GitHub，否则将无法登录' }, 400);
				}
				await env.forum_db.prepare('UPDATE users SET github_id = NULL, github_login = NULL, github_avatar_url = NULL WHERE id = ?').bind(userPayload.id).run();
				await security.logAudit(userPayload.id, 'GITHUB_UNLINK', 'user', String(userPayload.id), {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/login
		if (url.pathname === '/api/login' && method === 'POST') {
			try {
				const body = await request.json() as any;
				
				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				if (!(await checkTurnstile(body, ip))) {
					return jsonResponse({ error: 'Turnstile verification failed' }, 403);
				}

				const { email, password, totp_code } = body;
				if (!email || !password) {
					return jsonResponse({ error: 'Missing email or password' }, 400);
				}

				const user = await env.forum_db.prepare(
					'SELECT * FROM users WHERE email = ?'
				).bind(email).first();

				if (!user) {
					return jsonResponse({ error: 'Username or Password Error' }, 401);
				}

				if (!user.verified) {
					return jsonResponse({ error: 'Please verify your email first' }, 403);
				}

				const passwordHash = await hashPassword(password);
				if (user.password !== passwordHash) {
					return jsonResponse({ error: 'Username or Password Error' }, 401);
				}

				// TOTP Check
				if (user.totp_enabled) {
					if (!totp_code) {
						return jsonResponse({ error: 'TOTP_REQUIRED' }, 403);
					}

					const totp = new OTPAuth.TOTP({
						algorithm: 'SHA1',
						digits: 6,
						period: 30,
						secret: OTPAuth.Secret.fromBase32(user.totp_secret)
					});

					const delta = totp.validate({ token: totp_code, window: 1 });
					if (delta === null) {
						return jsonResponse({ error: 'Invalid TOTP code' }, 401);
					}
				}

				const sessionTtlDays = await getSessionTtlDays();
				const sessionTtlSeconds = sessionTtlDays * 24 * 60 * 60;
				const { token, jti, expiresAt } = await security.generateToken(
					{
						id: user.id,
						role: user.role || 'user',
						email: user.email
					},
					sessionTtlSeconds
				);

				await env.forum_db.prepare('INSERT INTO sessions (jti, user_id, expires_at) VALUES (?, ?, ?)').bind(jti, user.id, expiresAt).run();
				await security.logAudit(user.id, 'LOGIN', 'user', String(user.id), { email }, request);

				return jsonResponse({
					token,
					user: {
						id: user.id,
						email: user.email,
						username: user.username,
						avatar_url: rewriteAvatarValueToPublicUrl(user.avatar_url, env as unknown as S3Env),
						role: user.role || 'user',
						totp_enabled: !!user.totp_enabled,
						email_notifications: user.email_notifications === 1
					}
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/profile
		if (url.pathname === '/api/user/profile' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { username, avatar_url, email_notifications, article_notifications } = body;

				const user_id = userPayload.id;

				if (username) {
					if (username.length > 20) return jsonResponse({ error: 'Username too long (Max 20 chars)' }, 400);
					if (isVisuallyEmpty(username)) return jsonResponse({ error: 'Username cannot be empty' }, 400);
					if (hasInvisibleCharacters(username)) return jsonResponse({ error: 'Username contains invalid invisible characters' }, 400);
					if (hasControlCharacters(username)) return jsonResponse({ error: 'Username contains invalid control characters' }, 400);
					if (hasRestrictedKeywords(username) && userPayload.role !== 'admin') return jsonResponse({ error: 'Username contains restricted keywords' }, 400);

					// Check Uniqueness
					const existingUser = await env.forum_db.prepare('SELECT id FROM users WHERE username = ? AND id != ?').bind(username, user_id).first();
					if (existingUser) {
						return jsonResponse({ error: 'Username already taken' }, 409);
					}
				}

				// Fetch current user
				const currentUser = await env.forum_db.prepare('SELECT * FROM users WHERE id = ?').bind(user_id).first();
				if (!currentUser) return jsonResponse({ error: 'User not found' }, 404);

				let newUsername = currentUser.username;
				if (username !== undefined) {
					newUsername = username;
				}

				let newAvatarUrl = currentUser.avatar_url;
				if (avatar_url !== undefined) {
					if (avatar_url === '' || avatar_url === null) {
						// Generate Identicon
						newAvatarUrl = await generateIdenticon(String(user_id));
					} else {
						if (avatar_url.length > 5000) return jsonResponse({ error: 'Avatar URL too long (Max 5000 chars)' }, 400);
						if (!/^https?:\/\//i.test(avatar_url) && !avatar_url.startsWith('data:image/svg+xml') && !extractManagedImageKey(avatar_url, env as unknown as S3Env)) return jsonResponse({ error: 'Invalid Avatar URL (Must start with http:// or https://)' }, 400);
						newAvatarUrl = normalizeAvatarValueForStorage(avatar_url, env as unknown as S3Env);
					}
				}

				let newEmailNotif = currentUser.email_notifications;
				if (email_notifications !== undefined) {
					newEmailNotif = email_notifications ? 1 : 0;
				}

				let newArticleNotif = currentUser.article_notifications;
				if (article_notifications !== undefined) {
					newArticleNotif = article_notifications ? 1 : 0;
				}

				await env.forum_db.prepare('UPDATE users SET username = ?, avatar_url = ?, email_notifications = ?, article_notifications = ? WHERE id = ?')
					.bind(newUsername, newAvatarUrl, newEmailNotif, newArticleNotif, user_id).run();

				const user = await env.forum_db.prepare(
					`SELECT
						users.*,
						user_profiles.gender,
						user_profiles.bio,
						user_profiles.age,
						user_profiles.region
					 FROM users
					 LEFT JOIN user_profiles ON user_profiles.user_id = users.id
					 WHERE users.id = ?`
				).bind(user_id).first();

				await security.logAudit(userPayload.id, 'UPDATE_PROFILE', 'user', String(user_id), { username: newUsername }, request);

				return jsonResponse({
					success: true,
					user: {
						id: user.id,
						email: user.email,
						username: user.username,
						avatar_url: rewriteAvatarValueToPublicUrl(user.avatar_url, env as unknown as S3Env),
						role: user.role || 'user',
						totp_enabled: !!user.totp_enabled,
						email_notifications: user.email_notifications === 1,
						article_notifications: user.article_notifications === 1,
						gender: user.gender ?? null,
						bio: user.bio ?? null,
						age: user.age ?? null,
						region: user.region ?? null
					}
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/me/profile
		if (url.pathname === '/api/user/me/profile' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const gender = normalizeProfileGender(body.gender);
				const bio = normalizeOptionalProfileText(body.bio, 500, 'Bio');
				const age = normalizeProfileAge(body.age);
				const region = normalizeOptionalProfileText(body.region, 100, 'Region');

				const user = await env.forum_db.prepare('SELECT id FROM users WHERE id = ?').bind(userPayload.id).first();
				if (!user) return jsonResponse({ error: 'User not found' }, 404);

				const existingProfile = await env.forum_db.prepare('SELECT user_id FROM user_profiles WHERE user_id = ?').bind(userPayload.id).first();
				if (existingProfile) {
					await env.forum_db.prepare(
						'UPDATE user_profiles SET gender = ?, bio = ?, age = ?, region = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?'
					).bind(gender, bio, age, region, userPayload.id).run();
				} else {
					await env.forum_db.prepare(
						'INSERT INTO user_profiles (user_id, gender, bio, age, region) VALUES (?, ?, ?, ?, ?)'
					).bind(userPayload.id, gender, bio, age, region).run();
				}

				const profile = await env.forum_db.prepare(
					'SELECT user_id, gender, bio, age, region, created_at, updated_at FROM user_profiles WHERE user_id = ?'
				).bind(userPayload.id).first();

				await security.logAudit(userPayload.id, 'UPDATE_USER_PROFILE_EXT', 'user', String(userPayload.id), {
					gender,
					bio,
					age,
					region
				}, request);

				return jsonResponse({
					success: true,
					profile: {
						user_id: profile?.user_id,
						gender: profile?.gender ?? null,
						bio: profile?.bio ?? null,
						age: profile?.age ?? null,
						region: profile?.region ?? null,
						created_at: profile?.created_at,
						updated_at: profile?.updated_at
					}
				});
			} catch (e) {
				if (e instanceof Error) {
					const validationErrors = [
						'Gender must be a string',
						'Gender too long (Max 20 chars)',
						'Gender contains invalid invisible characters',
						'Gender contains invalid control characters',
						'Invalid gender',
						'Bio must be a string',
						'Bio too long (Max 500 chars)',
						'Bio contains invalid invisible characters',
						'Bio contains invalid control characters',
						'Region must be a string',
						'Region too long (Max 100 chars)',
						'Region contains invalid invisible characters',
						'Region contains invalid control characters',
						'Age must be an integer',
						'Age must be between 1 and 150'
					];
					if (validationErrors.includes(e.message)) {
						return jsonResponse({ error: e.message }, 400);
					}
				}
				return handleError(e);
			}
		}

		// POST /api/user/delete
		if (url.pathname === '/api/user/delete' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { password, totp_code } = body;
				
				if (!password) return jsonResponse({ error: 'Missing credentials' }, 400);

				const user_id = userPayload.id;

				const user = await env.forum_db.prepare('SELECT * FROM users WHERE id = ?').bind(user_id).first();
				if (!user) return jsonResponse({ error: 'User not found' }, 404);

				// Verify Password (Double check for sensitive delete op)
				const passwordHash = await hashPassword(password);
				if (user.password !== passwordHash) {
					return jsonResponse({ error: 'Invalid password' }, 401);
				}

				// Verify TOTP if enabled
				if (user.totp_enabled) {
					if (!totp_code) return jsonResponse({ error: 'TOTP_REQUIRED' }, 403);
					const totp = new OTPAuth.TOTP({
						algorithm: 'SHA1',
						digits: 6,
						period: 30,
						secret: OTPAuth.Secret.fromBase32(user.totp_secret)
					});
					if (totp.validate({ token: totp_code, window: 1 }) === null) {
						return jsonResponse({ error: 'Invalid TOTP code' }, 401);
					}
				}

				// Delete User and Data
				
				// 1. Delete images (Avatar + Post images)
				const posts = await env.forum_db.prepare('SELECT content FROM posts WHERE author_id = ?').bind(user_id).all();
				const deletionPromises: Promise<any>[] = [];
				
				if (user.avatar_url) {
					deletionPromises.push(deleteImage(env as unknown as S3Env, user.avatar_url, user_id));
				}
				
				if (posts.results) {
					for (const post of posts.results) {
						const imageKeys = extractManagedImageKeysFromMarkdown(post.content as string, env as unknown as S3Env);
						imageKeys.forEach(key => deletionPromises.push(deleteImage(env as unknown as S3Env, key, user_id)));
					}
				}
				
				if (deletionPromises.length > 0) {
					 ctx.waitUntil(Promise.all(deletionPromises).catch(err => console.error('Failed to delete user images', err)));
				}

				// 2. Delete likes/comments ON user's posts (Cascade manually)
				await env.forum_db.prepare('DELETE FROM likes WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?)').bind(user_id).run();
				await env.forum_db.prepare('DELETE FROM comment_likes WHERE comment_id IN (SELECT id FROM comments WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?))').bind(user_id).run();
				await env.forum_db.prepare('DELETE FROM comments WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?)').bind(user_id).run();

				// 3. Detach child comments that reply to user's comments
				await env.forum_db.prepare('UPDATE comments SET parent_id = NULL WHERE parent_id IN (SELECT id FROM comments WHERE author_id = ?)').bind(user_id).run();

				// 4. Delete user's activity
				await env.forum_db.prepare('DELETE FROM likes WHERE user_id = ?').bind(user_id).run();
				await env.forum_db.prepare('DELETE FROM comment_likes WHERE user_id = ?').bind(user_id).run();
				await env.forum_db.prepare('DELETE FROM comment_likes WHERE comment_id IN (SELECT id FROM comments WHERE author_id = ?)').bind(user_id).run();
				await env.forum_db.prepare('DELETE FROM comments WHERE author_id = ?').bind(user_id).run();

				// 5. Delete sessions, posts and user
				await env.forum_db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user_id).run();
				await env.forum_db.prepare('DELETE FROM user_profiles WHERE user_id = ?').bind(user_id).run();
				await env.forum_db.prepare('DELETE FROM posts WHERE author_id = ?').bind(user_id).run();
				await env.forum_db.prepare('DELETE FROM users WHERE id = ?').bind(user_id).run();
				
				await security.logAudit(userPayload.id, 'DELETE_ACCOUNT', 'user', String(user_id), {}, request);

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/totp/setup
		if (url.pathname === '/api/user/totp/setup' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const user_id = userPayload.id; // Force use of authenticated ID
				
				const secret = new OTPAuth.Secret({ size: 20 });
				const secretBase32 = secret.base32;

				await env.forum_db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?').bind(secretBase32, user_id).run();

				const user = await env.forum_db.prepare('SELECT email FROM users WHERE id = ?').bind(user_id).first();
				
				await security.logAudit(userPayload.id, 'SETUP_TOTP', 'user', String(user_id), {}, request);

				const totp = new OTPAuth.TOTP({
					issuer: 'CloudflareForum',
					label: user.email,
					algorithm: 'SHA1',
					digits: 6,
					period: 30,
					secret: secret
				});

				return jsonResponse({ 
					secret: secretBase32,
					uri: totp.toString() 
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/totp/verify
		if (url.pathname === '/api/user/totp/verify' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { token } = body;
				const user_id = userPayload.id; // Force use of authenticated ID

				if (!token) return jsonResponse({ error: 'Missing parameters' }, 400);

				const user = await env.forum_db.prepare('SELECT totp_secret FROM users WHERE id = ?').bind(user_id).first();

				if (!user || !user.totp_secret) return jsonResponse({ error: 'TOTP not setup' }, 400);

				const totp = new OTPAuth.TOTP({
					algorithm: 'SHA1',
					digits: 6,
					period: 30,
					secret: OTPAuth.Secret.fromBase32(user.totp_secret)
				});

				const delta = totp.validate({ token: token, window: 1 });

				if (delta !== null) {
					await env.forum_db.prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?').bind(user_id).run();
					await security.logAudit(userPayload.id, 'ENABLE_TOTP', 'user', String(user_id), {}, request);
					return jsonResponse({ success: true });
				} else {
					return jsonResponse({ error: 'Invalid code' }, 400);
				}
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/totp/disable
		if (url.pathname === '/api/user/totp/disable' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { password, totp_code } = body;
				const user_id = userPayload.id;

				if (!password || !totp_code) return jsonResponse({ error: 'Missing parameters' }, 400);

				const user = await env.forum_db.prepare('SELECT * FROM users WHERE id = ?').bind(user_id).first();
				if (!user) return jsonResponse({ error: 'User not found' }, 404);
				if (!user.totp_enabled || !user.totp_secret) return jsonResponse({ error: 'TOTP not enabled' }, 400);

				const passwordHash = await hashPassword(password);
				if (user.password !== passwordHash) {
					return jsonResponse({ error: 'Invalid password' }, 401);
				}

				const totp = new OTPAuth.TOTP({
					algorithm: 'SHA1',
					digits: 6,
					period: 30,
					secret: OTPAuth.Secret.fromBase32(user.totp_secret)
				});
				if (totp.validate({ token: totp_code, window: 1 }) === null) {
					return jsonResponse({ error: 'Invalid TOTP code' }, 401);
				}

				await env.forum_db.prepare('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?').bind(user_id).run();
				await security.logAudit(userPayload.id, 'DISABLE_TOTP', 'user', String(user_id), { method: 'password+totp' }, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/user/totp/status
		if (url.pathname === '/api/user/totp/status' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				const user = await env.forum_db.prepare('SELECT totp_enabled FROM users WHERE id = ?').bind(userPayload.id).first();

				if (!user) return jsonResponse({ error: 'User not found' }, 404);

				return jsonResponse({
					totp_enabled: !!user.totp_enabled,
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/auth/forgot-password
		if (url.pathname === '/api/auth/forgot-password' && method === 'POST') {
			try {
				const body = await request.json() as any;

				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
					if (!(await checkTurnstile(body, ip))) {
						return jsonResponse({ error: 'Turnstile verification failed' }, 403);
					}

				const { email } = body;
				if (!email) return jsonResponse({ error: 'Missing email' }, 400);

				const user = await env.forum_db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
				if (!user) return jsonResponse({ success: true }); // Silent fail

				const token = generateToken();
				const expires = Date.now() + 3600000; // 1 hour

				await env.forum_db.prepare('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?')
					.bind(token, expires, user.id).run();

				const resetLink = `https://2x.nz/forum/auth/reset-password/?token=${encodeURIComponent(token)}`;

				ctx.waitUntil(sendEmailByTemplate(email, 'reset_password', { resetLink }).catch(console.error));
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /auth/reset-password
		if (url.pathname === '/api/auth/reset-password' && method === 'POST') {
			try {
				const body = await request.json() as any;

				// Turnstile Check
				// Explicitly check config first to ensure it is enforced if enabled
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				const turnstileEnabled = await env.forum_db.prepare("SELECT value FROM settings WHERE key = 'turnstile_enabled'").first();
				
				if (turnstileEnabled && turnstileEnabled.value === '1') {
					if (!env.TURNSTILE_SECRET_KEY) return jsonResponse({ error: 'Turnstile not configured' }, 500);
					const token = body['cf-turnstile-response'];
					if (!token) return jsonResponse({ error: 'Turnstile verification failed (No Token)' }, 403);
					const valid = await verifyTurnstile(token, ip, env.TURNSTILE_SECRET_KEY);
					if (!valid) return jsonResponse({ error: 'Turnstile verification failed (Invalid Token)' }, 403);
				}

				const { token, new_password, totp_code } = body;
				if (!token || !new_password) return jsonResponse({ error: 'Missing parameters' }, 400);

				if (new_password.length < 8 || new_password.length > 16) return jsonResponse({ error: 'Password must be 8-16 characters' }, 400);

				// Verify token
				const user = await env.forum_db.prepare('SELECT * FROM users WHERE reset_token = ?').bind(token).first();
				
				if (!user) return jsonResponse({ error: 'Invalid token' }, 400);
				if (Date.now() > user.reset_token_expires) return jsonResponse({ error: 'Token expired' }, 400);

				// If user has 2FA, require it
				if (user.totp_enabled) {
					if (!totp_code) return jsonResponse({ error: 'TOTP_REQUIRED' }, 403);
					
					const totp = new OTPAuth.TOTP({
						algorithm: 'SHA1',
						digits: 6,
						period: 30,
						secret: OTPAuth.Secret.fromBase32(user.totp_secret)
					});
					if (totp.validate({ token: totp_code, window: 1 }) === null) {
						return jsonResponse({ error: 'Invalid TOTP code' }, 401);
					}
				}

				const passwordHash = await hashPassword(new_password);
				await env.forum_db.prepare('UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?')
					.bind(passwordHash, user.id).run();

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/user/change-email
		if (url.pathname === '/api/user/change-email' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { new_email, totp_code } = body; 
				
				if (!new_email) return jsonResponse({ error: 'Missing parameters' }, 400);
				
				if (new_email.length > 50) return jsonResponse({ error: 'Email too long (Max 50 chars)' }, 400);
				
				const user_id = userPayload.id;

				const user = await env.forum_db.prepare('SELECT * FROM users WHERE id = ?').bind(user_id).first();
				if (!user) return jsonResponse({ error: 'User not found' }, 404);

				// Verify 2FA if enabled
				if (user.totp_enabled) {
					if (!totp_code) return jsonResponse({ error: 'TOTP_REQUIRED' }, 403);
					const totp = new OTPAuth.TOTP({
						algorithm: 'SHA1',
						digits: 6,
						period: 30,
						secret: OTPAuth.Secret.fromBase32(user.totp_secret)
					});
					if (totp.validate({ token: totp_code, window: 1 }) === null) {
						return jsonResponse({ error: 'Invalid TOTP code' }, 401);
					}
				}

				// Check if email already exists
				const exists = await env.forum_db.prepare('SELECT id FROM users WHERE email = ?').bind(new_email).first();
				if (exists) return jsonResponse({ error: 'Email already in use' }, 400);

				const token = generateToken();
				await env.forum_db.prepare('UPDATE users SET pending_email = ?, email_change_token = ? WHERE id = ?')
					.bind(new_email, token, user.id).run();
				
				await security.logAudit(userPayload.id, 'CHANGE_EMAIL_INIT', 'user', String(user_id), { new_email }, request);

				const verifyLink = `${url.origin}/api/verify-email-change?token=${token}`;

				ctx.waitUntil(sendEmailByTemplate(new_email, 'change_email_confirm', { newEmail: new_email, verifyLink }).catch(console.error));
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/verify-email-change
		if (url.pathname === '/api/verify-email-change' && method === 'GET') {
			const token = url.searchParams.get('token');
			if (!token) return textResponse('Missing token', 400);

			try {
				const user = await env.forum_db.prepare('SELECT * FROM users WHERE email_change_token = ?').bind(token).first();
				if (!user) return textResponse('Invalid token', 400);

				await env.forum_db.prepare('UPDATE users SET email = ?, pending_email = NULL, email_change_token = NULL WHERE id = ?')
					.bind(user.pending_email, user.id).run();

				return redirectResponse(`${url.origin}/?email_changed=true`);
			} catch (e) {
				return textResponse('Failed', 500);
			}
		}

		// POST /api/admin/users/:id/update (Admin direct update)
		if (url.pathname.match(/^\/api\/admin\/users\/\d+\/update$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const body = await request.json() as any;
				const { password, email, username, avatar_url } = body;

				if (password && (password.length < 8 || password.length > 16)) return jsonResponse({ error: 'Password must be 8-16 characters' }, 400);

				if (password) {
					const hash = await hashPassword(password);
					await env.forum_db.prepare('UPDATE users SET password = ? WHERE id = ?').bind(hash, id).run();
				}
				if (email) {
					if (email.length > 50) return jsonResponse({ error: 'Email too long (Max 50 chars)' }, 400);
					await env.forum_db.prepare('UPDATE users SET email = ? WHERE id = ?').bind(email, id).run();
				}
				if (avatar_url !== undefined) {
					// Allow clearing avatar with empty string or null -> Force Regenerate Default
					if (!avatar_url) {
						// Reset to Default
						const identicon = await generateIdenticon(String(id));
						await env.forum_db.prepare('UPDATE users SET avatar_url = ? WHERE id = ?').bind(identicon, id).run();
					} else {
						if (avatar_url.length > 5000) return jsonResponse({ error: 'Avatar URL too long (Max 5000 chars)' }, 400);
						if (!/^https?:\/\//i.test(avatar_url) && !avatar_url.startsWith('data:image/svg+xml') && !extractManagedImageKey(avatar_url, env as unknown as S3Env)) return jsonResponse({ error: 'Invalid Avatar URL' }, 400);
						await env.forum_db.prepare('UPDATE users SET avatar_url = ? WHERE id = ?').bind(normalizeAvatarValueForStorage(avatar_url, env as unknown as S3Env), id).run();
					}

					// Notify Avatar Change
					const notifyAvatar = await env.forum_db.prepare("SELECT value FROM settings WHERE key = 'notify_on_avatar_change'").first();
					if (notifyAvatar && notifyAvatar.value === '1') {
						const user = await env.forum_db.prepare('SELECT email, username FROM users WHERE id = ?').bind(id).first();
						ctx.waitUntil(sendEmailByTemplate(user.email, 'admin_avatar_updated').catch(console.error));
					}
				}
				if (username) {
					if (username.length > 20) return jsonResponse({ error: 'Username too long (Max 20 chars)' }, 400);
					if (isVisuallyEmpty(username)) return jsonResponse({ error: 'Username cannot be empty' }, 400);
					if (hasInvisibleCharacters(username)) return jsonResponse({ error: 'Username contains invalid invisible characters' }, 400);
					if (hasControlCharacters(username)) return jsonResponse({ error: 'Username contains invalid control characters' }, 400);
					
					await env.forum_db.prepare('UPDATE users SET username = ? WHERE id = ?').bind(username, id).run();

					// Notify user about username change
					const notifyUsername = await env.forum_db.prepare("SELECT value FROM settings WHERE key = 'notify_on_username_change'").first();
					if (notifyUsername && notifyUsername.value === '1') {
						const user = await env.forum_db.prepare('SELECT email, username FROM users WHERE id = ?').bind(id).first();
						ctx.waitUntil(sendEmailByTemplate(user.email, 'admin_username_updated', { username }).catch(console.error));
					}
				}
				
				await security.logAudit(userPayload.id, 'ADMIN_UPDATE_USER', 'user', id, { username, email, avatar_url, passwordChanged: !!password }, request);

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/categories
		if (url.pathname === '/api/categories' && method === 'GET') {
			try {
				const { results } = await env.forum_db.prepare('SELECT * FROM categories ORDER BY created_at ASC').all();
				return jsonResponse(results);
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/categories
		if (url.pathname === '/api/admin/categories' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const body = await request.json() as any;
				const { name } = body;
				if (!name) return jsonResponse({ error: 'Missing name' }, 400);
				
				const { success } = await env.forum_db.prepare('INSERT INTO categories (name) VALUES (?)').bind(name).run();
				await security.logAudit(userPayload.id, 'CREATE_CATEGORY', 'category', name, {}, request);
				return jsonResponse({ success });
			} catch (e) {
				return handleError(e);
			}
		}

		// PUT /api/admin/categories/:id
		if (url.pathname.match(/^\/api\/admin\/categories\/\d+$/) && method === 'PUT') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const body = await request.json() as any;
				const { name } = body;
				if (!name) return jsonResponse({ error: 'Missing name' }, 400);
				
				await env.forum_db.prepare('UPDATE categories SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').bind(name, id).run();
				await security.logAudit(userPayload.id, 'UPDATE_CATEGORY', 'category', id, { name }, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// DELETE /api/admin/categories/:id
		if (url.pathname.match(/^\/api\/admin\/categories\/\d+$/) && method === 'DELETE') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				// Check if there are posts in this category
				const count = await env.forum_db.prepare('SELECT COUNT(*) as count FROM posts WHERE category_id = ?').bind(id).first('count');
				if (count > 0) {
					return jsonResponse({ error: 'Cannot delete category with existing posts' }, 400);
				}
				
				await env.forum_db.prepare('DELETE FROM categories WHERE id = ?').bind(id).run();
				await security.logAudit(userPayload.id, 'DELETE_CATEGORY', 'category', id, {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// --- ADMIN ROUTES ---

		// GET /api/admin/stats
		if (url.pathname === '/api/admin/stats' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const [userCount, postCount, commentCount] = await Promise.all([
					env.forum_db.prepare('SELECT COUNT(*) as count FROM users').first('count'),
					env.forum_db.prepare('SELECT COUNT(*) as count FROM posts').first('count'),
					env.forum_db.prepare('SELECT COUNT(*) as count FROM comments').first('count')
				]);
				
				return jsonResponse({
					users: userCount,
					posts: postCount,
					comments: commentCount
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/admin/users
		if (url.pathname === '/api/admin/users' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const q = (url.searchParams.get('q') || url.searchParams.get('query') || '').trim();
				let query = 'SELECT id, email, username, role, verified, created_at, avatar_url, last_seen_at, draw_banned FROM users';
				const params: any[] = [];
				const conditions: string[] = [];

				if (q) {
					conditions.push('(username LIKE ? OR email LIKE ?)');
					const like = `%${q}%`;
					params.push(like, like);
				}

				if (conditions.length) {
					query += ` WHERE ${conditions.join(' AND ')}`;
				}

				query += ' ORDER BY created_at DESC';

				const { results } = await env.forum_db.prepare(query).bind(...params).all();
				return jsonResponse(results.map((user: any) => ({
					...user,
					avatar_url: rewriteAvatarValueToPublicUrl(user.avatar_url, env as unknown as S3Env)
				})));
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/users/:id/verify (Manual Verify)
		if (url.pathname.match(/^\/api\/admin\/users\/\d+\/verify$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const { success } = await env.forum_db.prepare('UPDATE users SET verified = 1, verification_token = NULL WHERE id = ?').bind(id).run();
				await security.logAudit(userPayload.id, 'MANUAL_VERIFY_USER', 'user', id, {}, request);

				// Notification
				const setting = await env.forum_db.prepare("SELECT value FROM settings WHERE key = 'notify_on_manual_verify'").first();
				if (setting && setting.value === '1') {
					const user = await env.forum_db.prepare('SELECT email, username FROM users WHERE id = ?').bind(id).first();
					ctx.waitUntil(sendEmailByTemplate(user.email as string, 'admin_manual_verified', { username: user.username }).catch(console.error));
				}

				return jsonResponse({ success });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/users/:id/resend (Resend Verification Email)
		if (url.pathname.match(/^\/api\/admin\/users\/\d+\/resend$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const user = await env.forum_db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
				if (!user) return jsonResponse({ error: 'User not found' }, 404);
				if (user.verified) return jsonResponse({ error: 'User already verified' }, 400);

				// Generate new token if needed, or use existing
				let token = user.verification_token;
				if (!token) {
					token = generateToken();
					await env.forum_db.prepare('UPDATE users SET verification_token = ? WHERE id = ?').bind(token, id).run();
				}

				const verifyLink = `${url.origin}/api/verify?token=${token}`;

				ctx.waitUntil(
					sendEmailByTemplate(user.email, 'admin_resend_verify', { username: user.username, verifyLink })
						.catch(err => console.error('[Background Email Error]', err))
				);
				
				await security.logAudit(userPayload.id, 'RESEND_VERIFY_EMAIL', 'user', id, {}, request);

				return jsonResponse({ success: true, message: '验证邮件已发送' });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/users/:id/draw-ban (Toggle draw ban)
		if (url.pathname.match(/^\/api\/admin\/users\/\d+\/draw-ban$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const user = await env.forum_db.prepare('SELECT id, draw_banned FROM users WHERE id = ?').bind(id).first();
				if (!user) return jsonResponse({ error: 'User not found' }, 404);

				const newBanned = user.draw_banned ? 0 : 1;
				await env.forum_db.prepare('UPDATE users SET draw_banned = ? WHERE id = ?').bind(newBanned, id).run();

				await security.logAudit(
					userPayload.id,
					newBanned ? 'ADMIN_DRAW_BAN_USER' : 'ADMIN_DRAW_UNBAN_USER',
					'user', String(id), {}, request
				);

				return jsonResponse({
					success: true,
					draw_banned: !!newBanned,
					message: newBanned ? '已禁止该用户生图' : '已解除该用户生图禁令'
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// DELETE /api/admin/users/:id
		if (url.pathname.startsWith('/api/admin/users/') && method === 'DELETE') {
			const id = url.pathname.split('/').pop();
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				// 0. Delete user avatar and post images
				const user = await env.forum_db.prepare('SELECT avatar_url FROM users WHERE id = ?').bind(id).first();
				const posts = await env.forum_db.prepare('SELECT content FROM posts WHERE author_id = ?').bind(id).all();
				
				const deletionPromises: Promise<any>[] = [];
				if (user && user.avatar_url) {
					deletionPromises.push(deleteImage(env as unknown as S3Env, user.avatar_url, id));
				}
				if (posts.results) {
					for (const post of posts.results) {
						const imageKeys = extractManagedImageKeysFromMarkdown(post.content as string, env as unknown as S3Env);
						imageKeys.forEach(key => deletionPromises.push(deleteImage(env as unknown as S3Env, key, id)));
					}
				}
				if (deletionPromises.length > 0) {
					ctx.waitUntil(Promise.all(deletionPromises).catch(err => console.error('Failed to delete user images', err)));
				}

				// 1. Delete likes and comments ON the user's posts (to avoid orphans)
				await env.forum_db.prepare('DELETE FROM likes WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?)').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comment_likes WHERE comment_id IN (SELECT id FROM comments WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?))').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comments WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?)').bind(id).run();

				// 2. Detach child comments that reply to the user's comments
				await env.forum_db.prepare('UPDATE comments SET parent_id = NULL WHERE parent_id IN (SELECT id FROM comments WHERE author_id = ?)').bind(id).run();

				// 3. Delete the user's own activity (likes and comments they made)
				await env.forum_db.prepare('DELETE FROM likes WHERE user_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comment_likes WHERE user_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comment_likes WHERE comment_id IN (SELECT id FROM comments WHERE author_id = ?)').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comments WHERE author_id = ?').bind(id).run();

				// 4. Delete sessions and the user's posts
				await env.forum_db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM user_profiles WHERE user_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM posts WHERE author_id = ?').bind(id).run();

				// 5. Finally, delete the user
				const userToDelete = await env.forum_db.prepare('SELECT email, username FROM users WHERE id = ?').bind(id).first();
				await env.forum_db.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
				
				await security.logAudit(userPayload.id, 'ADMIN_DELETE_USER', 'user', id, {}, request);

				// Notification
				if (userToDelete) {
					const setting = await env.forum_db.prepare("SELECT value FROM settings WHERE key = 'notify_on_user_delete'").first();
					if (setting && setting.value === '1') {
						ctx.waitUntil(sendEmailByTemplate(userToDelete.email as string, 'admin_account_deleted', { username: userToDelete.username }).catch(console.error));
					}
				}

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// DELETE /api/admin/posts/:id
		if (url.pathname.startsWith('/api/admin/posts/') && method === 'DELETE') {
			const id = url.pathname.split('/').pop();
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const post = await env.forum_db.prepare(
					'SELECT posts.title, posts.content, posts.author_id, users.email, users.username FROM posts JOIN users ON posts.author_id = users.id WHERE posts.id = ?'
				).bind(id).first();
				if (!post) return jsonResponse({ error: 'Post not found' }, 404);

				const imageKeys = extractManagedImageKeysFromMarkdown(post.content as string, env as unknown as S3Env);
				if (imageKeys.length > 0) {
					ctx.waitUntil(Promise.all(imageKeys.map(key => deleteImage(env as unknown as S3Env, key, post.author_id as number))).catch(err => console.error('Failed to delete post images', err)));
				}

				await env.forum_db.prepare('DELETE FROM likes WHERE post_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comment_likes WHERE comment_id IN (SELECT id FROM comments WHERE post_id = ?)').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comments WHERE post_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM posts WHERE id = ?').bind(id).run();

				await security.logAudit(userPayload.id, 'ADMIN_DELETE_POST', 'post', id, {}, request);

				// 只有删除别人的帖子时才发送通知
				if (post.author_id !== userPayload.id) {
					const setting = await env.forum_db.prepare("SELECT value FROM settings WHERE key = 'notify_on_post_delete'").first();
					if (setting && setting.value === '1') {
						const postUrl = `https://2x.nz/forum/post/?id=${id}`;
						ctx.waitUntil(sendEmailByTemplate(post.email as string, 'admin_post_deleted', {
							username: post.username,
							postTitle: post.title,
							postUrl
 					}).catch(console.error));
					}
				}

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// DELETE /api/admin/comments/:id
		if (url.pathname.startsWith('/api/admin/comments/') && method === 'DELETE') {
			const id = url.pathname.split('/').pop();
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				// Delete the comment AND its children (orphans prevention)
				await env.forum_db.prepare('DELETE FROM comments WHERE parent_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comments WHERE id = ?').bind(id).run();
				
				await security.logAudit(userPayload.id, 'ADMIN_DELETE_COMMENT', 'comment', id, {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/posts/:id/pin
		if (url.pathname.match(/^\/api\/admin\/posts\/\d+\/pin$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const body = await request.json() as any;
				const { pinned } = body;
				await env.forum_db.prepare('UPDATE posts SET is_pinned = ? WHERE id = ?').bind(pinned ? 1 : 0, id).run();

				await security.logAudit(userPayload.id, 'ADMIN_PIN_POST', 'post', id, { pinned }, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/comments/:id/pin
		if (url.pathname.match(/^\/api\/comments\/\d+\/pin$/) && method === 'POST') {
			const id = url.pathname.split('/')[3];
			try {
				const userPayload = await authenticate(request);
				const comment = await env.forum_db.prepare('SELECT id, parent_id, author_id FROM comments WHERE id = ?').bind(id).first();
				if (!comment) return jsonResponse({ error: 'Comment not found' }, 404);
				if (comment.parent_id !== null) return jsonResponse({ error: 'Only root comments can be pinned' }, 400);
				if (userPayload.role !== 'admin' && comment.author_id !== userPayload.id) return jsonResponse({ error: 'Unauthorized' }, 403);

				const body = await request.json() as any;
				const { pinned } = body;
				await env.forum_db.prepare('UPDATE comments SET is_pinned = ? WHERE id = ?').bind(pinned ? 1 : 0, id).run();

				await security.logAudit(userPayload.id, pinned ? 'PIN_COMMENT' : 'UNPIN_COMMENT', 'comment', id, { pinned }, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/posts/:id/move
		if (url.pathname.match(/^\/api\/admin\/posts\/\d+\/move$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const body = await request.json() as any;
				const { category_id } = body;
				
				// Validate category exists if provided
				if (category_id) {
					const category = await env.forum_db.prepare('SELECT id FROM categories WHERE id = ?').bind(category_id).first();
					if (!category) return jsonResponse({ error: 'Category not found' }, 404);
				}

				await env.forum_db.prepare('UPDATE posts SET category_id = ? WHERE id = ?').bind(category_id || null, id).run();
				
				await security.logAudit(userPayload.id, 'ADMIN_MOVE_POST', 'post', id, { category_id }, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/admin/cleanup/analyze
		if (url.pathname === '/api/admin/cleanup/analyze' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);
                                
				// 1. List all S3 objects
				const allKeys = await listAllKeys(env as unknown as S3Env);
				
				// 2. Gather used keys
				const usedKeys = new Set<string>();

				// Users avatars
				const users = await env.forum_db.prepare('SELECT avatar_url FROM users WHERE avatar_url IS NOT NULL').all();
				for (const u of users.results) {
					const key = extractManagedImageKey(u.avatar_url as string, env as unknown as S3Env);
					if (key) usedKeys.add(key);
				}

				// Posts images
				const posts = await env.forum_db.prepare('SELECT content FROM posts').all();
				for (const p of posts.results) {
					const keys = extractManagedImageKeysFromMarkdown(p.content as string, env as unknown as S3Env);
					for (const key of keys) {
						usedKeys.add(key);
					}
				}

				// Comments images
				const comments = await env.forum_db.prepare('SELECT content FROM comments').all();
				for (const c of comments.results) {
					const keys = extractManagedImageKeysFromMarkdown(c.content as string, env as unknown as S3Env);
					for (const key of keys) {
						usedKeys.add(key);
					}
				}

				// 3. Find orphans
				const orphans = allKeys.filter(key => !usedKeys.has(key));

				return jsonResponse({ 
					total_files: allKeys.length,
					used_files: usedKeys.size,
					orphaned_files: orphans.length,
					orphans: orphans
				});

			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/admin/cleanup/execute
		if (url.pathname === '/api/admin/cleanup/execute' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);
				
				const body = await request.json() as any;
				const { orphans } = body;
				
				if (!orphans || !Array.isArray(orphans)) return jsonResponse({ error: 'Invalid parameters' }, 400);

				const deletePromises = orphans.map(key => deleteImage(env as unknown as S3Env, key));
				
				ctx.waitUntil(Promise.all(deletePromises).catch(err => console.error('Cleanup failed', err)));
				
				return jsonResponse({ success: true, message: `Deletion of ${orphans.length} files started` });
			} catch (e) {
				return handleError(e);
			}
		}

		if (url.pathname === '/api/admin/email/test' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const body = await request.json() as { to?: string; template?: string; payload?: EmailTemplatePayload };
				const to = String(body.to || '').trim();
				const template = String(body.template || '').trim();
				const payload = body.payload && typeof body.payload === 'object' ? body.payload : {};

				if (!to) return jsonResponse({ error: '缺少收件邮箱' }, 400);
				if (!isValidEmail(to)) return jsonResponse({ error: '收件邮箱格式无效' }, 400);
				if (!template) return jsonResponse({ error: '缺少邮件模板' }, 400);

				const isBatch = template === 'all';
				const templateKeys = isBatch ? EMAIL_TEMPLATE_DEFINITIONS.map((item) => item.key) : [template];
				const invalidTemplate = templateKeys.find((key) => !EMAIL_TEMPLATE_MAP[key]);
				if (invalidTemplate) return jsonResponse({ error: '无效的邮件模板' }, 400);

				const results: Array<{ template: string; label: string; success: boolean; error?: string }> = [];
				for (const templateKey of templateKeys) {
					const templateDefinition = EMAIL_TEMPLATE_MAP[templateKey];
					try {
						const currentPayload = isBatch ? {} : payload;
						await sendEmailByTemplate(to, templateKey, currentPayload);
						results.push({ template: templateKey, label: templateDefinition.label, success: true });
					} catch (error: any) {
						results.push({
							template: templateKey,
							label: templateDefinition.label,
							success: false,
							error: String(error?.message || error)
 					});
					}
				}

				const failedItems = results.filter((item) => !item.success).map((item) => ({ template: item.template, error: item.error }));
				await security.logAudit(userPayload.id, 'ADMIN_TEST_EMAIL', 'system', 'email', {
					to,
					template,
					isBatch,
					failedItems
				}, request);

				return jsonResponse({
					success: results.some((item) => item.success),
					results
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// --- END ADMIN ROUTES ---

		// TEST: Email Debug
		if (url.pathname === '/api/test-email' && method === 'POST') {
			try {
				const body = await request.json() as any;
				const { to } = body;
				if (!to) return jsonResponse({ error: '缺少收件人地址' }, 400);

				console.log('[DEBUG] Starting test email to:', to);
				await sendEmailByTemplate(to, 'smtp_test');
				console.log('[DEBUG] Test email sent successfully');
				
				return jsonResponse({ success: true, message: '邮件已发送' });
			} catch (e) {
				console.error('[DEBUG] Test email failed:', e);
				return handleError(e);
			}
		}

		// AUTH: Register
		if (url.pathname === '/api/register' && method === 'POST') {
			try {
				const body = await request.json() as any;

				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				if (!(await checkTurnstile(body, ip))) {
					return jsonResponse({ error: 'Turnstile verification failed' }, 403);
				}

				const { email, username, password } = body;
				if (!email || !username || !password) {
					return jsonResponse({ error: 'Missing email, username or password' }, 400);
				}

				if (email.length > 50) return jsonResponse({ error: 'Email too long (Max 50 chars)' }, 400);

				if (username.length > 20) return jsonResponse({ error: 'Username too long (Max 20 chars)' }, 400);
				if (isVisuallyEmpty(username)) return jsonResponse({ error: 'Username cannot be empty' }, 400);
				if (hasInvisibleCharacters(username)) return jsonResponse({ error: 'Username contains invalid invisible characters' }, 400);
				if (hasControlCharacters(username)) return jsonResponse({ error: 'Username contains invalid control characters' }, 400);
				if (hasRestrictedKeywords(username)) return jsonResponse({ error: 'Username contains restricted keywords' }, 400);

				if (password.length < 8 || password.length > 16) return jsonResponse({ error: 'Password must be 8-16 characters' }, 400);

				// Check Uniqueness (Combined Query for Performance)
				const existing = await env.forum_db.prepare('SELECT email, username FROM users WHERE email = ? OR username = ?').bind(email, username).first();
				if (existing) {
					if (existing.email === email) return jsonResponse({ error: 'Email already exists' }, 409);
					return jsonResponse({ error: 'Username already taken' }, 409);
				}

				const passwordHash = await hashPassword(password);
				const verificationToken = generateToken();

				// Pre-check email deliverability (Send a test email first)
				// Note: We don't insert user yet. If email fails, we abort.
				const verifyLink = `${url.origin}/api/verify?token=${verificationToken}`;

				try {
					await sendEmailByTemplate(email, 'register_verify', { username, verifyLink });
				} catch (e) {
					console.error('[Registration Email Error]', e);
					return jsonResponse({ error: '验证邮件发送失败，请检查邮箱地址是否正确。' }, 400);
				}

				const { success, meta } = await env.forum_db.prepare(
					'INSERT INTO users (email, username, password, role, verified, verification_token) VALUES (?, ?, ?, "user", 0, ?)'
				).bind(email, username, passwordHash, verificationToken).run();

				if (success) {
					// Generate Default Avatar (Identicon)
					// Use ID if available, otherwise fallback to Username
					const userId = meta?.last_row_id;
					if (userId) {
						const identicon = await generateIdenticon(String(userId));
						await env.forum_db.prepare('UPDATE users SET avatar_url = ? WHERE id = ?').bind(identicon, userId).run();
					} else {
						// Fallback if ID retrieval fails (rare in D1)
						const identicon = await generateIdenticon(username);
						// We don't have ID easily without query, but we can update by username or just skip
						await env.forum_db.prepare('UPDATE users SET avatar_url = ? WHERE username = ?').bind(identicon, username).run();
					}
				}

				return jsonResponse({ success, message: '注册成功，请前往邮箱完成验证。' }, 201);
			} catch (e: any) {
				if (e.message && e.message.includes('UNIQUE constraint failed')) {
					return jsonResponse({ error: 'Email already exists' }, 409);
				}
				return handleError(e);
			}
		}

		// AUTH: Verify Email
		if (url.pathname === '/api/verify' && method === 'GET') {
			const token = url.searchParams.get('token');
			if (!token) {
				return textResponse('缺少 token', 400);
			}

			try {
				const { success } = await env.forum_db.prepare(
					'UPDATE users SET verified = 1, verification_token = NULL WHERE verification_token = ?'
				).bind(token).run();

				if (success) {
					return redirectResponse('https://2x.nz/forum/auth/login/');
				} else {
					return textResponse('token 无效或已过期', 400);
				}
			} catch (e) {
				return textResponse('验证失败', 500);
			}
		}

		// GET /users
		if (url.pathname === '/api/users' && method === 'GET') {
			try {
				const { results } = await env.forum_db.prepare(
					'SELECT id, email, username, created_at FROM users'
				).all();
				return jsonResponse(results);
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/users/:id
		if (url.pathname.match(/^\/api\/users\/\d+$/) && method === 'GET') {
			const userId = url.pathname.split('/')[3];
			try {
				const user = await env.forum_db.prepare(
					`SELECT
						users.id,
						users.username,
						users.avatar_url,
						users.role,
						users.created_at,
						users.last_seen_at,
						user_profiles.gender,
						user_profiles.bio,
						user_profiles.age,
						user_profiles.region
					 FROM users
					 LEFT JOIN user_profiles ON user_profiles.user_id = users.id
					 WHERE users.id = ?`
				).bind(userId).first();
				if (!user) return jsonResponse({ error: 'User not found' }, 404);

				return jsonResponse({
					id: user.id,
					username: user.username,
					avatar_url: rewriteAvatarValueToPublicUrl(user.avatar_url, env as unknown as S3Env),
					role: user.role || 'user',
					gender: user.gender ?? null,
					bio: user.bio ?? null,
					age: user.age ?? null,
					region: user.region ?? null,
					created_at: user.created_at,
					last_seen_at: user.last_seen_at ?? null
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/users/:id/posts
		if (url.pathname.match(/^\/api\/users\/\d+\/posts$/) && method === 'GET') {
			const userId = url.pathname.split('/')[3];
			try {
				const user = await env.forum_db.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
				if (!user) return jsonResponse({ error: 'User not found' }, 404);

				const limit = parseInt(url.searchParams.get('limit') || '20');
				const offset = parseInt(url.searchParams.get('offset') || '0');
				const sortByRaw = (url.searchParams.get('sort_by') || 'time').trim().toLowerCase();
				const sortDirRaw = (url.searchParams.get('sort_dir') || 'desc').trim().toLowerCase();
				const sortDir = sortDirRaw === 'asc' ? 'ASC' : 'DESC';

				let query = `SELECT
						posts.*,
						users.username as author_name,
						users.avatar_url as author_avatar,
						users.role as author_role,
						categories.name as category_name,
						(SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) as like_count,
						(SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) as comment_count
					 FROM posts
					 JOIN users ON posts.author_id = users.id
					 LEFT JOIN categories ON posts.category_id = categories.id
					 WHERE posts.author_id = ?`;
				const countQuery = 'SELECT COUNT(*) as total FROM posts WHERE author_id = ?';
				const params: any[] = [userId];

				const sortExpr =
					sortByRaw === 'likes'
						? `like_count ${sortDir}`
						: sortByRaw === 'comments'
							? `comment_count ${sortDir}`
							: sortByRaw === 'views'
								? `posts.view_count ${sortDir}`
								: `posts.created_at ${sortDir}`;

				query += ` ORDER BY posts.is_pinned DESC, ${sortExpr}, posts.created_at DESC LIMIT ? OFFSET ?`;
				params.push(limit, offset);

				const [postsResult, countResult] = await Promise.all([
					env.forum_db.prepare(query).bind(...params).all(),
					env.forum_db.prepare(countQuery).bind(userId).first()
				]);

				return jsonResponse({
					posts: postsResult.results.map((post: any) => rewritePostForResponse(post, env as unknown as S3Env)),
					total: countResult ? countResult.total : 0
				});
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/user/likes (Get all post IDs liked by user)
		if (url.pathname === '/api/user/likes' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				const { results } = await env.forum_db.prepare('SELECT post_id FROM likes WHERE user_id = ?').bind(userPayload.id).all();
				return jsonResponse(results.map((r: any) => r.post_id));
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/posts/new-count (Count new posts since user's last visit)
		if (url.pathname === '/api/posts/new-count' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				// Read last_seen_at first — authenticate's ctx.waitUntil UPDATE is async,
				// so this SELECT will almost certainly read the OLD value.
				const user = await env.forum_db.prepare('SELECT last_seen_at FROM users WHERE id = ?').bind(userPayload.id).first();
				const lastSeenAt = user?.last_seen_at as string | null;
				if (!lastSeenAt) {
					// User has never been seen before (first login), return total post count
					const total = await env.forum_db.prepare('SELECT COUNT(*) as count FROM posts').first('count');
					return jsonResponse({ new_post_count: total || 0, last_seen_at: null });
				}
				const count = await env.forum_db.prepare('SELECT COUNT(*) as count FROM posts WHERE created_at > ?').bind(lastSeenAt).first('count');
				return jsonResponse({ new_post_count: count || 0, last_seen_at: lastSeenAt });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /posts
		if (url.pathname === '/api/posts' && method === 'GET') {
			try {
				const limit = parseInt(url.searchParams.get('limit') || '20');
				const offset = parseInt(url.searchParams.get('offset') || '0');
				const categoryId = url.searchParams.get('category_id');
				const q = (url.searchParams.get('q') || url.searchParams.get('query') || '').trim();
				const sortByRaw = (url.searchParams.get('sort_by') || 'time').trim().toLowerCase();
				const sortDirRaw = (url.searchParams.get('sort_dir') || 'desc').trim().toLowerCase();
				const sortDir = sortDirRaw === 'asc' ? 'ASC' : 'DESC';
				
				let query = `SELECT 
                        posts.*, 
                        users.username as author_name, 
                        users.avatar_url as author_avatar,
                        users.role as author_role,
                        categories.name as category_name,
                        (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) as like_count,
                        (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) as comment_count
                     FROM posts 
                     JOIN users ON posts.author_id = users.id 
                     LEFT JOIN categories ON posts.category_id = categories.id`;
                
                let countQuery = `SELECT COUNT(*) as total FROM posts`;

                const params: any[] = [];
                const countParams: any[] = [];
				const conditions: string[] = [];

                if (categoryId) {
                    if (categoryId === 'uncategorized') {
						conditions.push(`posts.category_id IS NULL`);
                    } else {
						conditions.push(`posts.category_id = ?`);
                        params.push(categoryId);
                        countParams.push(categoryId);
                    }
                }

				if (q) {
					conditions.push(`(posts.title LIKE ? OR posts.content LIKE ?)`);
					const like = `%${q}%`;
					params.push(like, like);
					countParams.push(like, like);
				}

				if (conditions.length) {
					query += ` WHERE ${conditions.join(' AND ')}`;
					countQuery += ` WHERE ${conditions.join(' AND ')}`;
				}

				const sortExpr =
					sortByRaw === 'likes'
						? `like_count ${sortDir}`
						: sortByRaw === 'comments'
							? `comment_count ${sortDir}`
							: sortByRaw === 'views'
								? `posts.view_count ${sortDir}`
								: `posts.created_at ${sortDir}`;

                query += ` ORDER BY is_pinned DESC, ${sortExpr}, posts.created_at DESC LIMIT ? OFFSET ?`;
                params.push(limit, offset);
				
				const [postsResult, countResult] = await Promise.all([
                    env.forum_db.prepare(query).bind(...params).all(),
                    env.forum_db.prepare(countQuery).bind(...countParams).first()
                ]);

				return jsonResponse({
                    posts: postsResult.results.map((post: any) => rewritePostForResponse(post, env as unknown as S3Env)),
                    total: countResult ? countResult.total : 0
                });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/posts/:id
		if (url.pathname.match(/^\/api\/posts\/\d+$/) && method === 'GET') {
			const postId = url.pathname.split('/')[3];
			try {
				const post = await env.forum_db.prepare(
					`SELECT 
                        posts.*, 
                        users.username as author_name, 
                        users.avatar_url as author_avatar,
                        users.role as author_role,
                        categories.name as category_name,
                        (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) as like_count,
                        (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) as comment_count
                     FROM posts 
                     JOIN users ON posts.author_id = users.id 
                     LEFT JOIN categories ON posts.category_id = categories.id
                     WHERE posts.id = ?`
				).bind(postId).first();
				
				if (!post) return jsonResponse({ error: 'Post not found' }, 404);

				try {
					await env.forum_db.prepare('UPDATE posts SET view_count = COALESCE(view_count, 0) + 1 WHERE id = ?').bind(postId).run();
					(post as any).view_count = Number((post as any).view_count || 0) + 1;
				} catch {}

				// Check like status if user_id provided
				const userId = url.searchParams.get('user_id');
				if (userId) {
					const like = await env.forum_db.prepare('SELECT id FROM likes WHERE post_id = ? AND user_id = ?').bind(postId, userId).first();
					(post as any).liked = !!like;
				}

				return jsonResponse(rewritePostForResponse(post, env as unknown as S3Env));
			} catch (e) {
				return handleError(e);
			}
		}

		// PUT /api/posts/:id
		if (url.pathname.match(/^\/api\/posts\/\d+$/) && method === 'PUT') {
			const postId = url.pathname.split('/')[3];
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { title, content, category_id } = body; // user_id not needed from body

				if (!title || !content) {
					return jsonResponse({ error: 'Missing parameters' }, 400);
				}

				if (isVisuallyEmpty(title) || isVisuallyEmpty(content)) return jsonResponse({ error: 'Title or content cannot be empty' }, 400);

				if (hasInvisibleCharacters(title) || hasInvisibleCharacters(content)) return jsonResponse({ error: 'Title or content contains invalid invisible characters' }, 400);

				// Check ownership or admin
				const post = await env.forum_db.prepare('SELECT author_id FROM posts WHERE id = ?').bind(postId).first();
				if (!post) return jsonResponse({ error: 'Post not found' }, 404);

				// Use userPayload for RBAC
				if (post.author_id !== userPayload.id && userPayload.role !== 'admin') {
					return jsonResponse({ error: 'Unauthorized' }, 403);
				}

				// Validate Lengths
				if (title.length > 30) return jsonResponse({ error: 'Title too long (Max 30 chars)' }, 400);
				if (content.length > 3000) return jsonResponse({ error: 'Content too long (Max 3000 chars)' }, 400);
				if (hasControlCharacters(title) || hasControlCharacters(content)) return jsonResponse({ error: 'Title or content contains invalid control characters' }, 400);

				// Validate Category
				if (category_id) {
					const category = await env.forum_db.prepare('SELECT id FROM categories WHERE id = ?').bind(category_id).first();
					if (!category) return jsonResponse({ error: 'Category not found' }, 400);
				}

				const storedContent = rewriteMarkdownImageRefsToStoredForm(content.trim(), env as unknown as S3Env);

				await env.forum_db.prepare(
					'UPDATE posts SET title = ?, content = ?, category_id = ? WHERE id = ?'
				).bind(title.trim(), storedContent, category_id || null, postId).run();

				await security.logAudit(userPayload.id, 'UPDATE_POST', 'post', postId, { title_length: title.length }, request);

				// WebSocket broadcast for real-time updates via Durable Object
				const wsId = env.WS_MANAGER.idFromName(String(postId));
				const wsStub = env.WS_MANAGER.get(wsId);
				ctx.waitUntil(wsStub.fetch(new Request('http://internal/broadcast', {
					method: 'POST',
					body: JSON.stringify({
						postId: String(postId),
						message: {
							type: 'post_updated',
							payload: {
								postId: postId,
								title: title.trim(),
								content: rewriteMarkdownImageRefsToPublicUrl(storedContent, env as unknown as S3Env),
								category_id: category_id || null,
								updated_at: new Date().toISOString()
							}
 					}
					})
				})).catch(console.error));

				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// DELETE /api/posts/:id (User delete own post)
		if (url.pathname.match(/^\/api\/posts\/\d+$/) && method === 'DELETE') {
			const id = url.pathname.split('/')[3];
			try {
				const userPayload = await authenticate(request);
				
				// Check ownership
				const post = await env.forum_db.prepare('SELECT author_id, content FROM posts WHERE id = ?').bind(id).first();
				if (!post) return jsonResponse({ error: 'Post not found' }, 404);
				
				if (post.author_id !== userPayload.id) {
					return jsonResponse({ error: 'Unauthorized' }, 403);
				}

				// Delete images in post
				const imageKeys = extractManagedImageKeysFromMarkdown(post.content as string, env as unknown as S3Env);
				if (imageKeys.length > 0) {
					ctx.waitUntil(Promise.all(imageKeys.map(key => deleteImage(env as unknown as S3Env, key, userPayload.id))).catch(err => console.error('Failed to delete post images', err)));
				}

				await env.forum_db.prepare('DELETE FROM likes WHERE post_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comment_likes WHERE comment_id IN (SELECT id FROM comments WHERE post_id = ?)').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comments WHERE post_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM posts WHERE id = ?').bind(id).run();
				
				await security.logAudit(userPayload.id, 'DELETE_POST', 'post', id, {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/posts/:id/comments
		if (url.pathname.match(/^\/api\/posts\/\d+\/comments$/) && method === 'GET') {
			const postId = url.pathname.split('/')[3];
			try {
				let currentUserId: number | null = null;
				try {
					const userPayload = await authenticate(request);
					currentUserId = userPayload.id;
				} catch {}

				const sortByRaw = (url.searchParams.get('sort_by') || 'likes').trim().toLowerCase();
				const sortDirRaw = (url.searchParams.get('sort_dir') || 'desc').trim().toLowerCase();
				const sortBy = sortByRaw === 'time' ? 'time' : 'likes';
				const sortDir = sortDirRaw === 'asc' ? 'ASC' : 'DESC';
				const sortExpr =
					sortBy === 'time'
						? `comments.created_at ${sortDir}`
						: sortDir === 'ASC'
							? 'like_count ASC, comments.created_at ASC'
							: 'like_count DESC, comments.created_at ASC';

				const { results } = await env.forum_db.prepare(
					`SELECT comments.*, users.username, users.avatar_url, users.role,
						(SELECT COUNT(*) FROM comment_likes WHERE comment_likes.comment_id = comments.id) as like_count,
						EXISTS(
							SELECT 1 FROM comment_likes
							WHERE comment_likes.comment_id = comments.id AND comment_likes.user_id = ?
						) as liked
                     FROM comments
                     JOIN users ON comments.author_id = users.id
                     WHERE post_id = ?
                     ORDER BY
					 	CASE WHEN comments.parent_id IS NULL THEN 0 ELSE 1 END ASC,
					 	CASE WHEN comments.parent_id IS NULL THEN COALESCE(comments.is_pinned, 0) ELSE 0 END DESC,
					 	${sortExpr}`
				).bind(currentUserId, postId).all();
				return jsonResponse(results.map((comment: any) => ({
					...rewriteCommentForResponse(comment, env as unknown as S3Env),
					like_count: Number(comment.like_count || 0),
					liked: !!comment.liked,
					is_pinned: Number(comment.is_pinned || 0)
				})));
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/posts/:id/comments
		if (url.pathname.match(/^\/api\/posts\/\d+\/comments$/) && method === 'POST') {
			const postId = url.pathname.split('/')[3];
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;

				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				if (!(await checkTurnstile(body, ip))) {
					return jsonResponse({ error: 'Turnstile verification failed' }, 403);
				}

				let { content, parent_id } = body;
				// user_id comes from token now

				if (!content) return jsonResponse({ error: 'Missing parameters' }, 400);
				
				// --- Input Sanitization & Validation (Sync with Frontend) ---
				// 1. Visually Empty Check
				if (isVisuallyEmpty(content)) return jsonResponse({ error: 'Comment cannot be empty' }, 400);
				
				// 2. Invisible Characters Check
				if (hasInvisibleCharacters(content)) return jsonResponse({ error: 'Comment contains invalid invisible characters' }, 400);
				
				// 3. Length Check
				if (content.length > 3000) return jsonResponse({ error: 'Comment too long (Max 3000 chars)' }, 400);
				
				// 4. Control Characters Check
				if (hasControlCharacters(content)) return jsonResponse({ error: 'Comment contains invalid control characters' }, 400);

				// 5. HTML Escape (Basic XSS Prevention - though we use textContent in DB, escaping here is safer)
				content = content
					.replace(/&/g, '&amp;')
					.replace(/</g, '&lt;')
					.replace(/>/g, '&gt;')
					.replace(/"/g, '&quot;')
					.replace(/'/g, '&#039;');
				
				// "Reply to Reply" Logic: Flatten to Level 2 with @Mention
				let originalParentAuthorId = null; // Track who was *originally* replied to for notifications

				if (parent_id) {
					const parent = await env.forum_db.prepare('SELECT parent_id, author_id FROM comments WHERE id = ?').bind(parent_id).first();
					
					if (parent) {
						if (parent.parent_id !== null) {
							// Level 3 attempt detected.
							// 1. Fetch username of the user being replied to
							const targetUser = await env.forum_db.prepare('SELECT username FROM users WHERE id = ?').bind(parent.author_id).first();
							const targetName = targetUser.username;

							// 2. Rewrite content and parent_id
							content = `@${targetName} ${content}`;
							parent_id = parent.parent_id; // Move up to share the same Level 1 parent
							originalParentAuthorId = parent.author_id; // We still want to notify the specific user we @mentioned
 					} else {
							// Normal Level 2 reply
							originalParentAuthorId = parent.author_id;
 					}
					}
				}

				const storedContent = rewriteMarkdownImageRefsToStoredForm(content, env as unknown as S3Env);

				const { success } = await env.forum_db.prepare(
					'INSERT INTO comments (post_id, author_id, content, parent_id) VALUES (?, ?, ?, ?)'
				).bind(postId, userPayload.id, storedContent, parent_id || null).run();

				await security.logAudit(userPayload.id, 'CREATE_COMMENT', 'comment', 'new', { postId, parent_id }, request);

				// Email Notification Logic
				if (success) {
					// 1. Notify Post Author
					const post = await env.forum_db.prepare(
						'SELECT posts.title, users.id as author_id, users.email, users.email_notifications, users.username FROM posts JOIN users ON posts.author_id = users.id WHERE posts.id = ?'
					).bind(postId).first();

					// Fetch commenter name
					const commenter = await env.forum_db.prepare('SELECT username FROM users WHERE id = ?').bind(userPayload.id).first();
					const commenterName = commenter.username;
					const postUrl = `https://2x.nz/forum/post/?id=${postId}`;

					// Notify Post Author (if not self)
					if (post && post.author_id !== userPayload.id && post.email_notifications === 1) {
						ctx.waitUntil(sendEmailByTemplate(post.email, 'post_new_comment', {
							commenterName,
							postTitle: post.title,
							commentContent: rewriteMarkdownImageRefsToPublicUrl(storedContent, env as unknown as S3Env),
							postUrl
 					}).catch(console.error));
					}

					// 2. Notify Parent Comment Author (if replying to a comment)
					if (parent_id || originalParentAuthorId) {
						// Determine who to notify:
						// If originalParentAuthorId is set, it means we flattened a Level 3 reply and should notify that specific user.
						// Otherwise, notify the direct parent (Level 1).
						
						const notifyUserId = originalParentAuthorId || (
							parent_id ? (await env.forum_db.prepare('SELECT author_id FROM comments WHERE id = ?').bind(parent_id).first())?.author_id : null
						);

						if (notifyUserId) {
							const parentCommentUser = await env.forum_db.prepare(
								'SELECT email, email_notifications, username FROM users WHERE id = ?'
							).bind(notifyUserId).first();

							if (parentCommentUser && notifyUserId !== userPayload.id && parentCommentUser.email_notifications === 1) {
								// Avoid double notification if parent author is also post author (already handled above)
								if (notifyUserId !== post.author_id) {
									ctx.waitUntil(sendEmailByTemplate(parentCommentUser.email, 'comment_new_reply', {
										commenterName,
										postTitle: post.title,
										replyContent: rewriteMarkdownImageRefsToPublicUrl(storedContent, env as unknown as S3Env),
										postUrl
									}).catch(console.error));
								}
							}
 					}
					}

					// WebSocket broadcast for real-time updates via Durable Object
					const wsId = env.WS_MANAGER.idFromName(String(postId));
					const wsStub = env.WS_MANAGER.get(wsId);
					ctx.waitUntil(wsStub.fetch(new Request('http://internal/broadcast', {
						method: 'POST',
						body: JSON.stringify({
							postId: String(postId),
							message: {
								type: 'new_comment',
								payload: {
									postId: postId,
									comment: {
										content: rewriteMarkdownImageRefsToPublicUrl(storedContent, env as unknown as S3Env),
										author_name: commenterName,
										author_id: userPayload.id,
										parent_id: parent_id || null,
										created_at: new Date().toISOString()
									}
								}
							}
 					})
					})).catch(console.error));
				}

				return jsonResponse({ success }, 201);
			} catch (e) {
				return handleError(e);
			}
		}

		// DELETE /api/comments/:id
		if (url.pathname.match(/^\/api\/comments\/\d+$/) && method === 'DELETE') {
			const id = url.pathname.split('/').pop();
			try {
				const userPayload = await authenticate(request);
				
				// Fetch comment to check ownership
				const comment = await env.forum_db.prepare('SELECT author_id FROM comments WHERE id = ?').bind(id).first();
				
				if (!comment) return jsonResponse({ error: 'Comment not found' }, 404);

				// Allow deletion if user is author OR admin
				if (comment.author_id !== userPayload.id && userPayload.role !== 'admin') {
					return jsonResponse({ error: 'Unauthorized' }, 403);
				}

				// Delete comment likes for the comment and its direct children before deleting comments
				await env.forum_db.prepare('DELETE FROM comment_likes WHERE comment_id IN (SELECT id FROM comments WHERE parent_id = ?)').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comment_likes WHERE comment_id = ?').bind(id).run();

				// Delete the comment AND its children (orphans prevention)
				await env.forum_db.prepare('DELETE FROM comments WHERE parent_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comments WHERE id = ?').bind(id).run();
				
				await security.logAudit(userPayload.id, 'DELETE_COMMENT', 'comment', id, {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/comments/:id/like
		if (url.pathname.match(/^\/api\/comments\/\d+\/like$/) && method === 'POST') {
			const commentId = url.pathname.split('/')[3];
			try {
				const userPayload = await authenticate(request);
				const userId = userPayload.id;

				const comment = await env.forum_db.prepare('SELECT id FROM comments WHERE id = ?').bind(commentId).first();
				if (!comment) return jsonResponse({ error: 'Comment not found' }, 404);

				const existing = await env.forum_db.prepare(
					'SELECT id FROM comment_likes WHERE comment_id = ? AND user_id = ?'
				).bind(commentId, userId).first();

				if (existing) {
					await env.forum_db.prepare('DELETE FROM comment_likes WHERE id = ?').bind(existing.id).run();
					return jsonResponse({ liked: false });
				} else {
					await env.forum_db.prepare('INSERT INTO comment_likes (comment_id, user_id) VALUES (?, ?)').bind(commentId, userId).run();
					return jsonResponse({ liked: true });
				}
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/posts/:id/like
		if (url.pathname.match(/^\/api\/posts\/\d+\/like$/) && method === 'POST') {
			const postId = url.pathname.split('/')[3];
			try {
				const userPayload = await authenticate(request);
				const userId = userPayload.id;

				// Toggle like
				const existing = await env.forum_db.prepare(
					'SELECT id FROM likes WHERE post_id = ? AND user_id = ?'
				).bind(postId, userId).first();

				if (existing) {
					await env.forum_db.prepare('DELETE FROM likes WHERE id = ?').bind(existing.id).run();
					return jsonResponse({ liked: false });
				} else {
					await env.forum_db.prepare('INSERT INTO likes (post_id, user_id) VALUES (?, ?)').bind(postId, userId).run();
					return jsonResponse({ liked: true });
				}
			} catch (e) {
				return handleError(e);
			}
		}
		
		// GET /api/posts/:id/like-status
		if (url.pathname.match(/^\/api\/posts\/\d+\/like-status$/) && method === 'GET') {
			const postId = url.pathname.split('/')[3];
			
			try {
				const userPayload = await authenticate(request);
				const existing = await env.forum_db.prepare(
					'SELECT id FROM likes WHERE post_id = ? AND user_id = ?'
				).bind(postId, userPayload.id).first();
				return jsonResponse({ liked: !!existing });
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /posts (Protected - in real app check token)
		if (url.pathname === '/api/posts' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;

				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				if (!(await checkTurnstile(body, ip))) {
					return jsonResponse({ error: 'Turnstile verification failed' }, 403);
				}

				const { title, content: rawContent, category_id } = body;
				let content = rawContent;
				
				if (!title || !content) {
					return jsonResponse({ error: 'Missing title or content' }, 400);
				}
				
				// --- Input Sanitization & Validation (Sync with Frontend) ---
				if (isVisuallyEmpty(title) || isVisuallyEmpty(content)) return jsonResponse({ error: 'Title or content cannot be empty' }, 400);
				
				if (hasInvisibleCharacters(title) || hasInvisibleCharacters(content)) return jsonResponse({ error: 'Title or content contains invalid invisible characters' }, 400);

				// Validate Lengths
				if (title.length > 30) return jsonResponse({ error: 'Title too long (Max 30 chars)' }, 400);
				if (content.length > 3000) return jsonResponse({ error: 'Content too long (Max 3000 chars)' }, 400);

				if (hasControlCharacters(title) || hasControlCharacters(content)) return jsonResponse({ error: 'Title or content contains invalid control characters' }, 400);

				// HTML Escape Content (Backend Enforcement)
				content = content
					.replace(/&/g, '&amp;')
					.replace(/</g, '&lt;')
					.replace(/>/g, '&gt;')
					.replace(/"/g, '&quot;')
					.replace(/'/g, '&#039;');
				
				// Escape Title as well just in case
				const safeTitle = title
					.replace(/&/g, '&amp;')
					.replace(/</g, '&lt;')
					.replace(/>/g, '&gt;')
					.replace(/"/g, '&quot;')
					.replace(/'/g, '&#039;');

				// Validate Category
				if (category_id) {
					const category = await env.forum_db.prepare('SELECT id FROM categories WHERE id = ?').bind(category_id).first();
					if (!category) return jsonResponse({ error: 'Category not found' }, 400);
				}

				const storedContent = rewriteMarkdownImageRefsToStoredForm(content.trim(), env as unknown as S3Env);

				const { success, meta } = await env.forum_db.prepare(
					'INSERT INTO posts (author_id, title, content, category_id) VALUES (?, ?, ?, ?)'
				).bind(userPayload.id, safeTitle.trim(), storedContent, category_id || null).run();
				const postId = Number(meta?.last_row_id || 0) || null;

				await security.logAudit(userPayload.id, 'CREATE_POST', 'post', String(postId || 'new'), { title_length: safeTitle.length }, request);

				return jsonResponse({ success, id: postId }, 201);
			} catch (e) {
				return handleError(e);
			}
		}

		// POST /api/webhook/posts (Blog post notification from blog-post plugin)
		if (url.pathname === '/api/webhook/posts' && method === 'POST') {
			try {
				const WEBHOOK_SECRET = env.BLOG_WEBHOOK_SECRET || 'hfp9yf934oufhgp439gh478o3ghriwue4';

				// Verify secret header
				const receivedSecret = request.headers.get('X-Webhook-Secret') || '';
				if (receivedSecret !== WEBHOOK_SECRET) {
					return jsonResponse({ error: 'Invalid secret' }, 401);
				}

				const body = await request.json() as any;

				// Validate source
				if (body.source !== 'blog-post-plugin') {
					return jsonResponse({ error: 'Invalid source' }, 400);
				}

				const postUrls = body.post_urls as string[];
				const summaries = body.summaries as string[];

				// Build email content
				const articleLinks = postUrls.length > 0
					? postUrls.map(url => `<a href="${escapeHtml(url)}">${escapeHtml(url)}</a>`).join('<br>')
					: '<a href="https://2x.nz">查看博客</a>';

				const summary = summaries.length > 0 ? summaries.join('；') : '博客更新';

				// Send emails immediately
				const users = await env.forum_db.prepare(
					'SELECT email FROM users WHERE verified = 1 AND article_notifications = 1'
				).all<{ email: string }>();

				if (users.results && users.results.length > 0) {
					for (const user of users.results) {
						ctx.waitUntil(
							sendEmailByTemplate(user.email, 'article_update', {
								summary,
								articleLinks
							}).catch(e => console.error(`Failed to send email to ${user.email}:`, e))
						);
					}
				}

				return jsonResponse({ status: 'ok', received: postUrls.length, sent: users.results?.length || 0 });
			} catch (e) {
				return handleError(e);
			}
		}

		// GET /api/subscriptions/article-notifications
		if (url.pathname === '/api/subscriptions/article-notifications' && method === 'GET') {
			try {
				const result = await env.forum_db.prepare(
					'SELECT COUNT(*) as count FROM users WHERE verified = 1 AND article_notifications = 1'
				).first();

				return jsonResponse({ count: result?.count || 0 });
			} catch (e) {
				return handleError(e);
			}
		}

		// ============== AI Draw Proxy (d.2x.nz) ==============
		const DRAW_BACKEND = 'https://d.2x.nz';
		const DRAW_ACCESS_CLIENT_ID = '6864bbcb13aa07d0f6f51233acdc9ad8.access';
		const DRAW_ACCESS_CLIENT_SECRET = (env as any).AI_DRAW_ACCESS || '';

		// WebSocket proxy for /api/draw/ws/* via Durable Object
		if (url.pathname.startsWith('/api/draw/ws/') && request.headers.get('Upgrade') === 'websocket') {
			let userPayload: UserPayload;
			try {
				userPayload = await authenticate(request);
			} catch {
				const wsToken = url.searchParams.get('token');
				if (!wsToken) return jsonResponse({ error: 'Unauthorized' }, 401);
				const payload = await security.verifyToken(wsToken);
				if (!payload) return jsonResponse({ error: 'Invalid Token' }, 401);
				userPayload = payload;
			}

			const drawUser = await env.forum_db.prepare(
				'SELECT username, draw_banned FROM users WHERE id = ?'
			).bind(userPayload.id).first();
			const creatorName = (drawUser?.username as string) || userPayload.email || 'unknown';

			if (drawUser && drawUser.draw_banned) {
				const [client, server] = Object.values(new WebSocketPair());
				server.accept();
				server.send(JSON.stringify({ type: 'error', message: '你已被禁止使用生图功能', banned: true }));
				server.close(1008, 'draw banned');
				return new Response(null, { status: 101, webSocket: client });
			}

			const backendPath = url.pathname.replace('/api/draw/ws/', '/ws/');

			if (backendPath === '/ws/run' && userPayload.role !== 'admin') {
				const cooldownSeconds = await getDrawCooldownSeconds();
				if (cooldownSeconds > 0) {
					const now = Math.floor(Date.now() / 1000);
					const row = await env.forum_db.prepare(
						'SELECT last_at FROM draw_rate_limits WHERE user_id = ?'
					).bind(userPayload.id).first();
					const lastAt = row ? Number(row.last_at) : 0;
					const remaining = cooldownSeconds - (now - lastAt);
					if (remaining > 0) {
						const [client, server] = Object.values(new WebSocketPair());
						server.accept();
						server.send(JSON.stringify({ type: 'error', message: `生图冷却中，请等待 ${remaining} 秒后再试`, cooldown: true, remaining }));
						server.close(1008, 'rate limited');
						return new Response(null, { status: 101, webSocket: client });
					}
					await env.forum_db.prepare(
						'INSERT OR REPLACE INTO draw_rate_limits (user_id, last_at) VALUES (?, ?)'
					).bind(userPayload.id, now).run();
				}
			}

			const cleanParams = new URLSearchParams(url.search);
			cleanParams.delete('token');
			const qs = cleanParams.toString();
			const backendWsUrl = `${DRAW_BACKEND.replace('https:', 'wss:').replace('http:', 'ws:')}${backendPath}${qs ? '?' + qs : ''}`;

			const doId = (env as any).DRAW_WS_PROXY.newUniqueId();
			const stub = (env as any).DRAW_WS_PROXY.get(doId);
			const doUrl = new URL('https://do/websocket');
			doUrl.searchParams.set('backendUrl', backendWsUrl);
			doUrl.searchParams.set('accessClientId', DRAW_ACCESS_CLIENT_ID);
			doUrl.searchParams.set('accessClientSecret', DRAW_ACCESS_CLIENT_SECRET);
			doUrl.searchParams.set('creatorName', creatorName);

			return stub.fetch(doUrl.toString(), {
				headers: { Upgrade: 'websocket' },
			});
		}

		// Diagnostic endpoint for AI Draw proxy
		if (url.pathname === '/api/draw/debug' && method === 'GET') {
			try {
				await authenticate(request);
			} catch {
				return jsonResponse({ error: 'Unauthorized' }, 401);
			}
			const testUrl = `${DRAW_BACKEND}/api/workflows`;
			const hasSecret = !!DRAW_ACCESS_CLIENT_SECRET;
			const secretLen = DRAW_ACCESS_CLIENT_SECRET.length;
			const secretPrefix = DRAW_ACCESS_CLIENT_SECRET.slice(0, 4);
			const diag: Record<string, unknown> = {
				draw_backend: DRAW_BACKEND,
				test_url: testUrl,
				client_id: DRAW_ACCESS_CLIENT_ID,
				secret_configured: hasSecret,
				secret_length: secretLen,
				secret_prefix: secretPrefix + '...',
			};
			try {
				const resp = await fetch(testUrl, {
					headers: {
						'CF-Access-Client-Id': DRAW_ACCESS_CLIENT_ID,
						'CF-Access-Client-Secret': DRAW_ACCESS_CLIENT_SECRET,
					},
				});
				const body = await resp.text();
				diag.upstream_status = resp.status;
				diag.upstream_status_text = resp.statusText;
				diag.upstream_content_type = resp.headers.get('content-type');
				diag.upstream_cf_ray = resp.headers.get('cf-ray');
				diag.upstream_server = resp.headers.get('server');
				diag.upstream_body_preview = body.slice(0, 500);
				const respHeaders: Record<string, string> = {};
				resp.headers.forEach((v, k) => { respHeaders[k] = v; });
				diag.upstream_headers = respHeaders;
			} catch (e) {
				diag.upstream_error = String(e);
			}

			// Also test WebSocket reachability via HTTP
			const wsTestUrl = `${DRAW_BACKEND}/ws/status`;
			try {
				const resp2 = await fetch(wsTestUrl, {
					headers: {
						'CF-Access-Client-Id': DRAW_ACCESS_CLIENT_ID,
						'CF-Access-Client-Secret': DRAW_ACCESS_CLIENT_SECRET,
					},
				});
				diag.ws_http_status = resp2.status;
				diag.ws_http_body_preview = (await resp2.text()).slice(0, 200);
			} catch (e) {
				diag.ws_http_error = String(e);
			}

			return jsonResponse(diag);
		}

		// HTTP proxy for /api/draw/*
		if (url.pathname.startsWith('/api/draw/')) {
			let httpUserPayload: UserPayload;
			try {
				httpUserPayload = await authenticate(request);
			} catch {
				const qToken = url.searchParams.get('token');
				if (!qToken) return jsonResponse({ error: 'Unauthorized' }, 401);
				const payload = await security.verifyToken(qToken);
				if (!payload) return jsonResponse({ error: 'Invalid Token' }, 401);
				httpUserPayload = payload;
			}

			const httpDrawUser = await env.forum_db.prepare(
				'SELECT username, draw_banned FROM users WHERE id = ?'
			).bind(httpUserPayload.id).first();
			if (httpDrawUser && httpDrawUser.draw_banned) {
				return jsonResponse({ error: '你已被禁止使用生图功能' }, 403);
			}
			const httpCreatorName = (httpDrawUser?.username as string) || httpUserPayload.email || 'unknown';

			const cleanParams = new URLSearchParams(url.search);
			cleanParams.delete('token');
			const qs = cleanParams.toString();
			const backendPath = url.pathname.replace('/api/draw', '');
			const backendUrl = `${DRAW_BACKEND}${backendPath}${qs ? '?' + qs : ''}`;

			const proxyHeaders = new Headers();
			const contentType = request.headers.get('Content-Type');
			if (contentType) proxyHeaders.set('Content-Type', contentType);
			const accept = request.headers.get('Accept');
			if (accept) proxyHeaders.set('Accept', accept);
			proxyHeaders.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP') || '');
			proxyHeaders.set('CF-Access-Client-Id', DRAW_ACCESS_CLIENT_ID);
			proxyHeaders.set('CF-Access-Client-Secret', DRAW_ACCESS_CLIENT_SECRET);
			proxyHeaders.set('X-Creator-Name', httpCreatorName);

			const proxyInit: RequestInit = {
				method: request.method,
				headers: proxyHeaders,
			};
			if (['POST', 'PUT', 'PATCH'].includes(method)) {
				proxyInit.body = request.body;
			}

			try {
				const upstream = await fetch(backendUrl, proxyInit);
				const respHeaders = new Headers(upstream.headers);
				for (const [k, v] of Object.entries(corsHeaders)) {
					respHeaders.set(k, v);
				}
				return new Response(upstream.body, {
					status: upstream.status,
					headers: respHeaders,
				});
			} catch (e) {
				return jsonResponse({ error: 'Draw backend unreachable', detail: String(e) }, 502);
			}
		}

		if (!url.pathname.startsWith('/api')) {
			return textResponse('Not Found', 404);
		}

		return textResponse('Not Found', 404);
	},
} satisfies ExportedHandler<Env>;
