import { getToken, logout, type User } from '@/lib/auth';

export type ForumConfig = {
	turnstile_enabled: boolean;
	turnstile_site_key: string;
	home_intro_markdown: string;
	site_footer_markdown: string;
	user_count?: number;
};

export type AdminSettings = {
	turnstile_enabled: boolean;
	notify_on_user_delete: boolean;
	notify_on_username_change: boolean;
	notify_on_avatar_change: boolean;
	notify_on_manual_verify: boolean;
	session_ttl_days: number;
	home_intro_markdown: string;
	site_footer_markdown: string;
};

export type SessionInfo = {
	valid: boolean;
	user: {
		id: number;
		email: string;
		role: string;
	};
};

export type Category = {
	id: number;
	name: string;
	created_at: string;
};

export type AdminEmailTestResult = {
	template: string;
	label: string;
	success: boolean;
	error?: string;
};

export type AdminEmailTestRequest = {
	to: string;
	template: string;
	payload?: Record<string, string>;
};

export type AdminEmailTestResponse = {
	success: boolean;
	results: AdminEmailTestResult[];
};

export type Post = {
	id: number;
	author_id: number;
	title: string;
	content: string;
	category_id: number | null;
	category_name?: string | null;
	is_pinned?: number;
	view_count?: number;
	created_at: string;
	author_name?: string;
	author_avatar?: string | null;
	author_role?: 'admin' | 'user';
	like_count?: number;
	comment_count?: number;
	liked?: boolean;
};

export type Comment = {
	id: number;
	post_id: number;
	parent_id: number | null;
	author_id: number;
	username: string;
	avatar_url?: string | null;
	role?: 'admin' | 'user';
	content: string;
	is_pinned?: number;
	created_at: string;
	like_count?: number;
	liked?: boolean;
};

const API_BASE = '/api';

export function getSecurityHeaders(method: string, contentType: string | null = 'application/json') {
	const headers: Record<string, string> = {};
	const token = getToken();
	if (token) headers.Authorization = `Bearer ${token}`;
	if (['POST', 'PUT', 'DELETE'].includes(method.toUpperCase())) {
		headers['X-Timestamp'] = Math.floor(Date.now() / 1000).toString();
		headers['X-Nonce'] = crypto.randomUUID();
	}
	if (contentType) headers['Content-Type'] = contentType;
	return headers;
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
	const res = await fetch(`${API_BASE}${path}`, init);
	if (res.status === 401) {
		logout();
		throw new Error('登录已过期，请重新登录');
	}
	const text = await res.text();
	const data = text ? (JSON.parse(text) as any) : null;
	if (!res.ok) {
		throw new Error(data?.error || `请求失败 (${res.status})`);
	}
	return data as T;
}

export async function checkSession(): Promise<SessionInfo> {
	return apiFetch<SessionInfo>('/session', {
		headers: getSecurityHeaders('GET')
	});
}

export async function getCurrentUser(): Promise<User> {
	return apiFetch<User>('/user/me', {
		headers: getSecurityHeaders('GET')
	});
}

export async function adminTestEmail(payload: AdminEmailTestRequest): Promise<AdminEmailTestResponse> {
	return apiFetch<AdminEmailTestResponse>('/admin/email/test', {
		method: 'POST',
		headers: getSecurityHeaders('POST'),
		body: JSON.stringify(payload)
	});
}

export type TextInsertResult = {
	value: string;
	selectionStart: number;
	selectionEnd: number;
};

export type UploadPlaceholder = {
	token: string;
	markdown: string;
};

const UPLOAD_PLACEHOLDER_PREFIX = 'uploading:';
const UPLOAD_PLACEHOLDER_ALT = '上传中...';

export function insertTextAtSelection(value: string, selectionStart: number, selectionEnd: number, insertedText: string): TextInsertResult {
	const safeStart = Math.max(0, Math.min(selectionStart, value.length));
	const safeEnd = Math.max(safeStart, Math.min(selectionEnd, value.length));
	const selectedText = value.slice(safeStart, safeEnd);
	const before = value.slice(0, safeStart);
	const after = value.slice(safeEnd);

	let textToInsert = insertedText;
	if (!selectedText) {
		const needsLeadingBreak = safeStart > 0 && !before.endsWith('\n');
		const needsTrailingBreak = safeEnd < value.length && !after.startsWith('\n');
		if (needsLeadingBreak) textToInsert = `\n${textToInsert}`;
		if (needsTrailingBreak) textToInsert = `${textToInsert}\n`;
	}

	const nextValue = `${before}${textToInsert}${after}`;
	const nextSelection = before.length + textToInsert.length;
	return {
		value: nextValue,
		selectionStart: nextSelection,
		selectionEnd: nextSelection
	};
}

export function createImageUploadPlaceholder(): UploadPlaceholder {
	const token = crypto.randomUUID();
	return {
		token,
		markdown: getImageUploadPlaceholderMarkdown(token)
	};
}

export function getImageUploadPlaceholderMarkdown(token: string) {
	return `![${UPLOAD_PLACEHOLDER_ALT}](${UPLOAD_PLACEHOLDER_PREFIX}${token})`;
}

export function isImageUploadPlaceholderUrl(url: string) {
	return url.startsWith(UPLOAD_PLACEHOLDER_PREFIX);
}

export function extractImageUploadToken(url: string) {
	return isImageUploadPlaceholderUrl(url) ? url.slice(UPLOAD_PLACEHOLDER_PREFIX.length) : '';
}

export function insertImageUploadPlaceholder(value: string, selectionStart: number, selectionEnd: number, placeholder: UploadPlaceholder) {
	return insertTextAtSelection(value, selectionStart, selectionEnd, placeholder.markdown);
}

export function replaceImageUploadPlaceholder(value: string, token: string, nextMarkdown: string): TextInsertResult {
	const placeholder = getImageUploadPlaceholderMarkdown(token);
	const index = value.indexOf(placeholder);
	if (index === -1) {
		return {
			value,
			selectionStart: value.length,
			selectionEnd: value.length
		};
	}
	const nextValue = `${value.slice(0, index)}${nextMarkdown}${value.slice(index + placeholder.length)}`;
	const nextSelection = index + nextMarkdown.length;
	return {
		value: nextValue,
		selectionStart: nextSelection,
		selectionEnd: nextSelection
	};
}

export function removeImageUploadPlaceholder(value: string, token: string): TextInsertResult {
	return replaceImageUploadPlaceholder(value, token, '');
}

export function formatDate(dateString: string | null | undefined) {
	if (!dateString) return '';
	const date = new Date(dateString.endsWith('Z') ? dateString : `${dateString}Z`);
	return date.toLocaleString('zh-CN', {
		year: 'numeric',
		month: 'short',
		day: 'numeric',
		hour: '2-digit',
		minute: '2-digit'
	});
}
