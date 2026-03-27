import * as React from 'react';
import { RefreshCw, Shield, User as UserIcon } from 'lucide-react';

import { PageShell } from '@/components/page-shell';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import {
	adminTestEmail,
	apiFetch,
	getSecurityHeaders,
	type AdminEmailTestResult,
	type Category
} from '@/lib/api';
import { getToken, getUser } from '@/lib/auth';

type EmailTemplateField = {
	key: string;
	label: string;
	placeholder: string;
};

type EmailTemplateOption = {
	key: string;
	label: string;
	fields: EmailTemplateField[];
};

const EMAIL_TEMPLATE_OPTIONS: EmailTemplateOption[] = [
	{ key: 'smtp_test', label: 'SMTP 测试邮件', fields: [] },
	{ key: 'reset_password', label: '密码重置邮件', fields: [{ key: 'resetLink', label: '重置链接', placeholder: 'https://example.com/reset?token=test' }] },
	{
		key: 'change_email_confirm',
		label: '更换邮箱确认邮件',
		fields: [
			{ key: 'newEmail', label: '新邮箱', placeholder: 'new-email@example.com' },
			{ key: 'verifyLink', label: '确认链接', placeholder: 'https://example.com/api/verify-email-change?token=test' }
		]
	},
	{
		key: 'register_verify',
		label: '注册验证邮件',
		fields: [
			{ key: 'username', label: '用户名', placeholder: '测试用户' },
			{ key: 'verifyLink', label: '验证链接', placeholder: 'https://example.com/api/verify?token=test' }
		]
	},
	{
		key: 'admin_resend_verify',
		label: '后台重发验证邮件',
		fields: [
			{ key: 'username', label: '用户名', placeholder: '测试用户' },
			{ key: 'verifyLink', label: '验证链接', placeholder: 'https://example.com/api/verify?token=test' }
		]
	},
	{ key: 'admin_avatar_updated', label: '后台头像更新通知', fields: [] },
	{ key: 'admin_username_updated', label: '后台用户名更新通知', fields: [{ key: 'username', label: '用户名', placeholder: '测试用户' }] },
	{ key: 'admin_manual_verified', label: '后台手动验证通知', fields: [{ key: 'username', label: '用户名', placeholder: '测试用户' }] },
	{ key: 'admin_account_deleted', label: '后台删号通知', fields: [{ key: 'username', label: '用户名', placeholder: '测试用户' }] },
	{
		key: 'post_new_comment',
		label: '帖子新评论提醒',
		fields: [
			{ key: 'commenterName', label: '评论者', placeholder: '测试评论者' },
			{ key: 'postTitle', label: '帖子标题', placeholder: '示例帖子标题' },
			{ key: 'commentContent', label: '评论内容', placeholder: '这是一条用于测试的新评论内容。' },
			{ key: 'postUrl', label: '帖子链接', placeholder: 'https://example.com/post?id=1' }
		]
	},
	{
		key: 'comment_new_reply',
		label: '评论新回复提醒',
		fields: [
			{ key: 'commenterName', label: '回复者', placeholder: '测试评论者' },
			{ key: 'postTitle', label: '帖子标题', placeholder: '示例帖子标题' },
			{ key: 'replyContent', label: '回复内容', placeholder: '这是一条用于测试的新回复内容。' },
			{ key: 'postUrl', label: '帖子链接', placeholder: 'https://example.com/post?id=1' }
		]
	}
];

const EMAIL_TEMPLATE_MAP = Object.fromEntries(EMAIL_TEMPLATE_OPTIONS.map((item) => [item.key, item]));

export function AdminPage() {
	const token = getToken();
	const user = React.useMemo(() => getUser(), [token]);
	const isAdmin = user?.role === 'admin';
	const [error, setError] = React.useState('');
	const [loading, setLoading] = React.useState(false);

	const [stats, setStats] = React.useState<{ users: number; posts: number; comments: number } | null>(null);
	const [users, setUsers] = React.useState<
		Array<{ id: number; email: string; username: string; role: string; verified: number; created_at: string; avatar_url?: string | null }>
	>([]);
	const [categories, setCategories] = React.useState<Category[]>([]);
	const [systemSettings, setSystemSettings] = React.useState({
		turnstile_enabled: false,
		notify_on_user_delete: false,
		notify_on_username_change: false,
		notify_on_avatar_change: false,
		notify_on_manual_verify: false,
		session_ttl_days: '7'
	});

	const [newCategoryName, setNewCategoryName] = React.useState('');
	const [editingCategoryId, setEditingCategoryId] = React.useState<number | null>(null);
	const [editingCategoryName, setEditingCategoryName] = React.useState('');

	const [editOpen, setEditOpen] = React.useState(false);
	const [editUserId, setEditUserId] = React.useState<number | null>(null);
	const [editEmail, setEditEmail] = React.useState('');
	const [editUsername, setEditUsername] = React.useState('');
	const [editAvatarUrl, setEditAvatarUrl] = React.useState('');
	const [editPassword, setEditPassword] = React.useState('');
	const [emailTestTo, setEmailTestTo] = React.useState('');
	const [emailTemplate, setEmailTemplate] = React.useState('smtp_test');
	const [emailTemplateFields, setEmailTemplateFields] = React.useState<Record<string, string>>({});
	const [emailTesting, setEmailTesting] = React.useState(false);
	const [emailTestResults, setEmailTestResults] = React.useState<AdminEmailTestResult[]>([]);
	const [emailTestError, setEmailTestError] = React.useState('');
	const [sendAllConfirmOpen, setSendAllConfirmOpen] = React.useState(false);

	React.useEffect(() => {
		if (!token) window.location.href = '/login';
	}, [token]);

	React.useEffect(() => {
		if (token && !isAdmin) setError('无权限访问管理后台');
	}, [token, isAdmin]);

	const selectedEmailTemplate = EMAIL_TEMPLATE_MAP[emailTemplate] ?? EMAIL_TEMPLATE_OPTIONS[0];

	const refresh = React.useCallback(async () => {
		if (!isAdmin) return;
		setLoading(true);
		setError('');
		try {
			const [s, u, c, settings] = await Promise.all([
				apiFetch<{ users: number; posts: number; comments: number }>('/admin/stats', { headers: getSecurityHeaders('GET') }),
				apiFetch<any[]>('/admin/users', { headers: getSecurityHeaders('GET') }),
				apiFetch<Category[]>('/categories'),
				apiFetch<any>('/admin/settings', { headers: getSecurityHeaders('GET') })
			]);
			setStats(s);
			setUsers(u as any);
			setCategories(c);
			setSystemSettings({
				turnstile_enabled: !!settings.turnstile_enabled,
				notify_on_user_delete: !!settings.notify_on_user_delete,
				notify_on_username_change: !!settings.notify_on_username_change,
				notify_on_avatar_change: !!settings.notify_on_avatar_change,
				notify_on_manual_verify: !!settings.notify_on_manual_verify,
				session_ttl_days: String(settings.session_ttl_days ?? 7)
			});
		} catch (e: any) {
			setError(String(e?.message || e));
		} finally {
			setLoading(false);
		}
	}, [isAdmin]);

	React.useEffect(() => {
		refresh();
	}, [refresh]);

	async function saveSettings() {
		if (!isAdmin) return;
		setLoading(true);
		setError('');
		try {
			const sessionTtlDays = Number.parseInt(systemSettings.session_ttl_days, 10);
			if (!Number.isInteger(sessionTtlDays)) {
				throw new Error('登录态有效天数必须为整数');
			}
			if (sessionTtlDays < 1 || sessionTtlDays > 365) {
				throw new Error('登录态有效天数必须在 1 到 365 之间');
			}
			await apiFetch('/admin/settings', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({
					...systemSettings,
					session_ttl_days: sessionTtlDays
				})
			});
			alert('设置已保存');
		} catch (e: any) {
			setError(String(e?.message || e));
		} finally {
			setLoading(false);
		}
	}

	async function createCategory() {
		if (!isAdmin) return;
		if (!newCategoryName) return;
		setLoading(true);
		setError('');
		try {
			await apiFetch('/admin/categories', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ name: newCategoryName })
			});
			setNewCategoryName('');
			await refresh();
		} catch (e: any) {
			setError(String(e?.message || e));
		} finally {
			setLoading(false);
		}
	}

	async function updateCategory(id: number) {
		if (!isAdmin) return;
		if (!editingCategoryName) return;
		setLoading(true);
		setError('');
		try {
			await apiFetch(`/admin/categories/${id}`, {
				method: 'PUT',
				headers: getSecurityHeaders('PUT'),
				body: JSON.stringify({ name: editingCategoryName })
			});
			setEditingCategoryId(null);
			setEditingCategoryName('');
			await refresh();
		} catch (e: any) {
			setError(String(e?.message || e));
		} finally {
			setLoading(false);
		}
	}

	async function deleteCategory(id: number) {
		if (!confirm('确定删除此分类？')) return;
		setLoading(true);
		setError('');
		try {
			await apiFetch(`/admin/categories/${id}`, { method: 'DELETE', headers: getSecurityHeaders('DELETE') });
			await refresh();
		} catch (e: any) {
			setError(String(e?.message || e));
		} finally {
			setLoading(false);
		}
	}

	function openEdit(u: any) {
		setEditUserId(u.id);
		setEditEmail(u.email || '');
		setEditUsername(u.username || '');
		setEditAvatarUrl(u.avatar_url || '');
		setEditPassword('');
		setEditOpen(true);
	}

	async function saveEdit() {
		if (!editUserId) return;
		setLoading(true);
		setError('');
		try {
			await apiFetch(`/admin/users/${editUserId}/update`, {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({
					email: editEmail || undefined,
					username: editUsername || undefined,
					avatar_url: editAvatarUrl,
					password: editPassword || undefined
				})
			});
			setEditOpen(false);
			await refresh();
		} catch (e: any) {
			setError(String(e?.message || e));
		} finally {
			setLoading(false);
		}
	}

	async function deleteUser(id: number) {
		if (!confirm('确定删除此用户？')) return;
		setLoading(true);
		setError('');
		try {
			await apiFetch(`/admin/users/${id}`, { method: 'DELETE', headers: getSecurityHeaders('DELETE') });
			await refresh();
		} catch (e: any) {
			setError(String(e?.message || e));
		} finally {
			setLoading(false);
		}
	}

	async function manualVerify(id: number) {
		if (!confirm('确认手动验证此用户？')) return;
		setLoading(true);
		setError('');
		try {
			await apiFetch(`/admin/users/${id}/verify`, { method: 'POST', headers: getSecurityHeaders('POST'), body: JSON.stringify({}) });
			await refresh();
		} catch (e: any) {
			setError(String(e?.message || e));
		} finally {
			setLoading(false);
		}
	}

	async function resendEmail(id: number) {
		if (!confirm('重新发送验证邮件？')) return;
		setLoading(true);
		setError('');
		try {
			await apiFetch(`/admin/users/${id}/resend`, { method: 'POST', headers: getSecurityHeaders('POST'), body: JSON.stringify({}) });
			alert('已发送');
		} catch (e: any) {
			setError(String(e?.message || e));
		} finally {
			setLoading(false);
		}
	}

	function updateEmailTemplateField(key: string, value: string) {
		setEmailTemplateFields((current) => ({ ...current, [key]: value }));
	}

	async function submitEmailTest(template: string) {
		if (!isAdmin) return;
		setEmailTesting(true);
		setEmailTestError('');
		try {
			const response = await adminTestEmail({
				to: emailTestTo,
				template,
				payload: template === 'all' ? undefined : emailTemplateFields
			});
			setEmailTestResults(response.results);
		} catch (e: any) {
			setEmailTestResults([]);
			setEmailTestError(String(e?.message || e));
		} finally {
			setEmailTesting(false);
		}
	}

	async function sendCurrentTemplate() {
		await submitEmailTest(emailTemplate);
	}

	async function sendAllTemplates() {
		setSendAllConfirmOpen(false);
		await submitEmailTest('all');
	}

	return (
		<PageShell>
			<div className="space-y-6">
				<div className="flex items-center justify-between">
					<div>
						<h1 className="text-2xl font-semibold tracking-tight">管理后台</h1>
						<p className="text-sm text-muted-foreground">站点设置、分类与用户管理</p>
					</div>
					<Button variant="outline" onClick={refresh} disabled={loading}>
						<RefreshCw className="h-4 w-4" />
						<span className="sr-only">刷新</span>
					</Button>
				</div>

				{user?.role !== 'admin' ? (
					<Card>
						<CardContent className="py-6 text-sm text-muted-foreground">无权限访问</CardContent>
					</Card>
				) : (
					<>
						{error ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{error}</div> : null}

						<Card>
							<CardHeader>
								<CardTitle>统计</CardTitle>
							</CardHeader>
							<CardContent className="grid gap-4 sm:grid-cols-3">
								<div className="rounded-md border p-4">
									<div className="text-sm text-muted-foreground">用户</div>
									<div className="text-2xl font-semibold">{stats?.users ?? '-'}</div>
								</div>
								<div className="rounded-md border p-4">
									<div className="text-sm text-muted-foreground">帖子</div>
									<div className="text-2xl font-semibold">{stats?.posts ?? '-'}</div>
								</div>
								<div className="rounded-md border p-4">
									<div className="text-sm text-muted-foreground">评论</div>
									<div className="text-2xl font-semibold">{stats?.comments ?? '-'}</div>
								</div>
							</CardContent>
						</Card>

						<Card>
							<CardHeader>
								<CardTitle>站点设置</CardTitle>
							</CardHeader>
							<CardContent className="space-y-4">
								<label className="flex items-center gap-2 text-sm">
									<input
										type="checkbox"
										className="h-4 w-4"
										checked={systemSettings.turnstile_enabled}
										onChange={(e) => setSystemSettings((s) => ({ ...s, turnstile_enabled: e.target.checked }))}
									/>
									启用 Cloudflare Turnstile
								</label>
								<div className="grid gap-2">
									<Label htmlFor="session-ttl-days">登录态有效天数</Label>
									<Input
										id="session-ttl-days"
										type="number"
										min={1}
										max={365}
										step={1}
										value={systemSettings.session_ttl_days}
										onChange={(e) => setSystemSettings((s) => ({ ...s, session_ttl_days: e.target.value }))}
									/>
									<p className="text-xs text-muted-foreground">请输入 1 到 365 之间的整数天数。</p>
								</div>
								<Separator />
								<div className="grid gap-3 sm:grid-cols-2">
									<label className="flex items-center gap-2 text-sm">
										<input
											type="checkbox"
											className="h-4 w-4"
											checked={systemSettings.notify_on_user_delete}
											onChange={(e) => setSystemSettings((s) => ({ ...s, notify_on_user_delete: e.target.checked }))}
										/>
										删除账号时通知用户
									</label>
									<label className="flex items-center gap-2 text-sm">
										<input
											type="checkbox"
											className="h-4 w-4"
											checked={systemSettings.notify_on_username_change}
											onChange={(e) => setSystemSettings((s) => ({ ...s, notify_on_username_change: e.target.checked }))}
										/>
										修改用户名时通知用户
									</label>
									<label className="flex items-center gap-2 text-sm">
										<input
											type="checkbox"
											className="h-4 w-4"
											checked={systemSettings.notify_on_avatar_change}
											onChange={(e) => setSystemSettings((s) => ({ ...s, notify_on_avatar_change: e.target.checked }))}
										/>
										修改头像时通知用户
									</label>
									<label className="flex items-center gap-2 text-sm">
										<input
											type="checkbox"
											className="h-4 w-4"
											checked={systemSettings.notify_on_manual_verify}
											onChange={(e) => setSystemSettings((s) => ({ ...s, notify_on_manual_verify: e.target.checked }))}
										/>
										手动验证通过时通知用户
									</label>
								</div>
								<Button onClick={saveSettings} disabled={loading}>
									{loading ? '保存中...' : '保存设置'}
								</Button>
							</CardContent>
						</Card>

						<Card>
							<CardHeader>
								<CardTitle>发信测试</CardTitle>
							</CardHeader>
							<CardContent className="space-y-4">
								<div className="grid gap-2">
									<Label htmlFor="email-test-to">收件邮箱</Label>
									<Input
										id="email-test-to"
										type="email"
										value={emailTestTo}
										onChange={(e) => setEmailTestTo(e.target.value)}
										placeholder="name@example.com"
									/>
								</div>
								<div className="grid gap-2">
									<Label htmlFor="email-template">邮件模板</Label>
									<select
										id="email-template"
										className="h-10 rounded-md border border-input bg-background px-3 py-2 text-sm"
										value={emailTemplate}
										onChange={(e) => {
											setEmailTemplate(e.target.value);
											setEmailTestResults([]);
											setEmailTestError('');
										}}
									>
										{EMAIL_TEMPLATE_OPTIONS.map((option) => (
											<option key={option.key} value={option.key}>
												{option.label}
											</option>
										))}
									</select>
								</div>
								{selectedEmailTemplate.fields.length > 0 ? (
									<div className="grid gap-4 sm:grid-cols-2">
										{selectedEmailTemplate.fields.map((field) => (
											<div key={field.key} className="grid gap-2">
												<Label htmlFor={`email-field-${field.key}`}>{field.label}</Label>
												<Input
													id={`email-field-${field.key}`}
													value={emailTemplateFields[field.key] ?? ''}
													onChange={(e) => updateEmailTemplateField(field.key, e.target.value)}
													placeholder={field.placeholder}
												/>
											</div>
										))}
									</div>
								) : (
									<p className="text-sm text-muted-foreground">当前模板无需额外字段，后端会自动使用默认示例内容。</p>
								)}
								<div className="flex flex-wrap gap-2">
									<Button onClick={sendCurrentTemplate} disabled={loading || emailTesting}>
										{emailTesting ? '发送中...' : '发送当前模板'}
									</Button>
									<Button variant="outline" onClick={() => setSendAllConfirmOpen(true)} disabled={loading || emailTesting}>
										发送全部模板
									</Button>
								</div>
								{emailTestError ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{emailTestError}</div> : null}
								{emailTestResults.length > 0 ? (
									<div className="space-y-2 rounded-md border p-3">
										<div className="text-sm font-medium">发送结果</div>
										<div className="space-y-2 text-sm">
											{emailTestResults.map((result) => (
												<div key={result.template} className="rounded border p-2">
													<div className="font-medium">{result.label}</div>
													<div className={result.success ? 'text-emerald-600' : 'text-destructive'}>{result.success ? '发送成功' : `发送失败：${result.error || '未知错误'}`}</div>
												</div>
											))}
										</div>
									</div>
								) : null}
							</CardContent>
						</Card>

						<Card>
							<CardHeader>
								<CardTitle>分类管理</CardTitle>
							</CardHeader>
							<CardContent className="space-y-4">
								<div className="flex flex-wrap items-end gap-2">
									<div className="space-y-2">
										<Label htmlFor="cat-name">分类名称</Label>
										<Input id="cat-name" value={newCategoryName} onChange={(e) => setNewCategoryName(e.target.value)} />
									</div>
									<Button onClick={createCategory} disabled={loading}>
										添加
									</Button>
								</div>
								<div className="space-y-2">
									{categories.map((c) => (
										<div key={c.id} className="flex items-center justify-between rounded-md border p-3 text-sm">
											{editingCategoryId === c.id ? (
												<Input
													value={editingCategoryName}
													onChange={(e) => setEditingCategoryName(e.target.value)}
													className="h-9 max-w-xs"
												/>
											) : (
												<span>{c.name}</span>
											)}
											<div className="flex items-center gap-2">
												{editingCategoryId === c.id ? (
													<>
														<Button variant="outline" size="sm" disabled={loading} onClick={() => updateCategory(c.id)}>
															保存
														</Button>
														<Button
															variant="outline"
															size="sm"
															disabled={loading}
															onClick={() => {
																setEditingCategoryId(null);
																setEditingCategoryName('');
															}}
														>
															取消
														</Button>
													</>
												) : (
													<Button
														variant="outline"
														size="sm"
														onClick={() => {
															setEditingCategoryId(c.id);
															setEditingCategoryName(c.name);
														}}
													>
														编辑
													</Button>
												)}
												<Button variant="destructive" size="sm" onClick={() => deleteCategory(c.id)}>
													删除
												</Button>
											</div>
										</div>
									))}
									{categories.length === 0 ? <div className="text-sm text-muted-foreground">暂无分类</div> : null}
								</div>
							</CardContent>
						</Card>

						<Card>
							<CardHeader>
								<CardTitle>用户管理</CardTitle>
							</CardHeader>
							<CardContent className="space-y-3">
								<div className="overflow-x-auto rounded-md border">
									<table className="w-full text-sm">
										<thead className="bg-muted/30 text-left">
											<tr>
												<th className="px-3 py-2">ID</th>
												<th className="px-3 py-2">用户名</th>
												<th className="px-3 py-2">邮箱</th>
												<th className="px-3 py-2">角色</th>
												<th className="px-3 py-2">已验证</th>
												<th className="px-3 py-2">操作</th>
											</tr>
										</thead>
										<tbody>
											{users.map((u) => (
												<tr key={u.id} className="border-t">
													<td className="px-3 py-2">{u.id}</td>
													<td className="px-3 py-2">
														<span className="inline-flex items-center gap-2">
															{u.avatar_url ? (
																<img
																	src={u.avatar_url}
																	alt=""
																	className="h-6 w-6 rounded-full object-cover"
																	loading="lazy"
																	referrerPolicy="no-referrer"
																/>
															) : (
																<span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-muted text-[10px] text-muted-foreground">
																	<UserIcon className="h-4 w-4" />
																</span>
															)}
															<span>{u.username}</span>
															{u.role === 'admin' ? (
																<span className="inline-flex items-center gap-1 rounded border border-indigo-500/30 bg-indigo-500/10 px-1.5 py-0.5 text-[10px] font-medium text-indigo-700 dark:text-indigo-300">
																	<Shield className="h-3 w-3" />
																	<span className="sr-only">管理员</span>
																</span>
															) : null}
														</span>
													</td>
													<td className="px-3 py-2">{u.email}</td>
													<td className="px-3 py-2">{u.role}</td>
													<td className="px-3 py-2">{u.verified ? '是' : '否'}</td>
													<td className="px-3 py-2">
														<div className="flex flex-wrap gap-2">
															<Button
																variant="outline"
																size="sm"
																className="border-sky-500 text-sky-700 hover:bg-sky-50 hover:text-sky-800 dark:text-sky-400 dark:hover:bg-sky-950/40"
																onClick={() => openEdit(u)}
															>
																编辑
															</Button>
															{!u.verified ? (
																<>
																	<Button
																		variant="outline"
																		size="sm"
																		className="border-emerald-500 text-emerald-700 hover:bg-emerald-50 hover:text-emerald-800 dark:text-emerald-400 dark:hover:bg-emerald-950/40"
																		onClick={() => manualVerify(u.id)}
																	>
																		验证
																	</Button>
																	<Button
																		variant="outline"
																		size="sm"
																		className="border-amber-500 text-amber-800 hover:bg-amber-50 hover:text-amber-900 dark:text-amber-400 dark:hover:bg-amber-950/40"
																		onClick={() => resendEmail(u.id)}
																	>
																		重发
																	</Button>
																</>
															) : null}
															{user?.id !== u.id ? (
																<Button variant="destructive" size="sm" onClick={() => deleteUser(u.id)}>
																	删除
																</Button>
															) : null}
														</div>
													</td>
												</tr>
											))}
										</tbody>
									</table>
								</div>
							</CardContent>
						</Card>

						<Dialog open={sendAllConfirmOpen} onOpenChange={setSendAllConfirmOpen}>
							<DialogContent>
								<DialogHeader>
									<DialogTitle>确认发送全部模板</DialogTitle>
									<DialogDescription>这会向同一收件箱连续发送全部测试邮件模板，请确认目标邮箱可用于批量测试。</DialogDescription>
								</DialogHeader>
								<DialogFooter>
									<Button variant="outline" onClick={() => setSendAllConfirmOpen(false)}>
										取消
									</Button>
									<Button onClick={sendAllTemplates} disabled={emailTesting}>
										{emailTesting ? '发送中...' : '确认发送'}
									</Button>
								</DialogFooter>
							</DialogContent>
						</Dialog>

						<Dialog open={editOpen} onOpenChange={setEditOpen}>
							<DialogContent>
								<DialogHeader>
									<DialogTitle>编辑用户</DialogTitle>
									<DialogDescription>修改用户名/邮箱/头像/密码</DialogDescription>
								</DialogHeader>
								<div className="grid gap-4 py-4">
									<div className="grid gap-2">
										<Label htmlFor="edit-username">用户名</Label>
										<Input id="edit-username" value={editUsername} onChange={(e) => setEditUsername(e.target.value)} maxLength={20} />
									</div>
									<div className="grid gap-2">
										<Label htmlFor="edit-email">邮箱</Label>
										<Input id="edit-email" value={editEmail} onChange={(e) => setEditEmail(e.target.value)} type="email" />
									</div>
									<div className="grid gap-2">
										<Label htmlFor="edit-avatar">头像 URL</Label>
										<Input id="edit-avatar" value={editAvatarUrl} onChange={(e) => setEditAvatarUrl(e.target.value)} />
									</div>
									<div className="grid gap-2">
										<Label htmlFor="edit-password">新密码 (留空不变)</Label>
										<Input id="edit-password" value={editPassword} onChange={(e) => setEditPassword(e.target.value)} />
									</div>
								</div>
								<DialogFooter>
									<Button variant="outline" onClick={() => setEditOpen(false)}>
										取消
									</Button>
									<Button onClick={saveEdit} disabled={loading}>
										{loading ? '保存中...' : '保存'}
									</Button>
								</DialogFooter>
							</DialogContent>
						</Dialog>
					</>
				)}
			</div>
		</PageShell>
	);
}
