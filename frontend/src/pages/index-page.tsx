import * as React from 'react';
import { ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Eye, Heart, MessageCircle, MoreVertical, Pin, RefreshCw, Search, Shield, Trash2, User, X } from 'lucide-react';

import MDEditor, { commands, type ICommand } from '@uiw/react-md-editor';
import { TurnstileWidget } from '@/components/turnstile';
import { PageShell } from '@/components/page-shell';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useConfig } from '@/hooks/use-config';
import { apiFetch, createImageUploadPlaceholder, formatDate, getSecurityHeaders, insertImageUploadPlaceholder, removeImageUploadPlaceholder, replaceImageUploadPlaceholder, type Category, type Post } from '@/lib/api';
import { getToken, getUser, logout } from '@/lib/auth';
import { renderMarkdownToHtml } from '@/lib/markdown';
import { validateText } from '@/lib/validators';

export function IndexPage() {
	const { config } = useConfig();
	const token = getToken();
	const user = React.useMemo(() => getUser(), [token]);
	const [banner, setBanner] = React.useState<string>('');
	const [categories, setCategories] = React.useState<Category[]>([]);
	const [selectedCategory, setSelectedCategory] = React.useState<string>('');
	const [searchInput, setSearchInput] = React.useState<string>('');
	const [searchQuery, setSearchQuery] = React.useState<string>('');
	const [posts, setPosts] = React.useState<Post[]>([]);
	const [totalPosts, setTotalPosts] = React.useState<number>(0);
	const [pageOffset, setPageOffset] = React.useState<number>(0);
	const [loading, setLoading] = React.useState<boolean>(true);
	const [error, setError] = React.useState<string>('');
	const pageLimit = 10;
	const [jumpTo, setJumpTo] = React.useState<string>('');

	const [newTitle, setNewTitle] = React.useState('');
	const [newContent, setNewContent] = React.useState('');
	const [newCategoryId, setNewCategoryId] = React.useState<string>('');
	const [createOpen, setCreateOpen] = React.useState(false);
	const [createLoading, setCreateLoading] = React.useState(false);
	const [createError, setCreateError] = React.useState('');
	const [turnstileToken, setTurnstileToken] = React.useState('');
	const [turnstileResetKey, setTurnstileResetKey] = React.useState(0);
	const [uploadingImage, setUploadingImage] = React.useState(false);
	const newContentSelectionRef = React.useRef<{ start: number; end: number } | null>(null);
	const newContentTextareaRef = React.useRef<HTMLTextAreaElement | null>(null);
	const newContentImageInputRef = React.useRef<HTMLInputElement | null>(null);
	const [adminMenuPostId, setAdminMenuPostId] = React.useState<number | null>(null);
	const [adminActionPostId, setAdminActionPostId] = React.useState<number | null>(null);
	const [sortOption, setSortOption] = React.useState('time_desc');
	const listTopRef = React.useRef<HTMLDivElement | null>(null);
	const lastOffsetRef = React.useRef<number | null>(null);

	const enabled = !!config?.turnstile_enabled;
	const siteKey = config?.turnstile_site_key || '';

	const fetchCategories = React.useCallback(async () => {
		try {
			const list = await apiFetch<Category[]>('/categories');
			setCategories(list);
		} catch {
			setCategories([]);
		}
	}, []);

	const fetchPosts = React.useCallback(
		async (offset: number) => {
			setLoading(true);
			setError('');
			try {
				const sortBy =
					sortOption === 'likes_desc'
						? 'likes'
						: sortOption === 'comments_desc'
							? 'comments'
							: sortOption === 'views_desc'
								? 'views'
								: 'time';
				const sortDir = sortOption === 'time_asc' ? 'asc' : 'desc';
				const categoryParam = selectedCategory ? `&category_id=${encodeURIComponent(selectedCategory)}` : '';
				const searchParam = searchQuery ? `&q=${encodeURIComponent(searchQuery)}` : '';
				const sortParam = `&sort_by=${encodeURIComponent(sortBy)}&sort_dir=${encodeURIComponent(sortDir)}`;
				const res = await fetch(`/api/posts?limit=${pageLimit}&offset=${offset}${categoryParam}${searchParam}${sortParam}`);
				if (!res.ok) throw new Error('加载帖子失败');
				const data = (await res.json()) as any;
				const list: Post[] = Array.isArray(data) ? data : (data.posts as Post[]);
				const total = Array.isArray(data) ? list.length : Number(data.total || 0);

				const processed = list.map((p) => ({
					...p,
					like_count: p.like_count || 0,
					comment_count: p.comment_count || 0
				}));

				setPosts(processed);
				setTotalPosts(total);
				setPageOffset(offset);
			} catch (e: any) {
				setError(String(e?.message || e));
			} finally {
				setLoading(false);
			}
		},
		[selectedCategory, searchQuery, sortOption]
	);

	React.useEffect(() => {
		fetchCategories();
	}, [fetchCategories]);

	React.useEffect(() => {
		fetchPosts(0);
	}, [fetchPosts]);

	React.useEffect(() => {
		const params = new URLSearchParams(window.location.search);
		if (params.get('verified') === 'true') {
			setBanner('邮箱验证成功，现在可以登录。');
			params.delete('verified');
			window.history.replaceState({}, document.title, `${window.location.pathname}${params.toString() ? `?${params.toString()}` : ''}`);
		} else if (params.get('email_changed') === 'true') {
			setBanner('邮箱更换成功。');
			params.delete('email_changed');
			window.history.replaceState({}, document.title, `${window.location.pathname}${params.toString() ? `?${params.toString()}` : ''}`);
		}
	}, []);

	React.useEffect(() => {
		if (adminMenuPostId == null) return;
		function close() {
			setAdminMenuPostId(null);
		}
		document.addEventListener('mousedown', close);
		document.addEventListener('touchstart', close);
		return () => {
			document.removeEventListener('mousedown', close);
			document.removeEventListener('touchstart', close);
		};
	}, [adminMenuPostId]);

	React.useEffect(() => {
		if (lastOffsetRef.current !== null && lastOffsetRef.current !== pageOffset && !loading) {
			listTopRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
		}
		lastOffsetRef.current = pageOffset;
	}, [pageOffset, loading]);

	async function adminTogglePin(post: Post) {
		if (!user || user.role !== 'admin') return;
		setAdminActionPostId(post.id);
		try {
			const next = !post.is_pinned;
			await apiFetch(`/admin/posts/${post.id}/pin`, {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ pinned: next })
			});
			setAdminMenuPostId(null);
			await fetchPosts(pageOffset);
		} catch {
			return;
		} finally {
			setAdminActionPostId(null);
		}
	}

	async function adminDeletePost(post: Post) {
		if (!user || user.role !== 'admin') return;
		if (!confirm('确定要删除这个帖子吗？此操作无法撤销。')) return;
		setAdminActionPostId(post.id);
		try {
			await apiFetch(`/admin/posts/${post.id}`, {
				method: 'DELETE',
				headers: getSecurityHeaders('DELETE')
			});
			setAdminMenuPostId(null);
			await fetchPosts(pageOffset);
		} catch {
			return;
		} finally {
			setAdminActionPostId(null);
		}
	}

	async function adminMovePost(post: Post, categoryId: number | null) {
		if (!user || user.role !== 'admin') return;
		setAdminActionPostId(post.id);
		try {
			await apiFetch(`/admin/posts/${post.id}/move`, {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ category_id: categoryId })
			});
			setAdminMenuPostId(null);
			await fetchPosts(pageOffset);
		} catch {
			return;
		} finally {
			setAdminActionPostId(null);
		}
	}

	async function uploadPostImage(file: File, selection = newContentSelectionRef.current) {
		if (!user) {
			window.location.href = '/login';
			return;
		}
		const token = getToken();
		if (!token) {
			setCreateError('登录已过期，请重新登录');
			return;
		}
		if (file.size > 500 * 1024) {
			setCreateError('文件过大 (最大 500KB)');
			return;
		}

		const placeholder = createImageUploadPlaceholder();
		let inserted = false;
		setCreateError('');
		setNewContent((prev) => {
			const insertion = insertImageUploadPlaceholder(prev, selection?.start ?? prev.length, selection?.end ?? prev.length, placeholder);
			newContentSelectionRef.current = { start: insertion.selectionStart, end: insertion.selectionEnd };
			inserted = true;
			return insertion.value;
		});
		if (!inserted) return;

		requestAnimationFrame(() => {
			const textarea = newContentTextareaRef.current;
			if (!textarea) return;
			const nextSelection = newContentSelectionRef.current;
			textarea.focus();
			if (nextSelection) textarea.setSelectionRange(nextSelection.start, nextSelection.end);
		});

		const formData = new FormData();
		formData.append('file', file);
		formData.append('type', 'post');
		formData.append('post_id', 'new');

		setUploadingImage(true);
		try {
			const headers = getSecurityHeaders('POST', null);
			const res = await fetch('/api/upload', {
				method: 'POST',
				headers,
				body: formData
			});
			if (res.status === 401) {
				logout();
				window.location.href = '/login';
				return;
			}
			const data = (await res.json()) as any;
			if (!res.ok) {
				throw new Error(data?.error || '上传失败');
			}
			const markdownImage = `![image](${data.url})`;
			let nextSelectionStart = 0;
			setNewContent((prev) => {
				const replacement = replaceImageUploadPlaceholder(prev, placeholder.token, markdownImage);
				nextSelectionStart = replacement.selectionStart;
				newContentSelectionRef.current = { start: replacement.selectionStart, end: replacement.selectionEnd };
				return replacement.value;
			});
			requestAnimationFrame(() => {
				const textarea = newContentTextareaRef.current;
				if (!textarea) return;
				textarea.focus();
				textarea.setSelectionRange(nextSelectionStart, nextSelectionStart);
			});
		} catch (e: any) {
			setNewContent((prev) => {
				const replacement = removeImageUploadPlaceholder(prev, placeholder.token);
				newContentSelectionRef.current = { start: replacement.selectionStart, end: replacement.selectionEnd };
				return replacement.value;
			});
			setCreateError(String(e?.message || e));
		} finally {
			setUploadingImage(false);
		}
	}

	async function createPost(e: React.FormEvent) {
		e.preventDefault();
		if (!user) {
			window.location.href = '/login';
			return;
		}

		setCreateError('');
		const titleErr = validateText(newTitle, '标题');
		if (titleErr) return setCreateError(titleErr);
		const contentErr = validateText(newContent, '内容');
		if (contentErr) return setCreateError(contentErr);
		if (newTitle.length > 30) return setCreateError('标题过长 (最多 30 字符)');
		if (newContent.length > 3000) return setCreateError('内容过长 (最多 3000 字符)');
		if (enabled && !turnstileToken) return setCreateError('请完成验证码验证');

		setCreateLoading(true);
		try {
			await apiFetch<{ success: boolean }>('/posts', {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({
					title: newTitle,
					content: newContent,
					category_id: newCategoryId ? Number(newCategoryId) : null,
					'cf-turnstile-response': turnstileToken
				})
			});
			setNewTitle('');
			setNewContent('');
			setNewCategoryId('');
			setTurnstileToken('');
			setTurnstileResetKey((v) => v + 1);
			setCreateOpen(false);
			await fetchPosts(0);
		} catch (e: any) {
			setCreateError(String(e?.message || e));
			setTurnstileToken('');
			setTurnstileResetKey((v) => v + 1);
		} finally {
			setCreateLoading(false);
		}
	}

	const currentPage = Math.floor(pageOffset / pageLimit) + 1;
	const totalPages = Math.max(1, Math.ceil(totalPosts / pageLimit));
	const pages: Array<number | 'ellipsis'> = [];
	if (totalPages <= 7) {
		for (let p = 1; p <= totalPages; p++) pages.push(p);
	} else {
		const start = Math.max(2, currentPage - 2);
		const end = Math.min(totalPages - 1, currentPage + 2);
		pages.push(1);
		if (start > 2) pages.push('ellipsis');
		for (let p = start; p <= end; p++) pages.push(p);
		if (end < totalPages - 1) pages.push('ellipsis');
		pages.push(totalPages);
	}

	function getCoverImageUrl(markdown: string) {
		const mdMatch = markdown.match(/!\[[^\]]*\]\((https?:\/\/[^)\s]+|\/[^)\s]+)\)/i);
		if (mdMatch?.[1]) return mdMatch[1];
		const htmlMatch = markdown.match(/<img[^>]+src=["']([^"']+)["']/i);
		return htmlMatch?.[1] || '';
	}

	function handleNewContentSelection(target: HTMLTextAreaElement) {
		newContentSelectionRef.current = {
			start: target.selectionStart ?? 0,
			end: target.selectionEnd ?? 0
		};
		newContentTextareaRef.current = target;
	}

	const editorCommands = React.useMemo<ICommand[]>(() => {
		const imageCommand: ICommand = {
			...commands.image,
			execute: (state) => {
				newContentSelectionRef.current = {
					start: state.selection.start,
					end: state.selection.end
				};
				newContentImageInputRef.current?.click();
			}
		};

		return commands.getCommands().map((command) => (command.keyCommand === 'image' ? imageCommand : command));
	}, []);

	return (
		<PageShell>
			<div className="space-y-6">
				{banner ? <div className="rounded-md border bg-muted/40 p-3 text-sm">{banner}</div> : null}
				<div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
					<div className="min-w-0">
						<h1 className="text-2xl font-semibold tracking-tight">D1 Forum</h1>
						<p className="break-all text-sm text-muted-foreground">
							开源：<a className="text-foreground underline" href="https://github.com/afoim/forum_for_cloudflare" target="_blank" rel="noopener noreferrer">https://github.com/afoim/forum_for_cloudflare</a> 基于 shadcn/ui + Tailwind 的多页应用（非 SPA），由 Cloudflare Workers 在边缘统一提供静态页面与 API。感谢 <a className="text-foreground underline" href="https://www.cloudflare.com" target="_blank" rel="noopener noreferrer">https://www.cloudflare.com</a> 提供的 CDN 与 DDoS 防护服务
						</p>
					</div>
					<div className="flex w-full min-w-0 flex-wrap items-center gap-2 lg:w-auto lg:justify-end">
						<label className="text-sm text-muted-foreground" htmlFor="category-filter">
							分类
						</label>
						<select
							id="category-filter"
							className="h-9 max-w-full min-w-0 rounded-md border bg-background px-3 text-sm"
							value={selectedCategory}
							onChange={(e) => {
								setSelectedCategory(e.target.value);
								setPageOffset(0);
							}}
						>
							<option value="">全部</option>
							<option value="uncategorized">未分类</option>
							{categories.map((c) => (
								<option key={c.id} value={String(c.id)}>
									{c.name}
								</option>
							))}
						</select>
						<label className="text-sm text-muted-foreground" htmlFor="sort-filter">
							排序
						</label>
						<select
							id="sort-filter"
							className="h-9 max-w-full min-w-0 rounded-md border bg-background px-3 text-sm"
							value={sortOption}
							onChange={(e) => {
								setSortOption(e.target.value);
								setPageOffset(0);
							}}
						>
							<option value="time_desc">最新发布</option>
							<option value="time_asc">最早发布</option>
							<option value="likes_desc">最多点赞</option>
							<option value="comments_desc">最多评论</option>
							<option value="views_desc">最多观看</option>
						</select>
						<form
							className="flex min-w-0 basis-full flex-wrap items-center gap-2 sm:basis-auto"
							onSubmit={(e) => {
								e.preventDefault();
								setPageOffset(0);
								setSearchQuery(searchInput.trim());
							}}
						>
							<Input
								value={searchInput}
								onChange={(e) => setSearchInput(e.target.value)}
								placeholder="搜索标题/内容"
								className="h-9 min-w-0 w-full flex-1 sm:w-48"
							/>
							<Button variant="outline" size="sm" type="submit" disabled={loading} className="shrink-0">
								<Search className="h-4 w-4" />
								<span className="sr-only">搜索</span>
							</Button>
							{searchInput || searchQuery ? (
								<Button
									variant="outline"
									size="sm"
									type="button"
									onClick={() => {
										setSearchInput('');
										setSearchQuery('');
										setPageOffset(0);
									}}
									disabled={loading}
									className="shrink-0"
								>
									<X className="h-4 w-4" />
									<span className="sr-only">清除</span>
								</Button>
							) : null}
						</form>
						<Button variant="outline" size="sm" onClick={() => fetchPosts(0)} disabled={loading}>
							<RefreshCw className="h-4 w-4" />
							<span className="sr-only">刷新</span>
						</Button>
					</div>
				</div>

				{user ? (
					<Card>
						<CardHeader>
							<CardTitle className="flex items-center justify-between gap-2">
								<span>发布新帖</span>
								<Button type="button" variant="outline" size="sm" onClick={() => setCreateOpen((v) => !v)}>
									{createOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
									<span className="sr-only">{createOpen ? '收起' : '展开'}</span>
								</Button>
							</CardTitle>
						</CardHeader>
						<CardContent>
							{!createOpen ? (
								<div className="text-sm text-muted-foreground">点击右侧按钮展开编辑器。</div>
							) : (
								<form className="space-y-4" onSubmit={createPost}>
									{createError ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{createError}</div> : null}
									<div className="sticky top-20 z-20 rounded-md border bg-background/95 p-3 shadow-sm backdrop-blur supports-[backdrop-filter]:bg-background/80">
										<div className="flex flex-wrap items-center gap-2">
											<Button type="button" variant="outline" size="sm" onClick={() => setCreateOpen(false)}>
												<ChevronUp className="h-4 w-4" />
												<span>收起编辑器</span>
											</Button>
											<Button type="submit" disabled={createLoading} size="sm" className="ml-auto">
												{createLoading ? '发布中...' : '发布'}
											</Button>
										</div>
									</div>
									<div className="space-y-4">
										<div className="space-y-2">
											<Label htmlFor="new-title">标题</Label>
											<Input id="new-title" maxLength={30} value={newTitle} onChange={(e) => setNewTitle(e.target.value)} required />
										</div>
										<div className="space-y-2">
											<Label htmlFor="new-category">分类 (可选)</Label>
											<select
												id="new-category"
												className="h-9 w-full rounded-md border bg-background px-3 text-sm"
												value={newCategoryId}
												onChange={(e) => setNewCategoryId(e.target.value)}
											>
												<option value="">无分类</option>
												{categories.map((c) => (
													<option key={c.id} value={String(c.id)}>
														{c.name}
													</option>
												))}
											</select>
										</div>
										<TurnstileWidget enabled={enabled} siteKey={siteKey} onToken={setTurnstileToken} resetKey={turnstileResetKey} />
									</div>
									<div className="space-y-2">
										<Label htmlFor="new-content">内容 (支持 Markdown)</Label>
										<input
											ref={newContentImageInputRef}
											type="file"
											accept="image/*"
											className="hidden"
											disabled={uploadingImage}
											onChange={(event) => {
												const file = event.target.files?.[0];
												if (file) void uploadPostImage(file);
												event.target.value = '';
											}}
										/>
										<div className="overflow-hidden rounded-md border" data-color-mode="light">
											<MDEditor
												value={newContent}
												onChange={(value) => setNewContent(value || '')}
												commands={editorCommands}
												preview="live"
												visibleDragbar={false}
												height={384}
												textareaProps={{
													id: 'new-content',
													placeholder: uploadingImage ? '图片上传中...' : '请输入内容',
													required: true,
													ref: (node) => {
														newContentTextareaRef.current = node;
													},
													onSelect: (event) => handleNewContentSelection(event.currentTarget),
													onClick: (event) => handleNewContentSelection(event.currentTarget),
													onKeyUp: (event) => handleNewContentSelection(event.currentTarget),
													onPaste: (event) => {
														const imageItem = Array.from(event.clipboardData?.items ?? []).find((item) => item.kind === 'file' && item.type.startsWith('image/'));
														const imageFile = imageItem?.getAsFile();
														if (!imageFile) return;
														event.preventDefault();
														handleNewContentSelection(event.currentTarget);
														void uploadPostImage(imageFile, {
															start: event.currentTarget.selectionStart ?? 0,
															end: event.currentTarget.selectionEnd ?? 0
														});
													}
												}}
											/>
										</div>
									</div>
								</form>
							)}
						</CardContent>
					</Card>
				) : (
					<Card>
						<CardContent className="py-6 text-sm text-muted-foreground">
							<a className="text-foreground underline" href="/login">
								登录
							</a>{' '}
							后可发布、点赞和评论。
						</CardContent>
					</Card>
				)}

				{error ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{error}</div> : null}

				<div className="space-y-4">
					<div ref={listTopRef} />
					{loading ? (
						<Card>
							<CardContent className="py-6 text-sm text-muted-foreground">加载中...</CardContent>
						</Card>
					) : posts.length === 0 ? (
						<Card>
							<CardContent className="py-6 text-sm text-muted-foreground">暂无帖子</CardContent>
						</Card>
					) : (
						posts.map((p) => {
							const coverUrl = getCoverImageUrl(p.content || '');
							const isAdmin = user?.role === 'admin';
							const menuOpen = adminMenuPostId === p.id;
							const actionLoading = adminActionPostId === p.id;
							return (
								<Card key={p.id}>
									<CardContent className="py-5">
										<div className="flex gap-4">
											{coverUrl ? (
												<img
													src={coverUrl}
													alt=""
													className="h-20 w-28 shrink-0 rounded-md object-cover"
													loading="lazy"
													referrerPolicy="no-referrer"
												/>
											) : null}
											<div className="min-w-0 flex-1 space-y-1">
												<div className="flex items-start justify-between gap-2">
													<div className="flex min-w-0 items-center gap-2">
														{p.is_pinned ? (
															<span className="inline-flex items-center gap-1 rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-700 dark:text-amber-300">
																<Pin className="h-3.5 w-3.5" />
																置顶
															</span>
														) : null}
														<a className="truncate text-lg font-semibold hover:underline" href={`/post?id=${p.id}`}>
															{p.title}
														</a>
													</div>
													{isAdmin ? (
														<div className="relative">
															<Button
																type="button"
																variant="ghost"
																size="sm"
																disabled={actionLoading}
																onMouseDown={(e) => e.stopPropagation()}
																onTouchStart={(e) => e.stopPropagation()}
																onClick={(e) => {
																	e.preventDefault();
																	e.stopPropagation();
																	setAdminMenuPostId((cur) => (cur === p.id ? null : p.id));
																}}
																aria-haspopup="menu"
																aria-expanded={menuOpen}
															>
																<MoreVertical className="h-4 w-4" />
																<span className="sr-only">更多</span>
															</Button>
															{menuOpen ? (
																<div
																	className="absolute right-0 top-full z-50 mt-1 w-40 rounded-md border bg-background p-1 shadow-md"
																	onMouseDown={(e) => e.stopPropagation()}
																	onTouchStart={(e) => e.stopPropagation()}
																	onClick={(e) => e.stopPropagation()}
																>
																	<button
																		type="button"
																		disabled={actionLoading}
																		className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-muted disabled:opacity-50"
																		onClick={() => void adminTogglePin(p)}
																	>
																		<Pin className="h-4 w-4" />
																		{p.is_pinned ? '取消置顶' : '置顶'}
																	</button>
																	<button
																		type="button"
																		disabled={actionLoading}
																		className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm text-destructive hover:bg-destructive/10 disabled:opacity-50"
																		onClick={() => void adminDeletePost(p)}
																	>
																		<Trash2 className="h-4 w-4" />
																		删除
																	</button>
																	<div className="my-1 h-px bg-border" />
																	<div className="px-2 py-1 text-xs font-medium text-muted-foreground">移动到分类</div>
																	<button
																		type="button"
																		disabled={actionLoading}
																		className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-muted disabled:opacity-50"
																		onClick={() => void adminMovePost(p, null)}
																	>
																		未分类
																	</button>
																	{categories.map((c) => (
																		<button
																			key={c.id}
																			type="button"
																			disabled={actionLoading}
																			className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-muted disabled:opacity-50"
																			onClick={() => void adminMovePost(p, c.id)}
																		>
																			{c.name}
																		</button>
																	))}
																</div>
															) : null}
														</div>
													) : null}
												</div>
												<div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted-foreground">
													<span className="inline-flex items-center gap-2">
														{p.author_avatar ? (
															<img
																src={p.author_avatar}
																alt=""
																className="h-6 w-6 rounded-full object-cover"
																loading="lazy"
																referrerPolicy="no-referrer"
															/>
														) : (
															<span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-muted text-[10px] text-muted-foreground">
																<User className="h-4 w-4" />
															</span>
														)}
														<span className="truncate text-foreground">{p.author_name}</span>
														{p.author_role === 'admin' ? (
															<span className="inline-flex items-center gap-1 rounded border border-indigo-500/30 bg-indigo-500/10 px-1.5 py-0.5 text-[10px] font-medium text-indigo-700 dark:text-indigo-300">
																<Shield className="h-3 w-3" />
																<span className="sr-only">管理员</span>
															</span>
														) : null}
													</span>
													{p.category_name ? (
														<>
															<span>·</span>
															<span className="truncate">{p.category_name}</span>
														</>
													) : null}
													<span>·</span>
													<span className="whitespace-nowrap">{formatDate(p.created_at)}</span>
												</div>
												<div className="flex items-center gap-4 text-xs text-muted-foreground">
													<span className="inline-flex items-center gap-1">
														<Heart className="h-4 w-4 text-rose-600" />
														{p.like_count || 0}
													</span>
													<span className="inline-flex items-center gap-1">
														<MessageCircle className="h-4 w-4 text-sky-600" />
														{p.comment_count || 0}
													</span>
													<span className="inline-flex items-center gap-1">
														<Eye className="h-4 w-4 text-emerald-600" />
														{p.view_count || 0}
													</span>
												</div>
											</div>
										</div>
									</CardContent>
								</Card>
							);
						})
					)}
				</div>

				<div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
					<div className="flex items-center gap-2">
						<Button
							variant="outline"
							size="sm"
							disabled={currentPage <= 1 || loading}
							onClick={() => fetchPosts(Math.max(0, pageOffset - pageLimit))}
						>
							<ChevronLeft className="h-4 w-4" />
							<span className="sr-only">上一页</span>
						</Button>
						<div className="flex items-center gap-1">
							{pages.map((p, idx) =>
								p === 'ellipsis' ? (
									<span key={`e-${idx}`} className="px-2 text-sm text-muted-foreground">
										…
									</span>
								) : (
									<Button
										key={p}
										variant={p === currentPage ? 'secondary' : 'outline'}
										size="sm"
										disabled={loading}
										onClick={() => fetchPosts((p - 1) * pageLimit)}
									>
										{p}
									</Button>
								)
							)}
						</div>
						<Button
							variant="outline"
							size="sm"
							disabled={currentPage >= totalPages || loading}
							onClick={() => fetchPosts(pageOffset + pageLimit)}
						>
							<ChevronRight className="h-4 w-4" />
							<span className="sr-only">下一页</span>
						</Button>
					</div>
					<form
						className="flex items-center gap-2"
						onSubmit={(e) => {
							e.preventDefault();
							const parsed = Number.parseInt(jumpTo, 10);
							if (!Number.isFinite(parsed)) return;
							const next = Math.min(Math.max(parsed, 1), totalPages);
							setJumpTo(String(next));
							fetchPosts((next - 1) * pageLimit);
						}}
					>
						<div className="text-sm text-muted-foreground">
							第 {currentPage} / {totalPages} 页
						</div>
						<Input
							value={jumpTo}
							onChange={(e) => setJumpTo(e.target.value)}
							inputMode="numeric"
							placeholder="跳页"
							className="h-9 w-20"
						/>
						<Button variant="outline" size="sm" type="submit" disabled={loading}>
							跳转
						</Button>
					</form>
				</div>
			</div>
		</PageShell>
	);
}
