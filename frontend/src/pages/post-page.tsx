import * as React from 'react';
import { ArrowLeft, Heart, MoreVertical, Pin, Pencil, Reply, Shield, Trash2, User, X } from 'lucide-react';

import MDEditor, { commands, type ICommand } from '@uiw/react-md-editor';
import { TurnstileWidget } from '@/components/turnstile';
import { PageShell } from '@/components/page-shell';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { useConfig } from '@/hooks/use-config';
import { apiFetch, createImageUploadPlaceholder, formatDate, getSecurityHeaders, insertImageUploadPlaceholder, removeImageUploadPlaceholder, replaceImageUploadPlaceholder, type Category, type Comment, type Post } from '@/lib/api';
import { getToken, getUser, logout } from '@/lib/auth';
import { attachFancybox, highlightCodeBlocks, renderMarkdownToHtml } from '@/lib/markdown';
import { validateText } from '@/lib/validators';

export function PostPage() {
	const token = getToken();
	const user = React.useMemo(() => getUser(), [token]);
	const { config } = useConfig();
	const enabled = !!config?.turnstile_enabled;
	const siteKey = config?.turnstile_site_key || '';

	const [post, setPost] = React.useState<Post | null>(null);
	const [comments, setComments] = React.useState<Comment[]>([]);
	const [initialLoading, setInitialLoading] = React.useState(true);
	const [commentsLoading, setCommentsLoading] = React.useState(false);
	const [error, setError] = React.useState('');

	const [newComment, setNewComment] = React.useState('');
	const [replyTo, setReplyTo] = React.useState<Comment | null>(null);
	const [commentLoading, setCommentLoading] = React.useState(false);
	const [commentError, setCommentError] = React.useState('');
	const [commentSortOption, setCommentSortOption] = React.useState('likes_desc');
	const [turnstileToken, setTurnstileToken] = React.useState('');
	const [turnstileResetKey, setTurnstileResetKey] = React.useState(0);
	const [uploadingCommentImage, setUploadingCommentImage] = React.useState(false);

	const [isEditing, setIsEditing] = React.useState(false);
	const [editTitle, setEditTitle] = React.useState('');
	const [editContent, setEditContent] = React.useState('');
	const [editLoading, setEditLoading] = React.useState(false);
	const [editUploadingImage, setEditUploadingImage] = React.useState(false);
	const [editError, setEditError] = React.useState('');
	const contentRef = React.useRef<HTMLDivElement | null>(null);
	const commentsRef = React.useRef<HTMLDivElement | null>(null);
	const commentSelectionRef = React.useRef<{ start: number; end: number } | null>(null);
	const commentTextareaRef = React.useRef<HTMLTextAreaElement | null>(null);
	const commentImageInputRef = React.useRef<HTMLInputElement | null>(null);
	const editSelectionRef = React.useRef<{ start: number; end: number } | null>(null);
	const editTextareaRef = React.useRef<HTMLTextAreaElement | null>(null);
	const editImageInputRef = React.useRef<HTMLInputElement | null>(null);
	const [adminMenuOpen, setAdminMenuOpen] = React.useState(false);
	const adminMenuRef = React.useRef<HTMLDivElement | null>(null);
	const [allCategories, setAllCategories] = React.useState<Category[]>([]);

	function getPostIdFromPath() {
		const params = new URLSearchParams(window.location.search);
		const q = params.get('id');
		return q && /^\d+$/.test(q) ? q : null;
	}

	const postId = getPostIdFromPath();
	const userId = user?.id ?? null;
	const didInitialLoadRef = React.useRef(false);

	const getCommentSortParams = React.useCallback((sortOption: string) => {
		const sortBy = sortOption === 'likes_desc' ? 'likes' : 'time';
		const sortDir = sortOption === 'time_asc' ? 'asc' : 'desc';
		return `?sort_by=${encodeURIComponent(sortBy)}&sort_dir=${encodeURIComponent(sortDir)}`;
	}, []);

	const refreshPost = React.useCallback(async () => {
		if (!postId) {
			setError('帖子不存在');
			setPost(null);
			return;
		}
		const userParam = userId ? `?user_id=${userId}` : '';
		const nextPost = await apiFetch<Post>(`/posts/${postId}${userParam}`);
		setPost(nextPost);
		setEditTitle(nextPost.title);
		setEditContent(nextPost.content);
	}, [postId, userId]);

	const refreshComments = React.useCallback(
		async (sortOption = commentSortOption, showLoading = true) => {
			if (!postId) {
				setError('帖子不存在');
				setComments([]);
				return;
			}
			if (showLoading) setCommentsLoading(true);
			try {
				const nextComments = await apiFetch<Comment[]>(`/posts/${postId}/comments${getCommentSortParams(sortOption)}`);
				setComments(nextComments);
			} finally {
				if (showLoading) setCommentsLoading(false);
			}
		},
		[commentSortOption, getCommentSortParams, postId]
	);

	React.useEffect(() => {
		didInitialLoadRef.current = false;
		async function runInitialLoad() {
			if (!postId) {
				setError('帖子不存在');
				setPost(null);
				setComments([]);
				setInitialLoading(false);
				return;
			}
			setInitialLoading(true);
			setError('');
			try {
				await Promise.all([refreshPost(), refreshComments(commentSortOption, false)]);
				didInitialLoadRef.current = true;
			} catch (e: any) {
				setError(String(e?.message || e));
				setPost(null);
				setComments([]);
			} finally {
				setInitialLoading(false);
				setCommentsLoading(false);
			}
		}
		void runInitialLoad();
	}, [postId, userId]);

	React.useEffect(() => {
		if (!didInitialLoadRef.current) return;
		void refreshComments();
	}, [refreshComments]);

	React.useEffect(() => {
		void apiFetch<Category[]>('/categories')
			.then((list) => setAllCategories(Array.isArray(list) ? list : []))
			.catch(() => setAllCategories([]));
	}, []);

	React.useEffect(() => {
		if (isEditing) return;
		const el = contentRef.current;
		if (!el) return;
		highlightCodeBlocks(el);
		const cleanup = attachFancybox(el);
		return cleanup;
	}, [post, isEditing]);

	React.useEffect(() => {
		const el = commentsRef.current;
		if (!el) return;
		highlightCodeBlocks(el);
		const cleanup = attachFancybox(el);
		return cleanup;
	}, [comments]);

	React.useEffect(() => {
		if (!adminMenuOpen) return;
		function onPointerDown(e: MouseEvent | TouchEvent) {
			const target = e.target as Node | null;
			if (!target) return;
			const menu = adminMenuRef.current;
			if (menu && !menu.contains(target)) setAdminMenuOpen(false);
		}
		document.addEventListener('mousedown', onPointerDown);
		document.addEventListener('touchstart', onPointerDown);
		return () => {
			document.removeEventListener('mousedown', onPointerDown);
			document.removeEventListener('touchstart', onPointerDown);
		};
	}, [adminMenuOpen]);

	function organizeComments(list: Comment[]) {
		const roots: Array<Comment & { replies?: Comment[] }> = [];
		const map = new Map<number, Comment & { replies?: Comment[] }>();
		list.forEach((c) => map.set(c.id, { ...c, replies: [] }));
		map.forEach((c) => {
			if (c.parent_id && map.has(c.parent_id)) map.get(c.parent_id)!.replies!.push(c);
			else roots.push(c);
		});
		return roots;
	}

	async function toggleLike() {
		if (!post) return;
		if (!user) {
			window.location.href = '/login';
			return;
		}
		try {
			const data = await apiFetch<{ liked: boolean }>(`/posts/${post.id}/like`, {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({})
			});
			setPost((prev) =>
				prev
					? {
							...prev,
							liked: data.liked,
							like_count: (prev.like_count || 0) + (data.liked ? 1 : -1)
						}
					: prev
			);
		} catch {
			return;
		}
	}

	async function toggleCommentLike(commentId: number) {
		if (!user) {
			window.location.href = '/login';
			return;
		}
		try {
			const data = await apiFetch<{ liked: boolean }>(`/comments/${commentId}/like`, {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({})
			});
			setComments((prev) =>
				prev.map((comment) =>
					comment.id === commentId
						? {
								...comment,
								liked: data.liked,
								like_count: Math.max(0, (comment.like_count || 0) + (data.liked ? 1 : -1))
						  }
						: comment
				)
			);
		} catch {
			return;
		}
	}

	async function uploadCommentImage(file: File, selection = commentSelectionRef.current) {
		if (!user) {
			window.location.href = '/login';
			return;
		}
		const tokenValue = getToken();
		if (!tokenValue) {
			setCommentError('登录已过期，请重新登录');
			return;
		}
		if (file.size > 500 * 1024) {
			setCommentError('文件过大 (最大 500KB)');
			return;
		}

		const placeholder = createImageUploadPlaceholder();
		setCommentError('');
		setNewComment((prev) => {
			const insertion = insertImageUploadPlaceholder(prev, selection?.start ?? prev.length, selection?.end ?? prev.length, placeholder);
			commentSelectionRef.current = { start: insertion.selectionStart, end: insertion.selectionEnd };
			return insertion.value;
		});
		requestAnimationFrame(() => {
			const textarea = commentTextareaRef.current;
			if (!textarea) return;
			const nextSelection = commentSelectionRef.current;
			textarea.focus();
			if (nextSelection) textarea.setSelectionRange(nextSelection.start, nextSelection.end);
		});

		const formData = new FormData();
		formData.append('file', file);
		formData.append('type', 'comment');
		formData.append('post_id', postId || 'general');

		setUploadingCommentImage(true);
		try {
			const headers = getSecurityHeaders('POST', null);
			const res = await fetch('/api/upload', { method: 'POST', headers, body: formData });
			if (res.status === 401) {
				logout();
				window.location.href = '/login';
				return;
			}
			const data = (await res.json()) as any;
			if (!res.ok) throw new Error(data?.error || '上传失败');
			let nextSelectionStart = 0;
			setNewComment((prev) => {
				const replacement = replaceImageUploadPlaceholder(prev, placeholder.token, `![image](${data.url})`);
				nextSelectionStart = replacement.selectionStart;
				commentSelectionRef.current = { start: replacement.selectionStart, end: replacement.selectionEnd };
				return replacement.value;
			});
			requestAnimationFrame(() => {
				const textarea = commentTextareaRef.current;
				if (!textarea) return;
				textarea.focus();
				textarea.setSelectionRange(nextSelectionStart, nextSelectionStart);
			});
		} catch (e: any) {
			setNewComment((prev) => {
				const replacement = removeImageUploadPlaceholder(prev, placeholder.token);
				commentSelectionRef.current = { start: replacement.selectionStart, end: replacement.selectionEnd };
				return replacement.value;
			});
			setCommentError(String(e?.message || e));
		} finally {
			setUploadingCommentImage(false);
		}
	}

	async function submitComment(e: React.FormEvent) {
		e.preventDefault();
		if (!postId) return;
		if (!user) {
			window.location.href = '/login';
			return;
		}
		setCommentError('');
		const err = validateText(newComment, '评论');
		if (err) return setCommentError(err);
		if (newComment.length > 3000) return setCommentError('评论过长 (最多 3000 字符)');
		if (enabled && !turnstileToken) return setCommentError('请完成验证码验证');

		setCommentLoading(true);
		try {
			await apiFetch(`/posts/${postId}/comments`, {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({
					content: newComment,
					parent_id: replyTo ? replyTo.id : null,
					'cf-turnstile-response': turnstileToken
				})
			});
			setNewComment('');
			setReplyTo(null);
			setTurnstileToken('');
			setTurnstileResetKey((v) => v + 1);
			await refreshComments();
		} catch (e: any) {
			setCommentError(String(e?.message || e));
			setTurnstileToken('');
			setTurnstileResetKey((v) => v + 1);
		} finally {
			setCommentLoading(false);
		}
	}

	async function deleteComment(id: number) {
		if (!confirm('确定要删除此评论吗？此操作无法撤销。')) return;
		try {
			await apiFetch(`/comments/${id}`, {
				method: 'DELETE',
				headers: getSecurityHeaders('DELETE')
			});
			await refreshComments();
		} catch (e: any) {
			alert(String(e?.message || e));
		}
	}

	async function toggleCommentPin(comment: Comment) {
		if (!user) return;
		try {
			await apiFetch(`/comments/${comment.id}/pin`, {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ pinned: !comment.is_pinned })
			});
			await refreshComments(commentSortOption, false);
		} catch (e: any) {
			alert(String(e?.message || e));
		}
	}

	async function deletePost() {
		if (!post) return;
		if (!confirm('确定要删除这个帖子吗？此操作无法撤销。')) return;
		try {
			const isAdmin = user?.role === 'admin';
			const path = isAdmin ? `/admin/posts/${post.id}` : `/posts/${post.id}`;
			await apiFetch(path, {
				method: 'DELETE',
				headers: getSecurityHeaders('DELETE')
			});
			window.location.href = '/';
		} catch (e: any) {
			alert(String(e?.message || e));
		}
	}

	async function togglePin() {
		if (!post) return;
		if (!user || user.role !== 'admin') return;
		try {
			const next = !post.is_pinned;
			await apiFetch(`/admin/posts/${post.id}/pin`, {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ pinned: next })
			});
			setPost((prev) => (prev ? { ...prev, is_pinned: next ? 1 : 0 } : prev));
		} catch {
			return;
		} finally {
			setAdminMenuOpen(false);
		}
	}

	async function adminMovePostCategory(categoryId: number | null) {
		if (!post) return;
		if (!user || user.role !== 'admin') return;
		try {
			await apiFetch(`/admin/posts/${post.id}/move`, {
				method: 'POST',
				headers: getSecurityHeaders('POST'),
				body: JSON.stringify({ category_id: categoryId })
			});
			setAdminMenuOpen(false);
			await refreshPost();
		} catch {
			return;
		}
	}

	async function uploadEditImage(file: File, selection = editSelectionRef.current) {
		if (!user) {
			window.location.href = '/login';
			return;
		}
		const tokenValue = getToken();
		if (!tokenValue) {
			setEditError('登录已过期，请重新登录');
			return;
		}
		if (!post) {
			setEditError('帖子不存在');
			return;
		}
		if (file.size > 500 * 1024) {
			setEditError('文件过大 (最大 500KB)');
			return;
		}

		const placeholder = createImageUploadPlaceholder();
		setEditError('');
		setEditContent((prev) => {
			const insertion = insertImageUploadPlaceholder(prev, selection?.start ?? prev.length, selection?.end ?? prev.length, placeholder);
			editSelectionRef.current = { start: insertion.selectionStart, end: insertion.selectionEnd };
			return insertion.value;
		});
		requestAnimationFrame(() => {
			const textarea = editTextareaRef.current;
			if (!textarea) return;
			const nextSelection = editSelectionRef.current;
			textarea.focus();
			if (nextSelection) textarea.setSelectionRange(nextSelection.start, nextSelection.end);
		});

		const formData = new FormData();
		formData.append('file', file);
		formData.append('type', 'post');
		formData.append('post_id', String(post.id));

		setEditUploadingImage(true);
		try {
			const headers = getSecurityHeaders('POST', null);
			const res = await fetch('/api/upload', { method: 'POST', headers, body: formData });
			if (res.status === 401) {
				logout();
				window.location.href = '/login';
				return;
			}
			const data = (await res.json()) as any;
			if (!res.ok) throw new Error(data?.error || '上传失败');
			let nextSelectionStart = 0;
			setEditContent((prev) => {
				const replacement = replaceImageUploadPlaceholder(prev, placeholder.token, `![image](${data.url})`);
				nextSelectionStart = replacement.selectionStart;
				editSelectionRef.current = { start: replacement.selectionStart, end: replacement.selectionEnd };
				return replacement.value;
			});
			requestAnimationFrame(() => {
				const textarea = editTextareaRef.current;
				if (!textarea) return;
				textarea.focus();
				textarea.setSelectionRange(nextSelectionStart, nextSelectionStart);
			});
		} catch (e: any) {
			setEditContent((prev) => {
				const replacement = removeImageUploadPlaceholder(prev, placeholder.token);
				editSelectionRef.current = { start: replacement.selectionStart, end: replacement.selectionEnd };
				return replacement.value;
			});
			setEditError(String(e?.message || e));
		} finally {
			setEditUploadingImage(false);
		}
	}

	function handleCommentSelection(target: HTMLTextAreaElement) {
		commentSelectionRef.current = {
			start: target.selectionStart ?? 0,
			end: target.selectionEnd ?? 0
		};
		commentTextareaRef.current = target;
	}

	function handleEditSelection(target: HTMLTextAreaElement) {
		editSelectionRef.current = {
			start: target.selectionStart ?? 0,
			end: target.selectionEnd ?? 0
		};
		editTextareaRef.current = target;
	}

	const commentEditorCommands = React.useMemo<ICommand[]>(() => {
		const imageCommand: ICommand = {
			...commands.image,
			execute: (state) => {
				commentSelectionRef.current = {
					start: state.selection.start,
					end: state.selection.end
				};
				commentImageInputRef.current?.click();
			}
		};

		return commands.getCommands().map((command) => (command.keyCommand === 'image' ? imageCommand : command));
	}, []);

	const editEditorCommands = React.useMemo<ICommand[]>(() => {
		const imageCommand: ICommand = {
			...commands.image,
			execute: (state) => {
				editSelectionRef.current = {
					start: state.selection.start,
					end: state.selection.end
				};
				editImageInputRef.current?.click();
			}
		};

		return commands.getCommands().map((command) => (command.keyCommand === 'image' ? imageCommand : command));
	}, []);

	async function saveEdit() {
		if (!post) return;
		setEditError('');
		const titleErr = validateText(editTitle, '标题');
		if (titleErr) return setEditError(titleErr);
		const contentErr = validateText(editContent, '内容');
		if (contentErr) return setEditError(contentErr);
		if (editTitle.length > 30) return setEditError('标题过长 (最多 30 字符)');
		if (editContent.length > 3000) return setEditError('内容过长 (最多 3000 字符)');

		setEditLoading(true);
		try {
			await apiFetch(`/posts/${post.id}`, {
				method: 'PUT',
				headers: getSecurityHeaders('PUT'),
				body: JSON.stringify({ title: editTitle, content: editContent, category_id: post.category_id })
			});
			setIsEditing(false);
			await refreshPost();
		} catch (e: any) {
			setEditError(String(e?.message || e));
		} finally {
			setEditLoading(false);
		}
	}

	function renderCommentForm(targetComment?: Comment | null) {
		const isReplying = !!targetComment;
		return (
			<form className="space-y-3" onSubmit={submitComment}>
				{isReplying ? (
					<div className="flex items-center justify-between rounded-md border bg-muted/30 p-2 text-sm">
						<span>
							回复 <span className="font-medium">{targetComment.username}</span>
						</span>
						<Button variant="ghost" size="sm" onClick={() => setReplyTo(null)} type="button">
							取消
						</Button>
					</div>
				) : null}
				{commentError ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{commentError}</div> : null}
				<div className="space-y-2">
					<div className="text-sm font-medium">{isReplying ? '回复 (支持 Markdown)' : '评论 (支持 Markdown)'}</div>
					<input
						ref={commentImageInputRef}
						type="file"
						accept="image/*"
						className="hidden"
						disabled={uploadingCommentImage}
						onChange={(event) => {
							const file = event.target.files?.[0];
							if (file) void uploadCommentImage(file);
							event.target.value = '';
						}}
					/>
					<div className="overflow-hidden rounded-md border" data-color-mode="light">
						<MDEditor
							value={newComment}
							onChange={(value) => setNewComment(value || '')}
							commands={commentEditorCommands}
							preview="live"
							visibleDragbar={false}
							height={220}
							textareaProps={{
								placeholder: uploadingCommentImage ? '图片上传中...' : isReplying ? '写下你的回复...' : '写下你的评论...',
								ref: (node) => {
									commentTextareaRef.current = node;
								},
								onSelect: (event) => handleCommentSelection(event.currentTarget),
								onClick: (event) => handleCommentSelection(event.currentTarget),
								onKeyUp: (event) => handleCommentSelection(event.currentTarget),
								onPaste: (event) => {
									const imageItem = Array.from(event.clipboardData?.items ?? []).find((item) => item.kind === 'file' && item.type.startsWith('image/'));
									const imageFile = imageItem?.getAsFile();
									if (!imageFile) return;
									event.preventDefault();
									handleCommentSelection(event.currentTarget);
									void uploadCommentImage(imageFile, { start: event.currentTarget.selectionStart ?? 0, end: event.currentTarget.selectionEnd ?? 0 });
								}
							}}
						/>
					</div>
				</div>
				<TurnstileWidget enabled={enabled} siteKey={siteKey} onToken={setTurnstileToken} resetKey={turnstileResetKey} />
				<div className="flex items-center gap-2">
					<Button type="submit" disabled={commentLoading || commentsLoading}>{commentLoading ? '发布中...' : isReplying ? '发布回复' : '发布评论'}</Button>
					{!user ? (
						<Button type="button" variant="outline" onClick={() => (window.location.href = '/login')}>
							登录后评论
						</Button>
					) : null}
				</div>
			</form>
		);
	}

	return (
		<PageShell>
			<div className="space-y-6">
				<div className="flex items-center justify-between">
					<Button asChild variant="ghost" size="sm">
						<a href="/">
							<ArrowLeft className="h-4 w-4" />
							<span className="sr-only">返回首页</span>
						</a>
					</Button>
				</div>

				{error ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{error}</div> : null}

				{initialLoading ? (
					<Card>
						<CardContent className="py-6 text-sm text-muted-foreground">加载中...</CardContent>
					</Card>
				) : !post ? (
					<Card>
						<CardContent className="py-6 text-sm text-muted-foreground">帖子不存在</CardContent>
					</Card>
				) : (
					<>
						<Card>
							<CardHeader>
								<CardTitle className="flex flex-col gap-2">
									<span>{post.title}</span>
									<span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm font-normal text-muted-foreground">
										<span className="inline-flex items-center gap-2">
											{post.author_avatar ? (
												<img src={post.author_avatar} alt="" className="h-6 w-6 rounded-full object-cover" loading="lazy" referrerPolicy="no-referrer" />
											) : (
												<span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-muted text-[10px] text-muted-foreground">
													<User className="h-4 w-4" />
												</span>
											)}
											<span className="text-foreground">{post.author_name}</span>
											{post.author_role === 'admin' ? (
												<span className="inline-flex items-center gap-1 rounded border border-indigo-500/30 bg-indigo-500/10 px-1.5 py-0.5 text-[10px] font-medium text-indigo-700 dark:text-indigo-300">
													<Shield className="h-3 w-3" />
													<span className="sr-only">管理员</span>
												</span>
											) : null}
										</span>
										<span>·</span>
										<span className="whitespace-nowrap">{formatDate(post.created_at)}</span>
									</span>
								</CardTitle>
							</CardHeader>
							<CardContent className="space-y-4">
								<div className="flex flex-wrap items-center gap-2">
									<Button variant={post.liked ? 'secondary' : 'outline'} size="sm" onClick={toggleLike} disabled={!user}>
										<Heart className="h-4 w-4 text-rose-600" fill={post.liked ? 'currentColor' : 'none'} />
										<span className="tabular-nums">{post.like_count || 0}</span>
										<span className="sr-only">{post.liked ? '取消点赞' : '点赞'}</span>
									</Button>

									{user && (user.role === 'admin' || user.id === post.author_id) ? (
										<Button variant="outline" size="sm" onClick={() => setIsEditing((v) => !v)}>
											{isEditing ? <X className="h-4 w-4" /> : <Pencil className="h-4 w-4" />}
											<span className="sr-only">{isEditing ? '取消编辑' : '编辑'}</span>
										</Button>
									) : null}

									{user && (user.role === 'admin' || user.id === post.author_id) ? (
										<div className="relative" ref={adminMenuRef}>
											<Button type="button" variant="outline" size="sm" onClick={() => setAdminMenuOpen((v) => !v)} aria-haspopup="menu" aria-expanded={adminMenuOpen}>
												<MoreVertical className="h-4 w-4" />
												<span className="sr-only">更多</span>
											</Button>
											{adminMenuOpen ? (
												<div className="absolute right-0 top-full z-50 mt-2 w-44 rounded-md border bg-background p-1 shadow-md">
													{user.role === 'admin' ? (
														<button type="button" className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-muted" onClick={togglePin}>
															<Pin className="h-4 w-4" />
															{post.is_pinned ? '取消置顶' : '置顶'}
														</button>
													) : null}
													<button
														type="button"
														className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm text-destructive hover:bg-destructive/10"
														onClick={() => {
															setAdminMenuOpen(false);
															void deletePost();
														}}
													>
														<Trash2 className="h-4 w-4" />
														删除
													</button>
													{user.role === 'admin' ? (
														<>
															<div className="my-1 h-px bg-border" />
															<div className="px-2 py-1 text-xs font-medium text-muted-foreground">移动到分类</div>
															<button type="button" className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-muted" onClick={() => void adminMovePostCategory(null)}>
																未分类
															</button>
															{allCategories.map((c) => (
																<button key={c.id} type="button" className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-muted" onClick={() => void adminMovePostCategory(c.id)}>
																	{c.name}
																</button>
															))}
														</>
													) : null}
												</div>
											) : null}
										</div>
									) : null}
								</div>

								{isEditing ? (
									<div className="space-y-4">
										{editError ? <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">{editError}</div> : null}
										<div className="sticky top-20 z-20 rounded-md border bg-background/95 p-3 shadow-sm backdrop-blur supports-[backdrop-filter]:bg-background/80">
											<div className="flex flex-wrap items-center gap-2">
												<Button type="button" variant="outline" size="sm" onClick={() => setIsEditing(false)}>
													<X className="h-4 w-4" />
													<span>退出编辑模式</span>
												</Button>
												<Button onClick={saveEdit} disabled={editLoading} size="sm" className="ml-auto">
													{editLoading ? '保存中...' : '保存'}
												</Button>
											</div>
										</div>
										<div className="space-y-2">
											<Input value={editTitle} onChange={(e) => setEditTitle(e.target.value)} maxLength={30} />
											<div className="space-y-2">
												<div className="text-sm font-medium">内容 (支持 Markdown)</div>
												<input
													ref={editImageInputRef}
													type="file"
													accept="image/*"
													className="hidden"
													disabled={editUploadingImage}
													onChange={(event) => {
														const file = event.target.files?.[0];
														if (file) void uploadEditImage(file);
														event.target.value = '';
													}}
												/>
												<div className="overflow-hidden rounded-md border" data-color-mode="light">
													<MDEditor
														value={editContent}
														onChange={(value) => setEditContent(value || '')}
														commands={editEditorCommands}
														preview="live"
														visibleDragbar={false}
														height={384}
														textareaProps={{
															placeholder: editUploadingImage ? '图片上传中...' : undefined,
															ref: (node) => {
																editTextareaRef.current = node;
															},
															onSelect: (event) => handleEditSelection(event.currentTarget),
															onClick: (event) => handleEditSelection(event.currentTarget),
															onKeyUp: (event) => handleEditSelection(event.currentTarget),
															onPaste: (event) => {
																const imageItem = Array.from(event.clipboardData?.items ?? []).find((item) => item.kind === 'file' && item.type.startsWith('image/'));
																const imageFile = imageItem?.getAsFile();
																if (!imageFile) return;
																event.preventDefault();
																handleEditSelection(event.currentTarget);
																void uploadEditImage(imageFile, { start: event.currentTarget.selectionStart ?? 0, end: event.currentTarget.selectionEnd ?? 0 });
															}
														}}
													/>
												</div>
											</div>
										</div>
									</div>
								) : (
									<div className="prose max-w-none break-words [&_ul]:list-disc [&_ul]:pl-6 [&_ol]:list-decimal [&_ol]:pl-6 [&_li]:my-1" ref={contentRef} dangerouslySetInnerHTML={{ __html: renderMarkdownToHtml(post.content || '') }} />
								)}
							</CardContent>
						</Card>

						<Card>
							<CardHeader>
								<div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
									<CardTitle>评论</CardTitle>
									<div className="flex items-center gap-2">
										<label className="text-sm text-muted-foreground" htmlFor="comment-sort-filter">
											排序
										</label>
										<select
											id="comment-sort-filter"
											className="h-9 max-w-full min-w-0 rounded-md border bg-background px-3 text-sm"
											value={commentSortOption}
											onChange={(e) => setCommentSortOption(e.target.value)}
											disabled={commentsLoading || commentLoading}
										>
											<option value="likes_desc">最多点赞</option>
											<option value="time_desc">最新发布</option>
											<option value="time_asc">最早发布</option>
										</select>
									</div>
								</div>
							</CardHeader>
							<CardContent className="space-y-4">
								{commentsLoading ? <div className="text-sm text-muted-foreground">评论加载中...</div> : null}
								{!replyTo ? renderCommentForm() : null}

								{comments.length === 0 ? (
									<div className="text-sm text-muted-foreground">暂无评论</div>
								) : (
									<div ref={commentsRef} className="space-y-3">
										{organizeComments(comments).map((c) => (
											<div key={c.id} className="rounded-md border p-3">
												<div className="flex items-center justify-between gap-2">
													<div className="text-sm">
														<span className="inline-flex flex-wrap items-center gap-2">
															{c.avatar_url ? <img src={c.avatar_url} alt="" className="h-6 w-6 rounded-full object-cover" loading="lazy" referrerPolicy="no-referrer" /> : <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-muted text-[10px] text-muted-foreground"><User className="h-4 w-4" /></span>}
															<span className="font-medium text-foreground">{c.username}</span>
															{c.role === 'admin' ? <span className="inline-flex items-center gap-1 rounded border border-indigo-500/30 bg-indigo-500/10 px-1.5 py-0.5 text-[10px] font-medium text-indigo-700 dark:text-indigo-300"><Shield className="h-3 w-3" /><span className="sr-only">管理员</span></span> : null}
															{c.is_pinned ? <span className="inline-flex items-center gap-1 rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-300"><Pin className="h-3 w-3" />置顶</span> : null}
															<span className="text-muted-foreground">{formatDate(c.created_at)}</span>
														</span>
													</div>
													<div className="flex items-center gap-2">
														<Button variant={c.liked ? 'secondary' : 'ghost'} size="sm" onClick={() => toggleCommentLike(c.id)} disabled={!user}>
															<Heart className="h-4 w-4 text-rose-600" fill={c.liked ? 'currentColor' : 'none'} />
															<span className="tabular-nums">{c.like_count || 0}</span>
															<span className="sr-only">{c.liked ? '取消点赞' : '点赞'}</span>
														</Button>
														<Button variant="ghost" size="sm" onClick={() => setReplyTo(c)}>
															<Reply className="h-4 w-4" />
															<span className="sr-only">回复</span>
														</Button>
														{user && (user.role === 'admin' || user.id === c.author_id) ? (
															<>
																<Button variant="ghost" size="sm" onClick={() => toggleCommentPin(c)}>
																	<Pin className="h-4 w-4" />
																	<span>{c.is_pinned ? '取消置顶' : '置顶'}</span>
																</Button>
																<Button variant="ghost" size="sm" onClick={() => deleteComment(c.id)}>
																	<Trash2 className="h-4 w-4" />
																	<span className="sr-only">删除</span>
																</Button>
															</>
														) : null}
													</div>
												</div>
												<div className="prose prose-sm mt-2 max-w-none break-words [&_ul]:list-disc [&_ul]:pl-6 [&_ol]:list-decimal [&_ol]:pl-6 [&_li]:my-1" dangerouslySetInnerHTML={{ __html: renderMarkdownToHtml(c.content || '') }} />
												{replyTo?.id === c.id ? <div className="mt-3">{renderCommentForm(c)}</div> : null}
												{c.replies && c.replies.length ? (
													<div className="mt-3 space-y-2 border-l pl-3">
														{c.replies.map((r) => (
															<div key={r.id} className="rounded-md bg-muted/30 p-2">
																<div className="flex items-center justify-between gap-2">
																	<div className="text-xs">
																		<span className="inline-flex items-center gap-2">
																			{r.avatar_url ? <img src={r.avatar_url} alt="" className="h-5 w-5 rounded-full object-cover" loading="lazy" referrerPolicy="no-referrer" /> : <span className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-muted text-[10px] text-muted-foreground"><User className="h-3.5 w-3.5" /></span>}
																			<span className="font-medium text-foreground">{r.username}</span>
																			{r.role === 'admin' ? <span className="inline-flex items-center gap-1 rounded border border-indigo-500/30 bg-indigo-500/10 px-1 py-0.5 text-[10px] font-medium text-indigo-700 dark:text-indigo-300"><Shield className="h-3 w-3" /><span className="sr-only">管理员</span></span> : null}
																			<span className="text-muted-foreground">{formatDate(r.created_at)}</span>
																		</span>
																	</div>
																	<div className="flex items-center gap-2">
																		<Button variant={r.liked ? 'secondary' : 'ghost'} size="sm" onClick={() => toggleCommentLike(r.id)} disabled={!user}>
																			<Heart className="h-4 w-4 text-rose-600" fill={r.liked ? 'currentColor' : 'none'} />
																			<span className="tabular-nums">{r.like_count || 0}</span>
																			<span className="sr-only">{r.liked ? '取消点赞' : '点赞'}</span>
																		</Button>
																		{user && (user.role === 'admin' || user.id === r.author_id) ? (
																			<Button variant="ghost" size="sm" onClick={() => deleteComment(r.id)}>
																				<Trash2 className="h-4 w-4" />
																				<span className="sr-only">删除</span>
																			</Button>
																		) : null}
																	</div>
																</div>
																<div className="prose prose-sm mt-1 max-w-none break-words [&_ul]:list-disc [&_ul]:pl-6 [&_ol]:list-decimal [&_ol]:pl-6 [&_li]:my-1" dangerouslySetInnerHTML={{ __html: renderMarkdownToHtml(r.content || '') }} />
															</div>
														))}
													</div>
												) : null}
											</div>
										))}
									</div>
								)}
							</CardContent>
						</Card>
					</>
				)}
			</div>
		</PageShell>
	);
}
