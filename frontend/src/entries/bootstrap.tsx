import '@/styles/globals.css';
import '@fancyapps/ui/dist/fancybox/fancybox.css';
import '@uiw/react-md-editor/markdown-editor.css';
import '@uiw/react-markdown-preview/markdown.css';
import { createRoot } from 'react-dom/client';
import * as React from 'react';
import { checkSession } from '@/lib/api';
import { getToken, logout } from '@/lib/auth';
import { initTheme } from '@/lib/theme';

const REQUIRED_AUTH_PATHS = new Set(['/settings', '/admin']);
const AUTH_PAGE_PATHS = new Set(['/login', '/register', '/forgot', '/reset']);

async function prepareSessionForCurrentPage() {
	const pathname = window.location.pathname;
	const token = getToken();
	const hasToken = !!token;
	const isRequiredAuthPage = REQUIRED_AUTH_PATHS.has(pathname);
	const isAuthPage = AUTH_PAGE_PATHS.has(pathname);

	if (!hasToken) {
		if (isRequiredAuthPage) {
			logout();
			window.location.replace('/login');
			return false;
		}
		return true;
	}

	try {
		await checkSession();
		return true;
	} catch {
		logout();
		if (!isAuthPage) {
			window.location.replace('/login');
			return false;
		}
		return true;
	}
}

export async function mount(nodeId: string, element: React.ReactNode) {
	initTheme();
	const canMount = await prepareSessionForCurrentPage();
	if (!canMount) return;
	const el = document.getElementById(nodeId);
	if (!el) throw new Error(`Missing root element #${nodeId}`);
	createRoot(el).render(
		<React.StrictMode>
			{element}
		</React.StrictMode>
	);
}
