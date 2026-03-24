import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig({
	plugins: [react()],
	root: path.resolve(__dirname, 'pages'),
	publicDir: false,
	build: {
		outDir: path.resolve(__dirname, '..', 'public'),
		emptyOutDir: true,
		assetsDir: 'assets',
		rollupOptions: {
			input: {
				index: path.resolve(__dirname, 'pages', 'index.html'),
				login: path.resolve(__dirname, 'pages', 'login.html'),
				register: path.resolve(__dirname, 'pages', 'register.html'),
				forgot: path.resolve(__dirname, 'pages', 'forgot.html'),
				reset: path.resolve(__dirname, 'pages', 'reset.html'),
				post: path.resolve(__dirname, 'pages', 'post.html'),
				settings: path.resolve(__dirname, 'pages', 'settings.html'),
				admin: path.resolve(__dirname, 'pages', 'admin.html')
			}
		}
	},
	resolve: {
		alias: {
			'@': path.resolve(__dirname, 'src'),
			'/src': path.resolve(__dirname, 'src')
		}
	},
	server: {
		fs: {
			allow: ['..']
		}
	}
});
