
import { AwsClient } from 'aws4fetch';

export interface S3Env {
    AWS_ACCESS_KEY_ID: string;
    AWS_SECRET_ACCESS_KEY: string;
    AWS_REGION: string;
    AWS_ENDPOINT: string;
    AWS_ENDPOINT_BACKEND?: string;
    AWS_BUCKET: string;
    AWS_PATH_PREFIX?: string;
}

function getClient(env: S3Env) {
    return new AwsClient({
        accessKeyId: env.AWS_ACCESS_KEY_ID,
        secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
        region: env.AWS_REGION,
        service: 's3',
    });
}

function getBackendEndpoint(env: S3Env): string {
    return normalizeEndpoint(env.AWS_ENDPOINT_BACKEND || env.AWS_ENDPOINT);
}

function normalizeKey(value: string): string {
    return value.replace(/^\/+/, '').trim();
}

function normalizeEndpoint(endpoint: string): string {
    return endpoint.replace(/\/+$/, '');
}

export function extractImageKey(env: S3Env, value: string | null | undefined): string | null {
    if (!value || typeof value !== 'string') return null;

    const trimmed = value.trim();
    if (!trimmed) return null;
    if (/^data:/i.test(trimmed)) return null;

    if (!/^[a-z][a-z\d+.-]*:/i.test(trimmed)) {
        const normalized = normalizeKey(trimmed);
        return normalized || null;
    }

    let parsed: URL;
    try {
        parsed = new URL(trimmed);
    } catch {
        return null;
    }

    if (!/^https?:$/i.test(parsed.protocol)) return null;

    const pathParts = parsed.pathname.split('/').filter(Boolean);
    if (pathParts.length < 2) return null;

    const bucketIndex = pathParts.indexOf(env.AWS_BUCKET);
    if (bucketIndex === -1 || bucketIndex === pathParts.length - 1) return null;

    const key = pathParts.slice(bucketIndex + 1).join('/');
    return normalizeKey(key) || null;
}

export async function uploadImage(env: S3Env, file: File, userId: string | number, postId: string | number = 'general', type: 'post' | 'avatar' | 'comment' = 'post'): Promise<string> {
    const s3 = getClient(env);
    const pathPrefix = env.AWS_PATH_PREFIX || '';
    const filename = `${Date.now()}-${file.name.replace(/[^a-zA-Z0-9.-]/g, '')}`;
    let key = '';

    if (type === 'avatar') {
        key = `${pathPrefix}/usr/${userId}/avatar/${filename}`.replace(/^\/+/, '');
    } else if (type === 'comment') {
        key = `${pathPrefix}/usr/${userId}/comment/${postId}/${filename}`.replace(/^\/+/, '');
    } else {
        key = `${pathPrefix}/usr/${userId}/post/${postId}/${filename}`.replace(/^\/+/, '');
    }

    const backendEndpoint = getBackendEndpoint(env);
    const url = `${backendEndpoint}/${env.AWS_BUCKET}/${normalizeKey(key)}`;

    const res = await s3.fetch(url, {
        method: 'PUT',
        body: file,
        headers: {
            'Content-Type': file.type || 'application/octet-stream',
        }
    });

    if (!res.ok) {
        const err = await res.text();
        throw new Error(`S3 Upload Failed: ${res.status} ${err}`);
    }

    return key;
}

export async function deleteImage(env: S3Env, imageValue: string, expectedOwnerId?: string | number): Promise<boolean> {
    const key = extractImageKey(env, imageValue);
    if (!key) return false;

    if (expectedOwnerId !== undefined && expectedOwnerId !== null) {
        const userSegment = `usr/${expectedOwnerId}/`;
        if (!key.includes(userSegment)) {
             console.error(`[Security] Blocked unauthorized image deletion. Key: ${key}, Expected Owner: ${expectedOwnerId}`);
             return false;
        }
    }

    const s3 = getClient(env);
    const backendEndpoint = getBackendEndpoint(env);
    const url = `${backendEndpoint}/${env.AWS_BUCKET}/${normalizeKey(key)}`;
    const res = await s3.fetch(url, { method: 'DELETE' });

    return res.ok;
}

export async function listAllKeys(env: S3Env): Promise<string[]> {
    const s3 = getClient(env);
    const keys: string[] = [];
    let continuationToken: string | undefined = undefined;
    const pathPrefix = env.AWS_PATH_PREFIX || '';
    const backendEndpoint = getBackendEndpoint(env);

    do {
        let url = `${backendEndpoint}/${env.AWS_BUCKET}?list-type=2`;
        if (pathPrefix) {
             const prefix = pathPrefix.replace(/^\/+/, '');
             url += `&prefix=${encodeURIComponent(prefix)}`;
        }

        if (continuationToken) {
            url += `&continuation-token=${encodeURIComponent(continuationToken)}`;
        }

        const res = await s3.fetch(url, { method: 'GET' });
        if (!res.ok) throw new Error(`List failed: ${res.status}`);

        const text = await res.text();

        const matches = text.matchAll(/<Key>(.*?)<\/Key>/g);
        for (const match of matches) {
            keys.push(match[1]);
        }

        const nextTokenMatch = text.match(/<NextContinuationToken>(.*?)<\/NextContinuationToken>/);
        continuationToken = nextTokenMatch ? nextTokenMatch[1] : undefined;

    } while (continuationToken);

    return keys;
}

export function getPublicUrl(env: S3Env, key: string): string {
    return `${normalizeEndpoint(env.AWS_ENDPOINT)}/${env.AWS_BUCKET}/${normalizeKey(key)}`;
}
