import { DurableObject } from "cloudflare:workers";

interface Env {
	WS_MANAGER: DurableObjectNamespace;
}

interface ConnectionMeta {
	postId?: string;
}

type BroadcastMessage = {
	postId: string;
	message: {
		type: string;
		payload: any;
	};
};

export class SSEHub extends DurableObject<Env> {
	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
	}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);

		switch (url.pathname) {
			case "/websocket":
				return this.handleWebSocketUpgrade(request, url);
			case "/broadcast":
				return this.handleBroadcast(request);
			case "/status":
				return this.handleStatus();
			default:
				return new Response("Not Found", { status: 404 });
		}
	}

	private handleWebSocketUpgrade(request: Request, url: URL): Response {
		if (request.headers.get("Upgrade") !== "websocket") {
			return new Response("Expected Upgrade: websocket", { status: 426 });
		}

		const postId = url.searchParams.get("postId") || undefined;

		const pair = new WebSocketPair();
		const [client, server] = Object.values(pair);

		this.ctx.acceptWebSocket(server, postId ? [postId] : []);

		server.serializeAttachment({ postId } as ConnectionMeta);

		return new Response(null, { status: 101, webSocket: client });
	}

	private async handleBroadcast(request: Request): Promise<Response> {
		let body: BroadcastMessage;
		try {
			body = await request.json();
		} catch {
			return Response.json({ error: "Invalid JSON" }, { status: 400 });
		}

		const { postId, message } = body;
		const payload = JSON.stringify({
			...message,
			timestamp: Date.now(),
		});

		const sockets = this.ctx.getWebSockets();
		let sent = 0;

		for (const ws of sockets) {
			try {
				const meta = ws.deserializeAttachment() as ConnectionMeta | null;
				if (postId === "global" || meta?.postId === String(postId)) {
					ws.send(payload);
					sent++;
				}
			} catch {
				// Socket closed
			}
		}

		return Response.json({ ok: true, sent, total: sockets.length });
	}

	private handleStatus(): Response {
		const postConnections: Record<string, number> = {};
		const sockets = this.ctx.getWebSockets();

		for (const ws of sockets) {
			try {
				const meta = ws.deserializeAttachment() as ConnectionMeta | null;
				if (meta?.postId) {
					postConnections[meta.postId] = (postConnections[meta.postId] || 0) + 1;
				}
			} catch {
				// Ignore closed connections
			}
		}

		return Response.json({
			totalConnections: sockets.length,
			postConnections,
		});
	}

	async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer) {
		try {
			const data = JSON.parse(message as string);

			if (data.type === "subscribe" && data.postId) {
				const postId = String(data.postId);
				const currentMeta = ws.deserializeAttachment() as ConnectionMeta | null;
				ws.serializeAttachment({ ...currentMeta, postId });
				ws.send(JSON.stringify({ type: "subscribed", postId, timestamp: Date.now() }));
			} else if (data.type === "unsubscribe") {
				const currentMeta = ws.deserializeAttachment() as ConnectionMeta | null;
				ws.serializeAttachment({ ...currentMeta, postId: undefined });
				ws.send(JSON.stringify({ type: "unsubscribed", timestamp: Date.now() }));
			} else if (data.type === "ping") {
				ws.send(JSON.stringify({ type: "pong", timestamp: Date.now() }));
			}
		} catch {
			// Ignore invalid messages - auto-response handles ping/pong
		}
	}

	async webSocketClose(ws: WebSocket, code: number, reason: string, _wasClean: boolean) {
		ws.close(code, reason);
	}

	async webSocketError(ws: WebSocket, _error: unknown) {
		ws.close(1011, "WebSocket error");
	}
}

async function handleSSEConnection(
	request: Request,
	env: Env,
	postId?: string
): Promise<Response> {
	const id = postId ? env.WS_MANAGER.idFromName(postId) : env.WS_MANAGER.idFromName("global");
	const stub = env.WS_MANAGER.get(id);

	const wsUrl = new URL("http://internal/websocket");
	if (postId) wsUrl.searchParams.set("postId", postId);

	const resp = await stub.fetch(wsUrl.toString(), {
		headers: { Upgrade: "websocket" },
	});

	const ws = resp.webSocket;
	if (!ws) {
		return new Response("WebSocket upgrade to DO failed", { status: 502 });
	}

	ws.accept();

	const encoder = new TextEncoder();
	let eventId = 0;

	const readable = new ReadableStream<Uint8Array>({
		start(controller) {
			const emit = (data: string) => {
				eventId++;
				controller.enqueue(encoder.encode(`id: ${eventId}\ndata: ${data}\n\n`));
			};

			controller.enqueue(
				encoder.encode(": SSE stream connected\n\n")
			);

			emit(JSON.stringify({ type: "connected", postId, timestamp: Date.now() }));

			ws.addEventListener("message", (evt) => {
				try {
					emit(typeof evt.data === "string" ? evt.data : "binary");
				} catch {
					ws.close(1000, "SSE stream closed");
				}
			});

			ws.addEventListener("close", () => {
				try {
					controller.close();
				} catch {
					// already closed
				}
			});

			ws.addEventListener("error", () => {
				try {
					controller.close();
				} catch {
					// already closed
				}
			});
		},

		cancel() {
			ws.close(1000, "Client disconnected");
		},
	});

	return new Response(readable, {
		headers: {
			"Content-Type": "text/event-stream",
			"Cache-Control": "no-cache, no-transform",
			"Connection": "keep-alive",
			"X-Accel-Buffering": "no",
			"Access-Control-Allow-Origin": "*",
		},
	});
}

export { handleSSEConnection };