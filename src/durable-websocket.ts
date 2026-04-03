export class ForumWebSocket {
	private state: DurableObjectState;

	constructor(state: DurableObjectState) {
		this.state = state;
	}

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);

		// WebSocket upgrade
		if (request.headers.get('Upgrade') === 'websocket') {
			const pair = new WebSocketPair();
			const [client, server] = Object.values(pair);

			const postId = url.searchParams.get('postId') || undefined;
			const userId = url.searchParams.get('userId') || undefined;

			// Use Hibernation API - allows the DO to sleep when idle
			this.state.acceptWebSocket(server);

			// Persist connection state that survives hibernation
			server.serializeAttachment({ postId, userId });

			return new Response(null, {
				status: 101,
				webSocket: client,
			});
		}

		// HTTP API for broadcasting
		if (url.pathname === '/broadcast' && request.method === 'POST') {
			const body = await request.json() as { postId: string; message: any };
			this.broadcastToPost(body.postId, body.message);
			return Response.json({ success: true, connections: this.state.getWebSockets().length });
		}

		// HTTP API for status
		if (url.pathname === '/status' && request.method === 'GET') {
			const postConnections: Record<string, number> = {};
			for (const ws of this.state.getWebSockets()) {
				try {
					const data = ws.deserializeAttachment() as { postId?: string; userId?: string } | null;
					if (data?.postId) {
						postConnections[data.postId] = (postConnections[data.postId] || 0) + 1;
					}
				} catch {
					// Ignore closed connections
				}
			}
			return Response.json({
				totalConnections: this.state.getWebSockets().length,
				postConnections
			});
		}

		return Response.json({ error: 'Not found' }, { status: 404 });
	}

	// Called when a WebSocket message is received
	async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer) {
		const data = ws.deserializeAttachment() as { postId?: string; userId?: string } | null;

		try {
			const msg = JSON.parse(message as string);

			switch (msg.type) {
				case 'subscribe_post':
					if (msg.payload?.postId) {
						ws.serializeAttachment({ ...data, postId: String(msg.payload.postId) });
						ws.send(JSON.stringify({
							type: 'subscribed',
							payload: { postId: msg.payload.postId }
						}));
					}
					break;

				case 'unsubscribe_post':
					ws.serializeAttachment({ ...data, postId: undefined });
					ws.send(JSON.stringify({
						type: 'unsubscribed',
						payload: { success: true }
					}));
					break;
			}
		} catch (e) {
			console.error('WebSocket message parse error:', e);
		}
	}

	// Called when a WebSocket closes
	async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean) {
		// Connection closed - the runtime will handle cleanup automatically
	}

	// Called when a WebSocket has an error
	async webSocketError(ws: WebSocket, error: unknown) {
		console.error('WebSocket error:', error);
	}

	private broadcastToPost(postId: string, message: any) {
		const payload = typeof message === 'string' ? message : JSON.stringify(message);
		let sent = 0;

		for (const ws of this.state.getWebSockets()) {
			try {
				const data = ws.deserializeAttachment() as { postId?: string; userId?: string } | null;
				if (data?.postId === String(postId)) {
					ws.send(payload);
					sent++;
				}
			} catch {
				// Connection is closed, ignore
			}
		}

		console.log(`[WebSocket] Broadcast to post ${postId}: ${sent} clients`);
	}

	// Broadcast to all connections
	broadcast(message: any) {
		const payload = typeof message === 'string' ? message : JSON.stringify(message);
		for (const ws of this.state.getWebSockets()) {
			try {
				ws.send(payload);
			} catch {
				// Connection is closed, ignore
			}
		}
	}
}