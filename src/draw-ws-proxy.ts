import { DurableObject } from "cloudflare:workers";

interface DrawWsProxyEnv {
	DRAW_WS_PROXY: DurableObjectNamespace;
}

export class DrawWsProxy extends DurableObject<DrawWsProxyEnv> {
	private upstream: WebSocket | null = null;

	async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);

		if (request.headers.get("Upgrade") !== "websocket") {
			return new Response("Expected WebSocket", { status: 426 });
		}

		const backendUrl = url.searchParams.get("backendUrl");
		const accessClientId = url.searchParams.get("accessClientId") || "";
		const accessClientSecret = url.searchParams.get("accessClientSecret") || "";
		const creatorName = url.searchParams.get("creatorName") || "";

		if (!backendUrl) {
			return new Response("Missing backendUrl", { status: 400 });
		}

		const pair = new WebSocketPair();
		const [client, server] = Object.values(pair);

		this.ctx.acceptWebSocket(server);

		const httpUrl = backendUrl.replace("wss:", "https:").replace("ws:", "http:");
		try {
			const upstreamResp = await fetch(httpUrl, {
				headers: {
					Upgrade: "websocket",
					"CF-Access-Client-Id": accessClientId,
					"CF-Access-Client-Secret": accessClientSecret,
					"X-Creator-Name": creatorName,
				},
			});
			const upstreamWs = (upstreamResp as any).webSocket as WebSocket | undefined;
			if (!upstreamWs) {
				const body = await upstreamResp.text();
				server.send(JSON.stringify({ type: "error", message: `Upstream ${upstreamResp.status}: ${body.slice(0, 300)}` }));
				server.close(1011, "upstream failed");
				return new Response(null, { status: 101, webSocket: client });
			}
			upstreamWs.accept();
			this.upstream = upstreamWs;

			upstreamWs.addEventListener("message", (e) => {
				try { server.send(typeof e.data === "string" ? e.data : e.data); } catch {}
			});
			upstreamWs.addEventListener("close", (e) => {
				try { server.close(e.code, e.reason); } catch {}
			});
			upstreamWs.addEventListener("error", () => {
				try { server.close(1011, "upstream error"); } catch {}
			});
		} catch (e) {
			server.send(JSON.stringify({ type: "error", message: "Upstream connect failed: " + String(e) }));
			server.close(1011, "upstream connect failed");
			return new Response(null, { status: 101, webSocket: client });
		}

		return new Response(null, { status: 101, webSocket: client });
	}

	async webSocketMessage(_ws: WebSocket, message: string | ArrayBuffer) {
		if (this.upstream) {
			try { this.upstream.send(typeof message === "string" ? message : message); } catch {}
		}
	}

	async webSocketClose(ws: WebSocket, code: number, reason: string) {
		if (this.upstream) {
			try { this.upstream.close(code, reason); } catch {}
		}
		ws.close(code, reason);
	}

	async webSocketError(ws: WebSocket) {
		if (this.upstream) {
			try { this.upstream.close(1011, "client error"); } catch {}
		}
		ws.close(1011, "error");
	}
}
