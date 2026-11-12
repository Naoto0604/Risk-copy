interface Env {
  RISKTRACE_ORIGIN: string;
  RISKTRACE_PROXY_TOKEN: string;
}

const HOP_BY_HOP_HEADERS = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

function originUrl(configured: string): URL {
  const origin = new URL(configured);
  if (
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash
  ) {
    throw new Error("RISKTRACE_ORIGIN must be an HTTPS origin without a path");
  }
  return origin;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (!env.RISKTRACE_ORIGIN || !env.RISKTRACE_PROXY_TOKEN) {
      return new Response("RiskTrace gateway is not configured", { status: 503 });
    }

    let upstream: URL;
    try {
      const base = originUrl(env.RISKTRACE_ORIGIN);
      const incoming = new URL(request.url);
      upstream = new URL(incoming.pathname + incoming.search, base);
    } catch {
      return new Response("RiskTrace gateway has an invalid origin configuration", {
        status: 503,
      });
    }

    const headers = new Headers(request.headers);
    for (const header of HOP_BY_HOP_HEADERS) headers.delete(header);
    headers.delete("host");
    headers.delete("x-forwarded-for");
    headers.delete("x-forwarded-host");
    headers.delete("x-forwarded-proto");
    headers.delete("x-risktrace-proxy-token");
    headers.set("X-RiskTrace-Proxy-Token", env.RISKTRACE_PROXY_TOKEN);
    headers.set("X-Forwarded-Host", new URL(request.url).host);
    headers.set("X-Forwarded-Proto", "https");
    const clientIp = request.headers.get("CF-Connecting-IP");
    if (clientIp) headers.set("X-Forwarded-For", clientIp);

    const init: RequestInit = {
      method: request.method,
      headers,
      redirect: "manual",
    };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body;
    }

    try {
      const response = await fetch(upstream, init);
      const responseHeaders = new Headers(response.headers);
      for (const header of HOP_BY_HOP_HEADERS) responseHeaders.delete(header);
      responseHeaders.set("Cache-Control", "private, no-store");
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch {
      return new Response("RiskTrace backend is unavailable", { status: 502 });
    }
  },
} satisfies ExportedHandler<Env>;
