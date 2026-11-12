// One address for two things:
//   https://YOUR-NAME.workers.dev/        the project site, served from GitHub Pages
//   https://YOUR-NAME.workers.dev/mcp     your mcpgate, reached through Tailscale Funnel
// Edit the two lines below, then paste this file into a Cloudflare Worker (see README, "One address").

const GATEWAY = "https://piyush.tail799736.ts.net";     // your Funnel address, no path, port 443
const SITE = "https://piyushchy.is-a.dev/mcp";           // where the GitHub Pages site lives, no trailing slash

// everything the gateway answers (the MCP endpoint and the sign-in pages claude.ai uses)
const GATEWAY_PATHS = ["/mcp", "/.well-known/", "/authorize", "/token", "/register", "/revoke", "/consent"];

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const toGateway = GATEWAY_PATHS.some((p) => (p.endsWith("/") ? url.pathname.startsWith(p) : url.pathname === p || url.pathname.startsWith(p + "/")));
    if (toGateway) {
      // pass the request through untouched: method, headers, body and streaming all stay as they are
      return fetch(new Request(GATEWAY + url.pathname + url.search, request), { redirect: "manual" });
    }
    if (request.method !== "GET" && request.method !== "HEAD") return new Response("Not found", { status: 404 });
    const path = url.pathname === "/" ? "/" : url.pathname;
    return fetch(SITE + path + url.search, { redirect: "follow", headers: { accept: request.headers.get("accept") || "*/*" } });
  },
};
