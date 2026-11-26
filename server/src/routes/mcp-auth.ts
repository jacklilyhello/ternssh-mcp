import { createMiddleware } from "hono/factory";
import { getAuthMode } from "../auth/identity";
import { authenticateMcpToken, digestToken } from "../db/mcp-access";

export type McpEnvironment = { Bindings: Env; Variables: { token: string; digest: string } };

export function unauthorized() {
  return new Response(null, { status: 401, headers: {
    "WWW-Authenticate": 'Bearer realm="ternssh-mcp"', "Cache-Control": "no-store",
  } });
}

export const requireMcpToken = createMiddleware<McpEnvironment>(async (c, next) => {
  c.header("Cache-Control", "no-store");
  c.header("X-Robots-Tag", "noindex, nofollow, noarchive");
  const origin = c.req.header("Origin");
  if ((origin !== undefined && origin !== new URL(c.req.url).origin) || c.req.header("Sec-Fetch-Site") === "cross-site") {
    return c.body(null, 403);
  }
  const match = /^Bearer (tmcp_[A-Za-z0-9_-]{43})$/i.exec(c.req.header("Authorization") ?? "");
  if (!match) return unauthorized();
  if (await getAuthMode(c.env) === "onboarding") return c.body(null, 403);
  if (!await authenticateMcpToken(c.env.DB, match[1])) return unauthorized();
  c.set("token", match[1]);
  c.set("digest", await digestToken(match[1]));
  return next();
});
