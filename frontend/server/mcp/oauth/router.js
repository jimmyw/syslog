import { randomBytes } from "node:crypto";
import express from "express";
import { githubAuthorizeUrl, githubLoginForCode, isAllowed } from "./github.js";
import { verifyS256 } from "./pkce.js";
import * as store from "./store.js";

export const ISSUER = (process.env.PUBLIC_BASE_URL || "https://syslog.wennlund.nu").replace(/\/$/, "");
export const RESOURCE = `${ISSUER}/mcp`;
const GITHUB_CALLBACK = `${ISSUER}/mcp/oauth/github/callback`;

const ACCESS_TTL_MS = 60 * 60 * 1000;
const REFRESH_TTL_MS = 365 * 24 * 60 * 60 * 1000;
const PENDING_TTL_MS = 10 * 60 * 1000;
const CODE_TTL_MS = 60 * 1000;

const pending = new Map(); // txn -> authorize request awaiting GitHub login
const codes = new Map(); // auth code -> grant awaiting token exchange

const rand = () => randomBytes(32).toString("base64url");

setInterval(() => {
  const now = Date.now();
  for (const m of [pending, codes]) for (const [k, v] of m) if (v.expiresAt <= now) m.delete(k);
}, 60 * 1000).unref();

const authServerMetadata = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  registration_endpoint: `${ISSUER}/register`,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["none"],
  scopes_supported: [],
};

const resourceMetadata = {
  resource: RESOURCE,
  authorization_servers: [ISSUER],
  bearer_methods_supported: ["header"],
};

const page = (res, status, msg) =>
  res.status(status).type("html").send(`<!doctype html><meta charset="utf-8"><title>syslog</title><p>${msg}</p>`);

function redirectWithParams(res, base, params) {
  const u = new URL(base);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) u.searchParams.set(k, v);
  res.redirect(302, u.toString());
}

function issueTokens({ clientId, githubLogin }) {
  const accessToken = rand();
  const refreshToken = rand();
  store.putTokens({
    accessToken,
    refreshToken,
    access: { clientId, githubLogin, expiresAt: Date.now() + ACCESS_TTL_MS },
    refresh: { clientId, githubLogin, expiresAt: Date.now() + REFRESH_TTL_MS },
  });
  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TTL_MS / 1000,
    refresh_token: refreshToken,
  };
}

export const router = express.Router();

router.get(
  [
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
  ],
  (_req, res) => res.json(resourceMetadata)
);

router.get(
  [
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/mcp",
    "/.well-known/openid-configuration",
    "/.well-known/openid-configuration/mcp",
    "/mcp/.well-known/openid-configuration",
  ],
  (_req, res) => res.json(authServerMetadata)
);

router.post("/register", (req, res) => {
  const { redirect_uris, client_name } = req.body || {};
  const valid =
    Array.isArray(redirect_uris) &&
    redirect_uris.length > 0 &&
    redirect_uris.length <= 10 &&
    redirect_uris.every((u) => {
      try {
        new URL(u);
        return typeof u === "string" && u.length <= 2048;
      } catch {
        return false;
      }
    });
  if (!valid) {
    return res.status(400).json({ error: "invalid_redirect_uri", error_description: "redirect_uris must be a list of valid URLs" });
  }
  const clientId = rand();
  const client = {
    redirectUris: redirect_uris,
    name: typeof client_name === "string" ? client_name.slice(0, 100) : undefined,
    createdAt: Date.now(),
  };
  store.putClient(clientId, client);
  res.status(201).json({
    client_id: clientId,
    client_name: client.name,
    redirect_uris: redirect_uris,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    client_id_issued_at: Math.floor(client.createdAt / 1000),
  });
});

router.get("/authorize", (req, res) => {
  const q = req.query;
  const client = typeof q.client_id === "string" ? store.getClient(q.client_id) : undefined;
  if (!client) return page(res, 400, "Unknown client_id.");
  if (typeof q.redirect_uri !== "string" || !client.redirectUris.includes(q.redirect_uri)) {
    return page(res, 400, "redirect_uri does not match the registered client.");
  }
  const fail = (error, description) =>
    redirectWithParams(res, q.redirect_uri, { error, error_description: description, state: q.state });

  if (q.response_type !== "code") return fail("unsupported_response_type", "only response_type=code is supported");
  if (typeof q.code_challenge !== "string" || q.code_challenge_method !== "S256") {
    return fail("invalid_request", "PKCE with code_challenge_method=S256 is required");
  }
  if (q.resource !== undefined && q.resource !== RESOURCE) {
    return fail("invalid_target", `resource must be ${RESOURCE}`);
  }

  const txn = rand();
  pending.set(txn, {
    clientId: q.client_id,
    redirectUri: q.redirect_uri,
    state: typeof q.state === "string" ? q.state : undefined,
    codeChallenge: q.code_challenge,
    expiresAt: Date.now() + PENDING_TTL_MS,
  });
  res.redirect(302, githubAuthorizeUrl(txn, GITHUB_CALLBACK));
});

router.get("/mcp/oauth/github/callback", async (req, res) => {
  const txn = typeof req.query.state === "string" ? req.query.state : "";
  const p = pending.get(txn);
  if (!p) return page(res, 400, "Login session expired or unknown. Restart the login from your MCP client.");
  pending.delete(txn);
  if (p.expiresAt <= Date.now()) return page(res, 400, "Login session expired. Restart the login from your MCP client.");

  if (typeof req.query.code !== "string") {
    return redirectWithParams(res, p.redirectUri, {
      error: "access_denied",
      error_description: "GitHub login was not completed",
      state: p.state,
    });
  }

  let login;
  try {
    login = await githubLoginForCode(req.query.code, GITHUB_CALLBACK);
  } catch (err) {
    console.error("oauth: github login failed:", err.message);
    return page(res, 502, "GitHub login failed. Try again.");
  }
  if (!isAllowed(login)) {
    console.warn(`oauth: denied github user ${login}`);
    return page(res, 403, "Access denied: this GitHub account is not allowed.");
  }

  const code = rand();
  codes.set(code, {
    clientId: p.clientId,
    redirectUri: p.redirectUri,
    codeChallenge: p.codeChallenge,
    githubLogin: login,
    expiresAt: Date.now() + CODE_TTL_MS,
  });
  redirectWithParams(res, p.redirectUri, { code, state: p.state });
});

router.post("/token", express.urlencoded({ extended: false }), (req, res) => {
  res.set("Cache-Control", "no-store");
  const b = req.body || {};
  const err = (status, error, description) =>
    res.status(status).json({ error, error_description: description });

  const client = typeof b.client_id === "string" ? store.getClient(b.client_id) : undefined;
  if (!client) return err(401, "invalid_client", "unknown client_id");

  if (b.grant_type === "authorization_code") {
    const grant = codes.get(b.code);
    codes.delete(b.code); // single use
    if (!grant || grant.expiresAt <= Date.now() || grant.clientId !== b.client_id) {
      return err(400, "invalid_grant", "invalid or expired code");
    }
    if (b.redirect_uri !== grant.redirectUri) return err(400, "invalid_grant", "redirect_uri mismatch");
    if (!verifyS256(b.code_verifier, grant.codeChallenge)) return err(400, "invalid_grant", "PKCE verification failed");
    return res.json(issueTokens({ clientId: grant.clientId, githubLogin: grant.githubLogin }));
  }

  if (b.grant_type === "refresh_token") {
    const rt = store.getRefreshToken(b.refresh_token);
    if (!rt || rt.clientId !== b.client_id) return err(400, "invalid_grant", "invalid refresh token");
    store.deleteRefreshToken(b.refresh_token); // rotate
    if (!isAllowed(rt.githubLogin)) return err(400, "invalid_grant", "user no longer allowed");
    return res.json(issueTokens({ clientId: rt.clientId, githubLogin: rt.githubLogin }));
  }

  err(400, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token");
});

export function requireBearerAuth(req, res, next) {
  const m = /^Bearer (.+)$/i.exec(req.headers.authorization || "");
  const t = m && store.getAccessToken(m[1]);
  if (!t || !isAllowed(t.githubLogin)) {
    res
      .status(401)
      .set(
        "WWW-Authenticate",
        `Bearer resource_metadata="${ISSUER}/.well-known/oauth-protected-resource/mcp"`
      )
      .json({ error: "invalid_token" });
    return;
  }
  req.githubLogin = t.githubLogin;
  next();
}
