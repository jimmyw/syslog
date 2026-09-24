const CLIENT_ID = process.env.MCP_GITHUB_CLIENT_ID;
const CLIENT_SECRET = process.env.MCP_GITHUB_CLIENT_SECRET;
const ALLOWED = (process.env.GITHUB_ALLOWED_USERS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

export function githubAuthorizeUrl(state, redirectUri) {
  const u = new URL("https://github.com/login/oauth/authorize");
  u.searchParams.set("client_id", CLIENT_ID);
  u.searchParams.set("redirect_uri", redirectUri);
  u.searchParams.set("scope", "read:user");
  u.searchParams.set("state", state);
  return u.toString();
}

export async function githubLoginForCode(code, redirectUri) {
  const tokRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      redirect_uri: redirectUri,
    }),
  });
  const tok = await tokRes.json();
  if (!tok.access_token) throw new Error(`github token exchange failed: ${tok.error || tokRes.status}`);

  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${tok.access_token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "syslog-mcp",
    },
  });
  if (!userRes.ok) throw new Error(`github user lookup failed: ${userRes.status}`);
  return (await userRes.json()).login;
}

export const isAllowed = (login) => ALLOWED.includes(String(login).toLowerCase());
