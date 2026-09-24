import fs from "node:fs";
import path from "node:path";

const FILE = process.env.OAUTH_STORE_FILE || "/data/oauth-store.json";

let data = { clients: {}, accessTokens: {}, refreshTokens: {} };

try {
  data = { ...data, ...JSON.parse(fs.readFileSync(FILE, "utf8")) };
} catch (err) {
  if (err.code !== "ENOENT") console.error("oauth store: failed to load", err.message);
}

function save() {
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  const tmp = `${FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
  fs.renameSync(tmp, FILE);
}

function purgeExpired() {
  const now = Date.now();
  let changed = false;
  for (const table of ["accessTokens", "refreshTokens"]) {
    for (const [k, v] of Object.entries(data[table])) {
      if (v.expiresAt <= now) {
        delete data[table][k];
        changed = true;
      }
    }
  }
  if (changed) save();
}
setInterval(purgeExpired, 60 * 60 * 1000).unref();
purgeExpired();

export const getClient = (id) => data.clients[id];

export function putClient(id, client) {
  data.clients[id] = client;
  save();
}

export function getAccessToken(token) {
  const t = data.accessTokens[token];
  return t && t.expiresAt > Date.now() ? t : undefined;
}

export function getRefreshToken(token) {
  const t = data.refreshTokens[token];
  return t && t.expiresAt > Date.now() ? t : undefined;
}

export function putTokens({ accessToken, refreshToken, access, refresh }) {
  data.accessTokens[accessToken] = access;
  data.refreshTokens[refreshToken] = refresh;
  save();
}

export function deleteRefreshToken(token) {
  delete data.refreshTokens[token];
  save();
}
