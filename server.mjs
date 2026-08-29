import http from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PIN = String(process.env.ADMIN_PIN || "2006").trim();
const ADMIN_SECRET = String(process.env.ADMIN_SECRET || "hokm-render-dariush-change-me");
const ADMIN_COOKIE = "hokm_admin";
const ADMIN_MAX_AGE = 7 * 24 * 60 * 60;
const DATA_FILE = process.env.DATA_FILE || join(ROOT, "hokm-data.json");

const staticFiles = new Map([
  ["/", ["assets/index.html", "text/html; charset=utf-8"]],
  ["/index.html", ["assets/index.html", "text/html; charset=utf-8"]],
  ["/assets/court-card-sprite.png", ["assets/court-card-sprite.png", "image/png"]],
  ["/assets/hokm-table-mobile.webp", ["assets/hokm-table-mobile.webp", "image/webp"]],
  ["/assets/hokm-table-tablet.webp", ["assets/hokm-table-tablet.webp", "image/webp"]],
  ["/assets/hokm-table-landscape.webp", ["assets/hokm-table-landscape.webp", "image/webp"]],
]);

let kv = {};
try {
  if (existsSync(DATA_FILE)) {
    const loaded = JSON.parse(readFileSync(DATA_FILE, "utf8"));
    if (loaded && typeof loaded === "object" && !Array.isArray(loaded)) kv = loaded;
  }
} catch (error) {
  console.warn("Could not load saved game data; starting clean.", error.message);
}

function saveData() {
  try {
    const temporary = `${DATA_FILE}.tmp`;
    writeFileSync(temporary, JSON.stringify(kv), "utf8");
    renameSync(temporary, DATA_FILE);
  } catch (error) {
    console.warn("Could not persist game data.", error.message);
  }
}

function sendJson(response, value, status = 200, headers = {}) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...headers,
  });
  response.end(JSON.stringify(value));
}

function parseCookies(request) {
  const result = {};
  for (const part of String(request.headers.cookie || "").split(";")) {
    const at = part.indexOf("=");
    if (at >= 0) result[part.slice(0, at).trim()] = decodeURIComponent(part.slice(at + 1).trim());
  }
  return result;
}

function sign(value) {
  return createHmac("sha256", ADMIN_SECRET).update(value).digest("hex");
}

function secureEqual(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function isAdmin(request) {
  const raw = parseCookies(request)[ADMIN_COOKIE];
  if (!raw) return false;
  const [expiryText, signature] = raw.split(".");
  const expiry = Number(expiryText);
  return Boolean(expiry && signature && expiry >= Date.now() && secureEqual(sign(expiryText), signature));
}

function adminCookie() {
  const expiry = Date.now() + ADMIN_MAX_AGE * 1000;
  return `${ADMIN_COOKIE}=${expiry}.${sign(String(expiry))}; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=${ADMIN_MAX_AGE}`;
}

function sameArray(left, right) {
  return JSON.stringify(left || null) === JSON.stringify(right || null);
}

function gameMutationNeedsAdmin(oldValue, newValue) {
  let oldState;
  let nextState;
  try {
    oldState = oldValue ? JSON.parse(oldValue) : null;
    nextState = JSON.parse(newValue);
  } catch {
    return true;
  }
  if (!oldState) return false;
  if (!sameArray(oldState.botSeats, nextState.botSeats)) return true;
  const oldNextHakem = Number.isInteger(oldState.nextHakemIndex) ? oldState.nextHakemIndex : null;
  const nextHakem = Number.isInteger(nextState.nextHakemIndex) ? nextState.nextHakemIndex : null;
  if (oldNextHakem !== nextHakem) return true;
  if (Boolean(oldState.nextHakemConfirmedAtMatchEnd) !== Boolean(nextState.nextHakemConfirmedAtMatchEnd)) return true;
  if (oldState.phase === "lobby" && nextState.phase !== "lobby") return true;
  if (oldState.phase !== "lobby" && nextState.phase === "lobby") return true;
  if (!sameArray(oldState.league, nextState.league)) {
    const oldLeague = oldState.league || [0, 0];
    const nextLeague = nextState.league || [0, 0];
    const delta = nextLeague[0] - oldLeague[0] + nextLeague[1] - oldLeague[1];
    const legitimateWin = delta === 1 && nextLeague[0] >= oldLeague[0] && nextLeague[1] >= oldLeague[1]
      && nextState.phase === "matchEnd" && nextState.matchResult && nextState.tricksWon
      && nextState.tricksWon[nextState.matchResult.team] >= 7;
    if (!legitimateWin) return true;
  }
  return false;
}

function gameMutationIsStale(oldValue, newValue) {
  if (!oldValue) return false;
  try {
    const oldState = JSON.parse(oldValue);
    const nextState = JSON.parse(newValue);
    if (typeof oldState.updatedAt !== "number") return false;
    return typeof nextState.baseUpdatedAt !== "number" || nextState.baseUpdatedAt !== oldState.updatedAt;
  } catch {
    return true;
  }
}

function readBody(request, limit = 2_000_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error("body too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); }
      catch { reject(new Error("invalid json")); }
    });
    request.on("error", reject);
  });
}

async function handleApi(request, response, url) {
  if (url.pathname === "/api/health") return sendJson(response, { ok: true, time: Date.now() });
  if (url.pathname === "/api/admin/status" && request.method === "GET") {
    return sendJson(response, { authenticated: isAdmin(request) });
  }
  if (url.pathname === "/api/admin/login" && request.method === "POST") {
    let body;
    try { body = await readBody(request); } catch { return sendJson(response, { error: "invalid body" }, 400); }
    if (String(body?.pin || "").trim() !== ADMIN_PIN) return sendJson(response, { error: "wrong pin" }, 401);
    return sendJson(response, { ok: true }, 200, { "set-cookie": adminCookie() });
  }
  if (url.pathname === "/api/admin/logout" && request.method === "POST") {
    return sendJson(response, { ok: true }, 200, {
      "set-cookie": `${ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=0`,
    });
  }

  const match = url.pathname.match(/^\/api\/kv\/(.+)$/);
  if (!match) return sendJson(response, { error: "not found" }, 404);
  let key;
  try { key = decodeURIComponent(match[1]); } catch { return sendJson(response, { error: "bad key" }, 400); }

  if (request.method === "GET") {
    return Object.hasOwn(kv, key)
      ? sendJson(response, { value: kv[key] })
      : sendJson(response, { error: "not found" }, 404);
  }
  if (request.method === "POST") {
    let body;
    try { body = await readBody(request); } catch { return sendJson(response, { error: "invalid body" }, 400); }
    if (typeof body?.value !== "string") return sendJson(response, { error: "body must be { value: string }" }, 400);
    const oldValue = Object.hasOwn(kv, key) ? kv[key] : null;
    if (key === "hokm_state_v1" && gameMutationIsStale(oldValue, body.value)) {
      return sendJson(response, { error: "stale game state" }, 409);
    }
    const protectedNames = key === "hokm_names_v1";
    const protectedGame = key === "hokm_state_v1" && gameMutationNeedsAdmin(oldValue, body.value);
    if ((protectedNames || protectedGame) && !isAdmin(request)) return sendJson(response, { error: "admin required" }, 403);
    kv[key] = body.value;
    saveData();
    return sendJson(response, { ok: true });
  }
  if (request.method === "DELETE") {
    if ((key === "hokm_state_v1" || key === "hokm_names_v1") && !isAdmin(request)) {
      return sendJson(response, { error: "admin required" }, 403);
    }
    delete kv[key];
    saveData();
    return sendJson(response, { ok: true });
  }
  return sendJson(response, { error: "method not allowed" }, 405);
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
  try {
    if (url.pathname.startsWith("/api/")) return await handleApi(request, response, url);
    const staticEntry = staticFiles.get(url.pathname);
    if (!staticEntry) {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      return response.end("Not found");
    }
    const [relativePath, contentType] = staticEntry;
    const body = readFileSync(join(ROOT, relativePath));
    response.writeHead(200, {
      "content-type": contentType,
      "cache-control": contentType.startsWith("text/html") ? "no-cache" : "public, max-age=86400",
      "x-content-type-options": "nosniff",
      "referrer-policy": "same-origin",
    });
    response.end(body);
  } catch (error) {
    console.error(error);
    if (!response.headersSent) sendJson(response, { error: "server error" }, 500);
    else response.end();
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Hokm Online is running on port ${PORT}`);
});
