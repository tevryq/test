// src/index.js — YT Player (Cloudflare Worker + KV binding "VIDEOS")
//
// Setup:
//   1. KV namespace bound as  VIDEOS
//   2. wrangler secret put ADMIN_PASSWORD      (admin login: user "admin")
//   3. Open /admin  ->  "Paste raw request"  ->  paste a  GET /watch?v=...  request copied from your browser
//   4. Use "Test" in the admin page to see exactly what YouTube returns before you press play.

const ADMIN_USER = "admin";
const GLOBAL_COOKIE_KEY = "setting:cookie";
const COOKIE_AT_KEY = "setting:cookie_at";
const HEADERS_KEY = "setting:headers";

const DEFAULT_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36";
const DEFAULT_CH_UA = '"Chromium";v="127", "Not)A;Brand";v="99"';

// Only "browser identity" headers are ever kept from a pasted request. Everything else
// (Authorization, Content-Type, Origin, Accept, Sec-Fetch-*, X-Goog-*, Referer ...) belongs to
// that one request and would break the watch-page request, so it is dropped.
const IDENTITY_HEADERS = new Set([
  "user-agent", "accept-language", "device-memory",
  "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-platform-version",
  "sec-ch-ua-full-version", "sec-ch-ua-full-version-list", "sec-ch-ua-arch", "sec-ch-ua-bitness",
  "sec-ch-ua-model", "sec-ch-ua-wow64", "sec-ch-ua-form-factors",
  "sec-ch-dpr", "sec-ch-viewport-width",
]);
// The subset that is forwarded to the video servers by /proxy.
const PROXY_HEADERS = ["user-agent", "accept-language", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"];

/* ---------- helpers ---------- */

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// Safe JSON embedding inside <script>
function jsonForScript(obj) {
  return JSON.stringify(obj).replace(/</g, "\\u003c").replace(/\u2028|\u2029/g, "");
}

function parseVideoId(input) {
  const s = String(input || "").trim();
  if (/^[A-Za-z0-9_-]{11}$/.test(s)) return s;
  const m = s.match(/(?:v=|youtu\.be\/|\/shorts\/|\/embed\/|\/live\/)([A-Za-z0-9_-]{11})/);
  return m ? m[1] : null;
}

// A Cookie header must be one line of printable ASCII. Also accepts "Cookie: a=b; c=d" pasted whole.
function cleanCookie(s) {
  return String(s || "")
    .replace(/^\s*cookie\s*:\s*/i, "")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/[^\x20-\x7E]/g, "")
    .replace(/\s{2,}/g, " ")
    .trim();
}

function ago(ms) {
  if (!ms) return "unknown time ago";
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 90) return s + " s ago";
  if (s < 5400) return Math.round(s / 60) + " min ago";
  if (s < 129600) return Math.round(s / 3600) + " h ago";
  return Math.round(s / 86400) + " days ago";
}

function validHeader(name, value) {
  try { new Headers().append(name, value); return true; } catch { return false; }
}

// Keep only identity headers with valid values (also cleans anything saved by older versions).
function sanitizeHeaders(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) {
    const lower = String(k).toLowerCase();
    if (IDENTITY_HEADERS.has(lower) && typeof v === "string" && v && validHeader(lower, v)) out[lower] = v;
  }
  return out;
}

// Parse a raw HTTP request copied from the browser / Burp (request line + "Name: value" lines).
// Returns { headers (identity only), cookie, method, path }.
function parseRawRequest(raw) {
  const text = String(raw || "")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1") // strip markdown links like [host](https://host)
    .replace(/\r/g, "");
  const lines = text.split("\n").map((l) => l.trim());
  const first = lines.find((l) => l) || "";
  const rl = first.match(/^([A-Z]+)\s+(\S+)\s+HTTP\/[\d.]+$/);
  const headers = {};
  let cookie = "";
  for (const l of lines) {
    const i = l.indexOf(":");
    if (i <= 0) continue; // blank, request line, body line
    const name = l.slice(0, i).trim();
    if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(name)) continue;
    const value = l.slice(i + 1).trim();
    const lower = name.toLowerCase();
    if (lower === "cookie") { cookie = cleanCookie(value); continue; }
    if (!IDENTITY_HEADERS.has(lower) || !value || !validHeader(name, value)) continue;
    headers[lower] = value;
  }
  return { headers, cookie, method: rl ? rl[1] : "", path: rl ? rl[2] : "" };
}

async function sha256(s) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
}

async function safeEqual(a, b) {
  const [ha, hb] = await Promise.all([sha256(a), sha256(b)]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

function unauthorized() {
  return new Response("Authentication required", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="Admin", charset="UTF-8"' },
  });
}

async function checkAuth(request, env) {
  // No default password: if the secret isn't set, admin is disabled.
  if (!env.ADMIN_PASSWORD) return false;
  const h = request.headers.get("Authorization") || "";
  if (!h.startsWith("Basic ")) return false;
  try {
    const bytes = Uint8Array.from(atob(h.slice(6)), (c) => c.charCodeAt(0));
    const decoded = new TextDecoder().decode(bytes);
    const i = decoded.indexOf(":");
    if (i < 0) return false;
    const okUser = await safeEqual(decoded.slice(0, i), ADMIN_USER);
    const okPass = await safeEqual(decoded.slice(i + 1), env.ADMIN_PASSWORD);
    return okUser && okPass;
  } catch {
    return false;
  }
}

// Basic-auth is sent automatically by browsers, so block cross-site POSTs.
function sameOrigin(request) {
  const site = request.headers.get("Sec-Fetch-Site");
  if (site) return site === "same-origin" || site === "none";
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  try { return new URL(origin).host === new URL(request.url).host; } catch { return false; }
}

function redirect(request, path) {
  return Response.redirect(new URL(path, request.url).toString(), 303);
}

async function listVideos(env) {
  const keys = [];
  let cursor;
  do {
    const res = await env.VIDEOS.list({ prefix: "video:", cursor });
    keys.push(...res.keys);
    cursor = res.list_complete ? undefined : res.cursor;
  } while (cursor);
  const records = await Promise.all(keys.map((k) => env.VIDEOS.get(k.name, "json")));
  return records.filter(Boolean).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
}

const thumbUrl = (id) => `https://i.ytimg.com/vi/${encodeURIComponent(id)}/mqdefault.jpg`;

/* ---------- layout ---------- */

const CSS = `
:root{
  --bg:#0f1115;--panel:#171a21;--panel2:#1e222b;--line:#2a2f3a;
  --text:#e8eaf0;--muted:#8b93a5;--accent:#4f8cff;--accent2:#3a72e0;
  --danger:#d9534f;--ok:#2ea66f;color-scheme:dark;
}
@media (prefers-color-scheme: light){
  :root{--bg:#f5f6f8;--panel:#fff;--panel2:#f0f2f6;--line:#dfe3ea;
    --text:#1a1d24;--muted:#6a7285;--accent:#2f6fed;--accent2:#2459c9;color-scheme:light}
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.top{position:sticky;top:0;z-index:5;background:var(--panel);border-bottom:1px solid var(--line)}
.top .in{max-width:1100px;margin:0 auto;padding:12px 20px;display:flex;align-items:center;gap:16px}
.brand{font-weight:700;font-size:17px;color:var(--text)}
.brand span{color:#ff4d4d}
.top nav{margin-left:auto;display:flex;gap:14px;font-size:14px}
.wrap{max-width:1100px;margin:0 auto;padding:24px 20px 60px}
h1{font-size:22px;margin:0 0 16px}
h2{font-size:15px;margin:28px 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.muted{color:var(--muted);font-size:13px}
.search{width:100%;max-width:420px;padding:10px 14px;border-radius:10px;border:1px solid var(--line);
  background:var(--panel);color:var(--text);font-size:14px;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:16px}
.card{display:block;background:var(--panel);border:1px solid var(--line);border-radius:12px;
  overflow:hidden;color:inherit;transition:transform .12s,border-color .12s}
.card:hover{transform:translateY(-2px);border-color:var(--accent);text-decoration:none}
.card .img{position:relative;aspect-ratio:16/9;background:#000 center/cover no-repeat}
.card .img::after{content:"▶";position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
  font-size:30px;color:#fff;opacity:0;background:rgba(0,0,0,.35);transition:opacity .12s}
.card:hover .img::after{opacity:1}
.card .meta{padding:10px 12px}
.card .t{font-weight:600;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.empty{text-align:center;padding:60px 20px;background:var(--panel);border:1px dashed var(--line);border-radius:12px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}
.form label{display:block;margin-bottom:14px;font-size:13px;color:var(--muted)}
.form input,.form textarea{display:block;width:100%;margin-top:6px;padding:10px 12px;background:var(--panel2);
  border:1px solid var(--line);border-radius:8px;color:var(--text);font:inherit;font-size:14px}
.form textarea{font-family:ui-monospace,Menlo,monospace;font-size:12px}
.form input:focus,.form textarea:focus,.search:focus{outline:2px solid var(--accent);outline-offset:-1px}
.btn{display:inline-block;padding:9px 16px;background:var(--accent);color:#fff;border:0;border-radius:8px;
  font-weight:600;cursor:pointer;font-size:14px}
.btn:hover{background:var(--accent2);text-decoration:none}
.btn.ghost{background:var(--panel2);color:var(--text);border:1px solid var(--line)}
.btn.danger{background:var(--danger)}
.btn.sm{padding:5px 10px;font-size:12px}
.tbl{width:100%;border-collapse:collapse;font-size:14px}
.tbl th,.tbl td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:middle}
.tbl th{color:var(--muted);font-weight:500;font-size:12px;text-transform:uppercase}
.tbl .thumbs{width:96px;border-radius:6px;display:block}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.actions form{margin:0}
.flash{padding:10px 14px;border-radius:8px;margin-bottom:16px;background:rgba(46,166,111,.15);
  border:1px solid var(--ok);font-size:14px}
.flash.err{background:rgba(217,83,79,.15);border-color:var(--danger)}
.player{width:100%;max-width:1000px;background:#000;border-radius:12px;aspect-ratio:16/9;display:block}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:12px}
select{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:6px 10px}
.table-wrap{overflow-x:auto}
`;

const EXTRA_CSS = `
.kv td:first-child{color:var(--muted);width:250px}
.good{color:var(--ok);font-weight:600}.bad{color:var(--danger);font-weight:600}.warn{color:#e0a030;font-weight:600}
code{background:var(--panel2);padding:1px 5px;border-radius:4px;font-size:12px}
.flash.ok2{background:rgba(46,166,111,.15);border-color:var(--ok)}
`;

function htmlPage(body, { status = 200, title = "YT Player" } = {}) {
  return new Response(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${CSS}${EXTRA_CSS}</style></head>
<body>
<header class="top"><div class="in">
  <a class="brand" href="/"><span>▶</span> YT Player</a>
  <nav><a href="/">Library</a><a href="/admin">Admin</a></nav>
</div></header>
<main class="wrap">${body}</main>
</body></html>`, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "same-origin",
    },
  });
}

function errorPage(msg, detail = "", status = 502, id = "") {
  return htmlPage(`
    <h1>Couldn't load video</h1>
    <div class="flash err">${escapeHtml(msg)}</div>
    ${detail ? `<p class="muted">${escapeHtml(detail)}</p>` : ""}
    <div class="row">
      ${id ? `<a class="btn" href="/watch?id=${encodeURIComponent(id)}">Try again</a>` : ""}
      ${id ? `<a class="btn ghost" href="/admin/test?id=${encodeURIComponent(id)}">Run diagnostics</a>` : ""}
      <a class="btn ghost" href="/">Back to library</a>
    </div>`, { status, title: "Error" });
}

/* ---------- YouTube parsing ---------- */

function extractPlayerResponse(html) {
  const re = /ytInitialPlayerResponse\s*=\s*/g;
  let m;
  let fallback = null;
  while ((m = re.exec(html)) !== null) {
    const start = m.index + m[0].length;
    if (html[start] !== "{") continue;
    const parsed = parseBalancedJson(html, start);
    if (parsed && parsed.streamingData) return parsed;
    if (parsed && parsed.playabilityStatus && !fallback) fallback = parsed; // error responses have no streamingData
  }
  return fallback;
}

function parseBalancedJson(html, start) {
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < html.length; i++) {
    const c = html[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
    } else if (c === '"') inStr = true;
    else if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) {
        try { return JSON.parse(html.slice(start, i + 1)); } catch { return null; }
      }
    }
  }
  return null;
}

/* ---------- talking to YouTube ---------- */

// Builds the headers for the watch-page request: sane navigation defaults + the saved browser identity.
async function ytHeaders(env, cookie) {
  const saved = sanitizeHeaders(await env.VIDEOS.get(HEADERS_KEY, "json"));
  const h = new Headers({
    "User-Agent": DEFAULT_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "max-age=0",
    "Upgrade-Insecure-Requests": "1",
    "Referer": "https://studio.youtube.com/",
    "Sec-Ch-Ua": DEFAULT_CH_UA,
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Site": "same-site",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
  });
  // If the saved browser has its own User-Agent, drop our default client hints so the two can't disagree.
  if (saved["user-agent"] && !saved["sec-ch-ua"]) {
    h.delete("Sec-Ch-Ua"); h.delete("Sec-Ch-Ua-Mobile"); h.delete("Sec-Ch-Ua-Platform");
  }
  for (const [k, v] of Object.entries(saved)) { try { h.set(k, v); } catch {} }
  if (cookie) h.set("Cookie", cookie);
  return h;
}

async function fetchWatchPage(env, id, ownCookie) {
  const base = ownCookie || (await env.VIDEOS.get(GLOBAL_COOKIE_KEY)) || "";
  const hadCookie = !!base;
  // SOCS=CAI = "consent already given"; avoids the EU/data-center consent interstitial.
  const cookie = /(^|;\s*)SOCS=/.test(base) ? base : (base ? base + "; SOCS=CAI" : "SOCS=CAI");
  const headers = await ytHeaders(env, cookie);
  const ytUrl = `https://www.youtube.com/watch?v=${encodeURIComponent(id)}&bpctr=9999999999&has_verified=1`;
  let res, html;
  try {
    res = await fetch(ytUrl, { headers, redirect: "follow", signal: AbortSignal.timeout(20000) });
    html = await res.text();
  } catch (e) {
    return { netError: String(e?.message || e), hadCookie };
  }
  const pr = extractPlayerResponse(html);
  const lm = html.match(/"LOGGED_IN"\s*:\s*(true|false)/);
  return { status: res.status, finalUrl: res.url || "", html, pr, hadCookie, loggedIn: lm ? lm[1] === "true" : null };
}

function explainNoPlayer(r) {
  const h = r.html || "";
  const u = r.finalUrl || "";
  if (/consent\.(youtube|google)\.com/.test(u)) {
    return { msg: "YouTube showed its cookie-consent page.", detail: "Paste a fresh GET /watch request from a logged-in browser so the cookie includes the consent values (SOCS / CONSENT)." };
  }
  if (r.status === 429 || /\/sorry\//.test(u) || /unusual traffic|g-recaptcha/i.test(h)) {
    return { msg: "YouTube is bot-checking / rate-limiting this worker's IP.", detail: "Cloudflare data-center IPs are sometimes blocked. Wait a while and retry, or use 'Import streaming data' (copy the page source from your own browser)." };
  }
  if (r.status >= 400) {
    return { msg: `YouTube returned HTTP ${r.status}.`, detail: "The video may be removed or private, or the request was refused." };
  }
  if (r.loggedIn === false) {
    return { msg: "The page loaded as logged out, so no video data was returned.", detail: "Your cookie is expired or incomplete. Paste a fresh GET /watch request (Incognito window works best, then close it)." };
  }
  return { msg: "Could not read the video data from YouTube.", detail: "The cookie may be missing or expired, or YouTube served a bot-check page. Run diagnostics for details." };
}

function explainStatus(ps, r) {
  const reason = ps.reason || ps.errorScreen?.playerErrorMessageRenderer?.reason?.simpleText || "";
  let hint = "";
  if (ps.status === "LOGIN_REQUIRED") {
    hint = r.loggedIn === false
      ? "The cookie looks logged out/expired. Paste a fresh GET /watch request."
      : "YouTube wants a sign-in or bot check — common for data-center IPs, or when the cookie is stale.";
  } else if (ps.status === "UNPLAYABLE") {
    hint = "The video can't be played here (region/age/embedding restriction or private).";
  } else if (ps.status === "ERROR") {
    hint = "The video is unavailable or removed.";
  }
  return [reason, hint].filter(Boolean).join(" — ");
}

// One place that decides "can this page be played, and with which streams?" (used by /watch and /admin/test)
function analyze(r) {
  if (r.netError) return { ok: false, msg: "Could not reach YouTube.", detail: r.netError, sd: {}, muxed: [] };
  if (!r.pr) return { ok: false, ...explainNoPlayer(r), sd: {}, muxed: [] };
  const ps = r.pr.playabilityStatus || {};
  const sd = r.pr.streamingData || {};
  const all = sd.formats || [];
  const muxed = all
    .filter((f) => f.url && /^video\/mp4/i.test(f.mimeType || ""))
    .sort((a, b) => (b.height || 0) - (a.height || 0) || (b.bitrate || 0) - (a.bitrate || 0));
  if (ps.status !== "OK") {
    return { ok: false, msg: `YouTube status: ${ps.status || "unknown"}`, detail: explainStatus(ps, r), sd, muxed };
  }
  if (!muxed.length) {
    const ciphered = all.some((f) => f.signatureCipher || f.cipher);
    let detail = "YouTube returned no combined audio+video stream for this video.";
    if (ciphered) detail = "This video's streams are protected by a signature cipher, which this worker can't decode.";
    else if (sd.serverAbrStreamingUrl) detail = "YouTube returned this video only through its SABR streaming protocol (no direct links), which a <video> tag can't play. Try 'Import streaming data' from your browser, or another video.";
    return { ok: false, msg: "No directly playable stream was found.", detail, sd, muxed };
  }
  return { ok: true, sd, muxed };
}

/* ---------- router ---------- */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname.replace(/\/+$/, "") || "/";
    try {
      if (p.startsWith("/admin")) {
        if (!env.ADMIN_PASSWORD) {
          return new Response(
            "Admin disabled: run `wrangler secret put ADMIN_PASSWORD` and redeploy.",
            { status: 503 }
          );
        }
        if (!(await checkAuth(request, env))) return unauthorized();

        if (p === "/admin" && request.method === "GET") return handleAdminPage(url, env);
        if (p === "/admin/test" && request.method === "GET") return handleTest(url, env);
        if (request.method === "POST") {
          if (!sameOrigin(request)) return new Response("Bad origin", { status: 403 });
          if (p === "/admin/save") return handleSave(request, env);
          if (p === "/admin/delete") return handleDelete(request, env);
          if (p === "/admin/global-cookie") return handleGlobalCookie(request, env);
          if (p === "/admin/raw-request") return handleRawRequest(request, env);
          if (p === "/admin/import-player") return handleImportPlayer(request, env);
        }
        return new Response("Not found", { status: 404 });
      }
      if (p === "/watch") return handleWatch(request, env);
      if (p === "/proxy") return handleProxy(request, env);
      if (p === "/") return handleHome(env);
      return new Response("Not found", { status: 404 });
    } catch (err) {
      console.error(err?.stack || err);
      return new Response("Internal error", { status: 500 });
    }
  },
};

/* ---------- handlers ---------- */

async function handleHome(env) {
  const items = await listVideos(env);
  const cards = items.map((r) => `
    <a class="card" data-t="${escapeHtml((r.title || r.videoId).toLowerCase())}"
       href="/watch?id=${encodeURIComponent(r.videoId)}">
      <div class="img" style="background-image:url('${thumbUrl(r.videoId)}')"></div>
      <div class="meta"><div class="t">${escapeHtml(r.title || r.videoId)}</div></div>
    </a>`).join("");

  return htmlPage(`
    <h1>Library</h1>
    ${items.length === 0
      ? `<div class="empty"><p>No videos yet.</p><a class="btn" href="/admin">Add your first video</a></div>`
      : `<input class="search" id="q" type="search" placeholder="Search videos…" autocomplete="off">
         <div class="grid" id="grid">${cards}</div>
         <p class="muted" id="none" hidden>No matches.</p>
         <script>
           const q=document.getElementById('q'),cs=[...document.querySelectorAll('#grid .card')],none=document.getElementById('none');
           q.addEventListener('input',()=>{const v=q.value.trim().toLowerCase();let n=0;
             cs.forEach(c=>{const ok=c.dataset.t.includes(v);c.hidden=!ok;if(ok)n++});none.hidden=n>0});
         </script>`}
  `);
}

async function handleAdminPage(url, env) {
  const items = await listVideos(env);
  const globalCookie = await env.VIDEOS.get(GLOBAL_COOKIE_KEY);
  const cookieAt = Number(await env.VIDEOS.get(COOKIE_AT_KEY)) || 0;
  const savedHeaders = sanitizeHeaders(await env.VIDEOS.get(HEADERS_KEY, "json"));
  const savedCount = Object.keys(savedHeaders).length;
  const msg = url.searchParams.get("msg");
  const err = url.searchParams.get("err");
  const editId = url.searchParams.get("edit");
  const editing = editId ? items.find((r) => r.videoId === editId) : null;

  const rows = items.map((r) => `
    <tr>
      <td><img class="thumbs" loading="lazy" src="${thumbUrl(r.videoId)}" alt=""></td>
      <td><strong>${escapeHtml(r.title || "(untitled)")}</strong><div class="muted">${escapeHtml(r.videoId)}</div></td>
      <td class="muted">${r.cookie ? "own cookie" : globalCookie ? "global cookie" : "none"}</td>
      <td><div class="actions">
        <a class="btn sm" href="/watch?id=${encodeURIComponent(r.videoId)}" target="_blank" rel="noopener">Play</a>
        <a class="btn sm ghost" href="/admin/test?id=${encodeURIComponent(r.videoId)}">Test</a>
        <a class="btn sm ghost" href="/admin?edit=${encodeURIComponent(r.videoId)}#form">Edit</a>
        <form method="POST" action="/admin/delete" onsubmit="return confirm('Delete this video?')">
          <input type="hidden" name="videoId" value="${escapeHtml(r.videoId)}">
          <button class="btn sm danger" type="submit">Delete</button>
        </form>
      </div></td>
    </tr>`).join("");

  return htmlPage(`
    <h1>Admin</h1>
    ${msg ? `<div class="flash">${escapeHtml(msg)}</div>` : ""}
    ${err ? `<div class="flash err">${escapeHtml(err)}</div>` : ""}

    <h2>Status</h2>
    <div class="panel"><table class="tbl kv"><tbody>
      <tr><td>Global cookie</td><td class="${globalCookie ? "good" : "bad"}">${globalCookie ? `saved (${globalCookie.length} chars), ${escapeHtml(ago(cookieAt))}` : "not set"}</td></tr>
      <tr><td>Saved browser headers</td><td class="${savedCount ? "good" : "warn"}">${savedCount ? savedCount + " identity headers" : "none (built-in defaults are used)"}</td></tr>
    </tbody></table>
    <p class="muted" style="margin-bottom:0">Tip: if a video stops working after some hours/days, the cookie has expired — paste a fresh <code>GET /watch</code> request below.</p></div>

    <h2>Paste raw request</h2>
    <div class="panel">
      <form method="POST" action="/admin/raw-request" class="form">
        <label>Paste a <code>GET /watch?v=…</code> request copied from your browser (DevTools → Network → Doc → Copy request headers, or Burp → Raw).
          Only the Cookie and the browser identity headers (User-Agent, Sec-Ch-Ua*, Accept-Language …) are kept; everything else is ignored.
          <textarea name="raw" rows="8" placeholder="GET /watch?v=... HTTP/2&#10;Cookie: ...&#10;User-Agent: ...&#10;Accept: ..."></textarea>
        </label>
        <label style="display:flex;gap:8px;align-items:center">
          <input type="checkbox" name="clear" value="1" style="width:auto;margin:0"> Clear saved headers
        </label>
        <button class="btn" type="submit">Save request</button>
      </form>
    </div>

    <h2>Diagnostics</h2>
    <div class="panel">
      <form method="GET" action="/admin/test" class="form">
        <label>Test a video (checks cookie, login state, playability and available streams — without playing)
          <input name="id" required placeholder="https://www.youtube.com/watch?v=E0kdkDlIJUU  or  E0kdkDlIJUU">
        </label>
        <button class="btn" type="submit">Run test</button>
      </form>
    </div>

    <h2 id="form">${editing ? "Edit video" : "Add video"}</h2>
    <div class="panel">
      <form method="POST" action="/admin/save" class="form">
        <label>YouTube link or video ID
          <input name="video" required placeholder="https://youtu.be/dQw4w9WgXcQ  or  dQw4w9WgXcQ"
                 value="${escapeHtml(editing?.videoId || "")}" ${editing ? "readonly" : ""}>
        </label>
        <label>Title <span class="muted">(optional — filled in automatically on first play)</span>
          <input name="title" placeholder="My video" value="${escapeHtml(editing?.title || "")}">
        </label>
        <label>Cookie <span class="muted">(optional — overrides the global cookie
          ${editing?.cookie ? "· leave blank to keep the saved one" : ""})</span>
          <textarea name="cookie" rows="4" placeholder="VISITOR_INFO1_LIVE=...; SID=..."></textarea>
        </label>
        <div class="row" style="margin-top:0">
          <button class="btn" type="submit">${editing ? "Update" : "Save"}</button>
          ${editing ? `<a class="btn ghost" href="/admin">Cancel</a>` : ""}
        </div>
      </form>
    </div>

    <h2>Global cookie</h2>
    <div class="panel">
      <form method="POST" action="/admin/global-cookie" class="form">
        <label>Used for every video that has no cookie of its own (normally set automatically by "Paste raw request")
          <textarea name="cookie" rows="3" placeholder="Paste the Cookie header value. Leave blank and tick below to clear."></textarea>
        </label>
        <label style="display:flex;gap:8px;align-items:center">
          <input type="checkbox" name="clear" value="1" style="width:auto;margin:0"> Clear the global cookie
        </label>
        <button class="btn" type="submit">Save global cookie</button>
      </form>
    </div>

    <h2>Import streaming data (direct play)</h2>
    <div class="panel">
      <form method="POST" action="/admin/import-player" class="form">
        <label>Video link or ID <span class="muted">(needed when you paste only a streamingData snippet; optional for a full page)</span>
          <input name="video" placeholder="https://www.youtube.com/watch?v=E0kdkDlIJUU  or  E0kdkDlIJUU">
        </label>
        <label>Paste the page source (Ctrl+U on the watch page, select all, copy), or just the part starting
          <code>"streamingData":{"expiresInSeconds"…</code>. The 360p stream link is saved and plays directly, with no proxy.
          <textarea name="data" rows="6" placeholder='"streamingData":{"expiresInSeconds":"21540","formats":[{"itag":18,"url":"https://…' required></textarea>
        </label>
        <p class="muted">The link is tied to the IP of the browser it came from and expires after a few hours (about 6). Only the combined 360p stream has a direct link; higher qualities use YouTube's streaming protocol, which a video tag can't play.</p>
        <button class="btn" type="submit">Import</button>
      </form>
    </div>

    <h2>Videos (${items.length})</h2>
    ${items.length === 0
      ? `<p class="muted">None yet.</p>`
      : `<div class="panel table-wrap"><table class="tbl">
          <thead><tr><th></th><th>Video</th><th>Cookie</th><th></th></tr></thead>
          <tbody>${rows}</tbody></table></div>`}
  `, { title: "Admin · YT Player" });
}

async function handleTest(url, env) {
  const id = parseVideoId(url.searchParams.get("id"));
  if (!id) return htmlPage(`<h1>Diagnostics</h1><div class="flash err">Couldn't find a valid video ID.</div><a class="btn ghost" href="/admin">Back</a>`, { status: 400, title: "Diagnostics" });

  const rec = await env.VIDEOS.get(`video:${id}`, "json");
  const globalCookie = await env.VIDEOS.get(GLOBAL_COOKIE_KEY);
  const cookieAt = Number(await env.VIDEOS.get(COOKIE_AT_KEY)) || 0;
  const r = await fetchWatchPage(env, id, rec?.cookie);
  const a = analyze(r);
  const sd = a.sd || {};
  const adaptive = sd.adaptiveFormats || [];
  const row = (k, v, cls = "") => `<tr><td>${escapeHtml(k)}</td><td class="${cls}">${escapeHtml(String(v))}</td></tr>`;

  let where = "";
  try { const u = new URL(r.finalUrl); where = u.hostname + u.pathname; } catch {}
  const ps = r.pr?.playabilityStatus;

  const rows = [
    row("Cookie used", rec?.cookie ? "this video's own cookie" : globalCookie ? `global cookie (${ago(cookieAt)})` : "none", (rec?.cookie || globalCookie) ? "good" : "bad"),
    r.netError ? row("Network", r.netError, "bad") : row("HTTP status", r.status, r.status < 400 ? "good" : "bad"),
    where ? row("Final page", where, /consent|sorry/.test(where) ? "bad" : "") : "",
    row("Logged in (per page)", r.loggedIn === null ? "unknown" : r.loggedIn ? "yes" : "NO — cookie expired or invalid", r.loggedIn === false ? "bad" : r.loggedIn ? "good" : "warn"),
    row("Player data found", r.pr ? "yes" : "no", r.pr ? "good" : "bad"),
    ps ? row("Playability", `${ps.status || "?"}${ps.reason ? " — " + ps.reason : ""}`, ps.status === "OK" ? "good" : "bad") : "",
    r.pr?.videoDetails?.title ? row("Title", r.pr.videoDetails.title) : "",
    row("Combined audio+video streams with direct link", a.muxed.length ? a.muxed.map((f) => f.qualityLabel || (f.height ? f.height + "p" : "?")).join(", ") : "none", a.muxed.length ? "good" : "bad"),
    row("Adaptive formats listed", adaptive.length),
    row("Adaptive formats with direct link", adaptive.filter((f) => f.url).length),
    row("Signature-ciphered formats", [...(sd.formats || []), ...adaptive].filter((f) => f.signatureCipher || f.cipher).length),
    row("SABR-only streaming URL present", sd.serverAbrStreamingUrl ? "yes" : "no"),
  ].join("");

  return htmlPage(`
    <p><a href="/admin">← Admin</a></p>
    <h1>Diagnostics · ${escapeHtml(id)}</h1>
    <div class="flash ${a.ok ? "ok2" : "err"}">
      <strong>${a.ok ? "Ready to play." : escapeHtml(a.msg)}</strong>
      ${a.ok ? "" : `<div class="muted" style="margin-top:6px">${escapeHtml(a.detail || "")}</div>`}
    </div>
    <div class="panel"><table class="tbl kv"><tbody>${rows}</tbody></table></div>
    <div class="row">
      <a class="btn" href="/watch?id=${encodeURIComponent(id)}" target="_blank" rel="noopener">Play</a>
      <a class="btn ghost" href="/admin/test?id=${encodeURIComponent(id)}">Run again</a>
    </div>`, { title: "Diagnostics" });
}

async function handleSave(request, env) {
  const fd = await request.formData();
  const videoId = parseVideoId(fd.get("video"));
  if (!videoId) return redirect(request, "/admin?err=" + encodeURIComponent("Couldn't find a valid 11-character video ID in that input."));

  const key = `video:${videoId}`;
  const existing = await env.VIDEOS.get(key, "json");
  const title = String(fd.get("title") || "").trim().slice(0, 200);
  const newCookie = cleanCookie(fd.get("cookie"));

  await env.VIDEOS.put(key, JSON.stringify({
    videoId,
    title: title || existing?.title || "",
    cookie: newCookie || existing?.cookie || "",
    createdAt: existing?.createdAt || Date.now(),
    ...(existing?.direct ? { direct: existing.direct } : {}),
  }));
  return redirect(request, "/admin?msg=" + encodeURIComponent(existing ? "Video updated." : "Video added."));
}

async function handleDelete(request, env) {
  const fd = await request.formData();
  const videoId = parseVideoId(fd.get("videoId"));
  if (videoId) await env.VIDEOS.delete(`video:${videoId}`);
  return redirect(request, "/admin?msg=" + encodeURIComponent("Video deleted."));
}

async function handleGlobalCookie(request, env) {
  const fd = await request.formData();
  if (fd.get("clear")) {
    await env.VIDEOS.delete(GLOBAL_COOKIE_KEY);
    await env.VIDEOS.delete(COOKIE_AT_KEY);
    return redirect(request, "/admin?msg=" + encodeURIComponent("Global cookie cleared."));
  }
  const c = cleanCookie(fd.get("cookie"));
  if (!c) return redirect(request, "/admin?err=" + encodeURIComponent("Nothing to save."));
  await env.VIDEOS.put(GLOBAL_COOKIE_KEY, c);
  await env.VIDEOS.put(COOKIE_AT_KEY, String(Date.now()));
  return redirect(request, "/admin?msg=" + encodeURIComponent("Global cookie saved."));
}

async function handleRawRequest(request, env) {
  const fd = await request.formData();
  if (fd.get("clear")) {
    await env.VIDEOS.delete(HEADERS_KEY);
    return redirect(request, "/admin?msg=" + encodeURIComponent("Saved headers cleared."));
  }
  const { headers, cookie, method, path } = parseRawRequest(fd.get("raw"));
  const n = Object.keys(headers).length;
  if (!n && !cookie) {
    return redirect(request, "/admin?err=" + encodeURIComponent("Couldn't find a Cookie or any browser headers in that paste."));
  }
  if (n) await env.VIDEOS.put(HEADERS_KEY, JSON.stringify(headers));
  if (cookie) {
    await env.VIDEOS.put(GLOBAL_COOKIE_KEY, cookie);
    await env.VIDEOS.put(COOKIE_AT_KEY, String(Date.now()));
  }
  let msg = `Saved ${n} header${n === 1 ? "" : "s"}${cookie ? " and the cookie" : ""}.`;
  if (!cookie) msg += " Warning: no Cookie line was found, so the existing cookie (if any) is unchanged.";
  if (method && !(method === "GET" && path.startsWith("/watch"))) {
    msg += ` Note: that was a ${method} ${path.split("?")[0]} request, not GET /watch — only the cookie and browser identity were used, which is fine.`;
  }
  return redirect(request, "/admin?msg=" + encodeURIComponent(msg));
}

// Pull combined (audio+video) mp4 stream URLs out of pasted text. Tolerant on purpose: works on a full
// page, a full player-response JSON, or just a (possibly cut-off) `"streamingData":{...` fragment.
function extractDirectFormats(raw) {
  const found = new Map();
  const re = /"url"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(raw)) !== null) {
    let url;
    try { url = JSON.parse('"' + m[1] + '"'); } catch { continue; }
    let host;
    try { host = new URL(url).hostname.toLowerCase(); } catch { continue; }
    const okHost = /(^|\.)googlevideo\.com$/.test(host) || /^[a-z0-9-]+\.c\.youtube\.com$/.test(host);
    if (!okHost || !url.includes("/videoplayback")) continue;
    const after = raw.slice(m.index, m.index + 3000); // the other fields of the same format object
    const mime = (after.match(/"mimeType"\s*:\s*"((?:[^"\\]|\\.)*)"/) || [])[1] || "";
    if (!/^video\\?\/mp4/i.test(mime) || !/mp4a/i.test(mime)) continue; // need video AND audio in one stream
    const height = Number((after.match(/"height"\s*:\s*(\d+)/) || [])[1]) || 0;
    const label = (after.match(/"qualityLabel"\s*:\s*"([^"]+)"/) || [])[1] || (height ? height + "p" : "Default");
    if (!found.has(label)) found.set(label, { label, url, height });
  }
  return [...found.values()]
    .sort((a, b) => b.height - a.height)
    .map(({ label, url }) => ({ label, url }));
}

async function handleImportPlayer(request, env) {
  const fd = await request.formData();
  const raw = String(fd.get("data") || "");
  const fail = (m) => redirect(request, "/admin?err=" + encodeURIComponent(m));

  // A full page or player-response JSON also tells us the video ID, title and play status.
  let pr = extractPlayerResponse(raw);
  if (!pr) {
    try {
      const j = JSON.parse(raw.trim());
      pr = j.streamingData || j.playabilityStatus ? j : j.playerResponse || null;
    } catch {}
  }
  const videoId = parseVideoId(fd.get("video")) || pr?.videoDetails?.videoId;
  if (!videoId) {
    return fail("Which video is this? Put its link or ID in the first box (a streamingData snippet doesn't contain it).");
  }
  if (pr?.playabilityStatus?.status && pr.playabilityStatus.status !== "OK") {
    return fail(`YouTube status in that data: ${pr.playabilityStatus.status}.`);
  }

  const formats = extractDirectFormats(raw);
  if (!formats.length) {
    return fail("No direct stream URL (with audio and video together) found in that paste. Only the 360p stream usually has one.");
  }

  // Expiry: the sooner of expiresInSeconds and the URL's own expire= parameter, minus 5 minutes.
  const now = Date.now();
  const candidates = [];
  const secs = Number((raw.match(/"expiresInSeconds"\s*:\s*"?(\d+)/) || [])[1]);
  if (secs > 0) candidates.push(now + secs * 1000);
  try {
    const e = Number(new URL(formats[0].url).searchParams.get("expire"));
    if (e > 0) candidates.push(e * 1000);
  } catch {}
  const expires = (candidates.length ? Math.min(...candidates) : now + 3600 * 1000) - 5 * 60 * 1000;
  if (expires <= now) return fail("That streaming data has already expired. Copy a fresh page.");

  const key = `video:${videoId}`;
  const existing = await env.VIDEOS.get(key, "json");
  await env.VIDEOS.put(key, JSON.stringify({
    videoId,
    title: existing?.title || String(pr?.videoDetails?.title || "").slice(0, 200),
    cookie: existing?.cookie || "",
    createdAt: existing?.createdAt || now,
    direct: { formats, expires },
  }));
  const mins = Math.round((expires - now) / 60000);
  return redirect(request, "/admin?msg=" + encodeURIComponent(
    `Imported ${videoId}: ${formats.map((f) => f.label).join(", ")} direct link, valid for about ${mins} minutes.`));
}

async function handleWatch(request, env) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id") || "";
  if (!/^[A-Za-z0-9_-]{11}$/.test(id)) return errorPage("Missing or invalid video id.", "", 400);

  const rec = await env.VIDEOS.get(`video:${id}`, "json");
  if (!rec) return errorPage("Video not found in your library.", "", 404);
  const clientIp = request.headers.get("CF-Connecting-IP") || "";

  // A stream URL imported in the admin page (tied to the IP of the browser it was copied from)
  // plays straight away: no YouTube fetch. The browser tries the direct link first, then the proxy.
  if (rec.direct && rec.direct.expires > Date.now() && rec.direct.formats?.length) {
    const options = rec.direct.formats.map((f) => ({
      label: f.label,
      direct: f.url,
      src: "/proxy?u=" + encodeURIComponent(f.url),
    }));
    return playerPage(id, rec.title || id, options, { clientIp, imported: true });
  }

  const r = await fetchWatchPage(env, id, rec.cookie);
  const a = analyze(r);
  if (!a.ok) return errorPage(a.msg, a.detail, 502, id);

  // Auto-fill title on first play
  const ytTitle = r.pr?.videoDetails?.title;
  if (!rec.title && ytTitle) {
    rec.title = String(ytTitle).slice(0, 200);
    try { await env.VIDEOS.put(`video:${id}`, JSON.stringify(rec)); } catch {}
  }

  // These links were issued to the worker's IP, so the browser can't use them directly: go through /proxy.
  const options = a.muxed.map((f) => ({
    label: f.qualityLabel || (f.height ? f.height + "p" : "Default"),
    direct: f.url,
    src: "/proxy?u=" + encodeURIComponent(f.url),
  }));
  return playerPage(id, rec.title || ytTitle || id, options, { clientIp, imported: false });
}

function playerPage(id, title, options, { clientIp = "", imported = false } = {}) {
  // Imported links only work for the IP they were issued to. Show a clear warning when that isn't you.
  let linkIp = "";
  try { linkIp = new URL(options[0].direct).searchParams.get("ip") || ""; } catch {}
  const mismatch = imported && linkIp && clientIp && linkIp !== clientIp;
  return htmlPage(`
    <p><a href="/">← Library</a></p>
    <h1>${escapeHtml(title)}</h1>
    ${mismatch ? `<div class="flash err">This stream link is tied to IP ${escapeHtml(linkIp)}, but you are connecting from
      ${escapeHtml(clientIp)}. Your browser can't play it directly, and the proxy will probably be refused too.
      Import the streaming data again from a browser that uses the same IP as this one.</div>` : ""}
    <video id="v" class="player" controls playsinline preload="metadata" referrerpolicy="no-referrer" poster="${thumbUrl(id)}"></video>
    <div class="row">
      ${options.length > 1 ? `<label class="muted">Quality <select id="q"></select></label>` : ""}
      <span class="muted" id="status"></span>
    </div>
    <p class="muted">id: ${escapeHtml(id)}</p>
    <script>
      const opts=${jsonForScript(options)};
      const v=document.getElementById('v'),q=document.getElementById('q'),st=document.getElementById('status');
      let direct=${imported ? "true" : "false"}; // imported links: try the YouTube URL first; fetched links go via the proxy
      function load(i,keep){
        const t=keep?v.currentTime:0,playing=keep&&!v.paused;
        v.src=direct?opts[i].direct:opts[i].src;
        v.addEventListener('loadedmetadata',()=>{if(t)v.currentTime=t;if(playing)v.play().catch(()=>{})},{once:true});
      }
      if(q){opts.forEach((o,i)=>q.add(new Option(o.label,i)));q.onchange=()=>load(+q.value,true)}
      v.addEventListener('error',async()=>{
        if(direct){
          direct=false;
          st.textContent='Direct link refused, switching to proxy…';
          load(q?+q.value:0,true);
          return;
        }
        st.textContent='Playback failed. Checking why…';
        try{
          const r=await fetch(v.currentSrc||v.src,{headers:{Range:'bytes=0-0'}});
          st.textContent='Playback failed (stream server replied HTTP '+r.status+'). '+
            (r.status===403?'YouTube refused the request — the link is bound to a different IP or needs a PO token. Reload to get a fresh link.':'Reload to get a fresh link.');
        }catch(e){st.textContent='Playback failed (could not reach the proxy).'}
      });
      load(0,false);
    </script>`, { title });
}

async function handleProxy(request, env) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
        "Access-Control-Allow-Headers": "Range",
      },
    });
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method not allowed", { status: 405 });
  }

  const target = new URL(request.url).searchParams.get("u");
  if (!target) return new Response("missing u", { status: 400 });

  let t;
  try { t = new URL(target); } catch { return new Response("bad url", { status: 400 }); }
  // Only stream hosts — thumbnails/youtube.com aren't needed through the proxy.
  // YouTube serves streams from *.googlevideo.com and from rrN---sn-xxxx.c.youtube.com.
  const host = t.hostname.toLowerCase();
  const okHost = /(^|\.)googlevideo\.com$/.test(host) || /^[a-z0-9-]+\.c\.youtube\.com$/.test(host);
  if (t.protocol !== "https:" || !okHost) {
    return new Response("forbidden host", { status: 403 });
  }

  const fwd = new Headers({
    "User-Agent": DEFAULT_UA,
    "Referer": "https://www.youtube.com/",
    "Origin": "https://www.youtube.com",
  });
  // Reuse the browser identity from the pasted request (never the cookie: it's for youtube.com only).
  const saved = sanitizeHeaders(await env.VIDEOS.get(HEADERS_KEY, "json"));
  for (const k of PROXY_HEADERS) {
    if (saved[k]) { try { fwd.set(k, saved[k]); } catch {} }
  }
  const range = request.headers.get("Range");
  if (range) fwd.set("Range", range);

  let res;
  try {
    res = await fetch(t.toString(), { method: request.method, headers: fwd, redirect: "follow" });
  } catch (e) {
    console.error("proxy fetch failed", e?.message || e);
    return new Response("Could not reach the video server", {
      status: 502, headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" },
    });
  }
  console.log("proxy upstream status", res.status, t.hostname, "range:", range || "-");

  if (res.status >= 400) {
    return new Response(`Upstream googlevideo returned HTTP ${res.status}`, {
      status: res.status,
      headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" },
    });
  }

  const out = new Headers();
  for (const k of ["content-type", "content-length", "content-range", "accept-ranges", "etag", "last-modified"]) {
    const v = res.headers.get(k);
    if (v) out.set(k, v);
  }
  if (!out.has("accept-ranges")) out.set("Accept-Ranges", "bytes");
  out.set("Cache-Control", "private, no-store");
  out.set("Access-Control-Allow-Origin", "*");
  out.set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges");

  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: out });
}
