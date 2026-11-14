// src/index.js — YT Player (Cloudflare Worker + KV binding "VIDEOS")

const ADMIN_USER = "admin";
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36";
const GLOBAL_COOKIE_KEY = "setting:cookie";

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

function cleanCookie(s) {
  // Cookie header must be one line, no control characters
  return String(s || "").replace(/[\r\n\t]+/g, " ").replace(/\s{2,}/g, " ").trim();
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

function htmlPage(body, { status = 200, title = "YT Player", admin = false } = {}) {
  return new Response(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${CSS}</style></head>
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
      <a class="btn ghost" href="/">Back to library</a>
    </div>`, { status, title: "Error" });
}

/* ---------- YouTube parsing ---------- */

function extractPlayerResponse(html) {
  const re = /ytInitialPlayerResponse\s*=\s*/g;
  let m;
  while ((m = re.exec(html)) !== null) {
    const start = m.index + m[0].length;
    if (html[start] !== "{") continue;
    const parsed = parseBalancedJson(html, start);
    if (parsed && parsed.streamingData) return parsed;
    // Some pages have a response without streamingData (errors) — keep as fallback
    if (parsed && parsed.playabilityStatus) return parsed;
  }
  return null;
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
        if (request.method === "POST") {
          if (!sameOrigin(request)) return new Response("Bad origin", { status: 403 });
          if (p === "/admin/save") return handleSave(request, env);
          if (p === "/admin/delete") return handleDelete(request, env);
          if (p === "/admin/global-cookie") return handleGlobalCookie(request, env);
        }
        return new Response("Not found", { status: 404 });
      }
      if (p === "/watch") return handleWatch(request, env);
      if (p === "/proxy") return handleProxy(request);
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
        <label>Used for every video that has no cookie of its own
          <span class="muted">${globalCookie ? `(currently set, ${globalCookie.length} chars)` : "(not set)"}</span>
          <textarea name="cookie" rows="3" placeholder="Paste the Cookie header value. Leave blank and tick below to clear."></textarea>
        </label>
        <label style="display:flex;gap:8px;align-items:center">
          <input type="checkbox" name="clear" value="1" style="width:auto;margin:0"> Clear the global cookie
        </label>
        <button class="btn" type="submit">Save global cookie</button>
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
    return redirect(request, "/admin?msg=" + encodeURIComponent("Global cookie cleared."));
  }
  const c = cleanCookie(fd.get("cookie"));
  if (!c) return redirect(request, "/admin?err=" + encodeURIComponent("Nothing to save."));
  await env.VIDEOS.put(GLOBAL_COOKIE_KEY, c);
  return redirect(request, "/admin?msg=" + encodeURIComponent("Global cookie saved."));
}

async function handleWatch(request, env) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id") || "";
  if (!/^[A-Za-z0-9_-]{11}$/.test(id)) return errorPage("Missing or invalid video id.", "", 400);

  const rec = await env.VIDEOS.get(`video:${id}`, "json");
  if (!rec) return errorPage("Video not found in your library.", "", 404);

  const cookie = rec.cookie || (await env.VIDEOS.get(GLOBAL_COOKIE_KEY)) || "";
  const ytUrl = `https://www.youtube.com/watch?v=${encodeURIComponent(id)}&bpctr=9999999999&has_verified=1`;
  const headers = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "max-age=0",
    "Upgrade-Insecure-Requests": "1",
    "Referer": "https://studio.youtube.com/",
    "Sec-Ch-Ua": '"Not-A.Brand";v="99", "Google Chrome";v="157", "Chromium";v="157"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Site": "same-site",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
  };
  if (cookie) headers["Cookie"] = cookie;

  let html;
  try {
    const res = await fetch(ytUrl, { headers });
    html = await res.text();
  } catch {
    return errorPage("Could not reach YouTube.", "Network error — try again in a moment.", 502, id);
  }

  const pr = extractPlayerResponse(html);
  if (!pr) {
    return errorPage(
      "Could not read the video data from YouTube.",
      "The cookie may be missing, expired or invalid, or YouTube served a consent/bot-check page.",
      502, id
    );
  }
  if (pr.playabilityStatus?.status !== "OK") {
    return errorPage(
      `YouTube status: ${pr.playabilityStatus?.status || "unknown"}`,
      pr.playabilityStatus?.reason || "",
      502, id
    );
  }

  // Auto-fill title on first play
  const ytTitle = pr.videoDetails?.title;
  if (!rec.title && ytTitle) {
    rec.title = ytTitle;
    await env.VIDEOS.put(`video:${id}`, JSON.stringify(rec));
  }
  const title = rec.title || ytTitle || id;

  const sd = pr.streamingData || {};
  const all = sd.formats || [];
  const muxed = all
    .filter((f) => f.url && /^video\/mp4/i.test(f.mimeType || ""))
    .sort((a, b) => (b.height || 0) - (a.height || 0) || (b.bitrate || 0) - (a.bitrate || 0));

  if (!muxed.length) {
    const ciphered = all.some((f) => f.signatureCipher || f.cipher);
    return errorPage(
      "No directly playable stream was found.",
      ciphered
        ? "This video's streams are protected by a signature cipher, which this worker can't decode."
        : "YouTube returned no combined audio+video stream for this video.",
      502, id
    );
  }

  const options = muxed.map((f) => ({
    label: f.qualityLabel || (f.height ? f.height + "p" : "Default"),
    src: "/proxy?u=" + encodeURIComponent(f.url),
  }));

  return htmlPage(`
    <p><a href="/">← Library</a></p>
    <h1>${escapeHtml(title)}</h1>
    <video id="v" class="player" controls playsinline preload="metadata" poster="${thumbUrl(id)}"></video>
    <div class="row">
      ${options.length > 1 ? `<label class="muted">Quality <select id="q"></select></label>` : ""}
      <span class="muted" id="status"></span>
    </div>
    <p class="muted">id: ${escapeHtml(id)}</p>
    <script>
      const opts=${jsonForScript(options)};
      const v=document.getElementById('v'),q=document.getElementById('q'),st=document.getElementById('status');
      function load(i,keep){
        const t=keep?v.currentTime:0,playing=keep&&!v.paused;
        v.src=opts[i].src;
        v.addEventListener('loadedmetadata',()=>{if(t)v.currentTime=t;if(playing)v.play().catch(()=>{})},{once:true});
      }
      if(q){opts.forEach((o,i)=>q.add(new Option(o.label,i)));q.onchange=()=>load(+q.value,true)}
      v.addEventListener('error',async()=>{
        st.textContent='Playback failed. Checking why…';
        try{
          const r=await fetch(v.currentSrc||v.src,{headers:{Range:'bytes=0-0'}});
          st.textContent='Playback failed (stream server replied HTTP '+r.status+'). '+
            (r.status===403?'YouTube refused the request — the link is bound to a different IP or needs a PO token.':'Reload to get a fresh link.');
        }catch(e){st.textContent='Playback failed (could not reach the proxy).'}
      });
      load(0,false);
    </script>`, { title });
}

async function handleProxy(request) {
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
  if (t.protocol !== "https:" || !/(^|\.)googlevideo\.com$/.test(t.hostname)) {
    return new Response("forbidden host", { status: 403 });
  }

  const fwd = new Headers({
    "User-Agent": UA,
    "Referer": "https://www.youtube.com/",
    "Origin": "https://www.youtube.com",
  });
  const range = request.headers.get("Range");
  if (range) fwd.set("Range", range);

  const res = await fetch(t.toString(), { method: request.method, headers: fwd, redirect: "follow" });

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
