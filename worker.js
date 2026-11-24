import { DurableObject } from "cloudflare:workers";
import SURVEY from "./r-dc3e7126e5/survey.json";

// رموز العائلة المقبولة (بعد التطبيع): بدية / بديه / bidiya / bidiyah
const FAMILY_CODES = new Set(["بديه", "bidiya", "bidiyah"]);
const COOKIE = "rimal_done";
const MAX_BODY = 8000;

function normCode(s) {
  return String(s || "").trim().toLowerCase()
    .replace(/[ً-ٰٟـ]/g, "")
    .replace(/[أإآ]/g, "ا").replace(/ة/g, "ه").replace(/ى/g, "ي")
    .replace(/\s+/g, "");
}
const codeOk = (c) => FAMILY_CODES.has(normCode(c));

function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra },
  });
}
function getCookie(req, name) {
  const m = (req.headers.get("cookie") || "").match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? m[1] : "";
}
async function sha256hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function isAdmin(req, env) {
  const key = req.headers.get("x-admin-key") || "";
  if (!key || key.length > 100) return false;
  return (await sha256hex(key)) === env.ADMIN_HASH;
}

// تنظيف الإجابات وفق تعريف الاستبيان فقط
function sanitize(answers) {
  if (!answers || typeof answers !== "object") return null;
  const out = {};
  for (const q of SURVEY.questions) {
    const v = answers[q.id];
    const empty = v === undefined || v === null || v === "" || (Array.isArray(v) && v.length === 0);
    if (empty) { if (q.required) return null; continue; }
    if (q.type === "single") {
      if (!q.options.some((o) => o.k === v)) return null;
      out[q.id] = v;
    } else if (q.type === "multi") {
      if (!Array.isArray(v)) return null;
      const ks = [...new Set(v)].filter((x) => q.options.some((o) => o.k === x));
      if (ks.length) out[q.id] = ks;
    } else if (q.type === "rating") {
      const n = Number(v);
      if (!Number.isInteger(n) || n < 1 || n > 5) return null;
      out[q.id] = n;
    } else if (q.type === "text") {
      const t = String(v).trim().slice(0, q.max || 500);
      if (t) out[q.id] = t;
    }
  }
  return out;
}

export class RimalStore extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec("CREATE TABLE IF NOT EXISTS responses (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, data TEXT NOT NULL)");
    this.sql.exec("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)");
    if (!this.#get("epoch")) this.#set("epoch", crypto.randomUUID());
  }
  #get(k) { const r = [...this.sql.exec("SELECT v FROM meta WHERE k=?", k)]; return r.length ? r[0].v : null; }
  #set(k, v) { this.sql.exec("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", k, v); }

  async epoch() { return this.#get("epoch"); }
  async add(data) {
    const now = Date.now();
    const recent = [...this.sql.exec("SELECT COUNT(*) c FROM responses WHERE ts > ?", now - 60000)][0].c;
    const total = [...this.sql.exec("SELECT COUNT(*) c FROM responses")][0].c;
    if (recent >= 20 || total >= 500) return { ok: false };
    this.sql.exec("INSERT INTO responses(ts,data) VALUES(?,?)", now, JSON.stringify(data));
    return { ok: true, epoch: this.#get("epoch") };
  }
  async list() {
    return [...this.sql.exec("SELECT ts, data FROM responses ORDER BY id")].map((r) => ({ ts: r.ts, a: JSON.parse(r.data) }));
  }
  async reset() {
    this.sql.exec("DELETE FROM responses");
    this.#set("epoch", crypto.randomUUID()); // تُلغى علامات الأجهزة القديمة فيستطيع الجميع المشاركة من جديد
    return { ok: true };
  }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/rimal/")) return env.ASSETS.fetch(req);

    const route = url.pathname.slice("/api/rimal/".length);
    const store = env.RIMAL.get(env.RIMAL.idFromName("main"));

    if (req.method === "POST") {
      const origin = req.headers.get("origin");
      if (origin && origin !== url.origin) return json({ error: "forbidden" }, 403);
    }
    const readBody = async () => {
      const txt = await req.text();
      if (txt.length > MAX_BODY) return null;
      try { return JSON.parse(txt); } catch { return null; }
    };

    if (route === "status" && req.method === "GET") {
      const epoch = await store.epoch();
      const done = getCookie(req, COOKIE) === epoch || url.searchParams.get("ls") === epoch;
      return json({ done });
    }

    if (route === "check" && req.method === "POST") {
      const b = await readBody();
      return json({ ok: !!b && codeOk(b.code) });
    }

    if (route === "submit" && req.method === "POST") {
      const b = await readBody();
      if (!b) return json({ error: "bad_request" }, 400);
      if (!codeOk(b.code)) return json({ error: "bad_code" }, 403);
      const epoch = await store.epoch();
      if (getCookie(req, COOKIE) === epoch || b.ls === epoch) return json({ error: "already" }, 409);
      const clean = sanitize(b.answers);
      if (!clean) return json({ error: "invalid" }, 400);
      const r = await store.add(clean);
      if (!r.ok) return json({ error: "busy" }, 429);
      return json({ ok: true, epoch: r.epoch }, 200, {
        "set-cookie": `${COOKIE}=${r.epoch}; Path=/; Max-Age=31536000; SameSite=Lax; Secure`,
      });
    }

    if (route === "results" && req.method === "GET") {
      if (!(await isAdmin(req, env))) return json({ error: "unauthorized" }, 401);
      return json({ rows: await store.list() });
    }

    if (route === "reset" && req.method === "POST") {
      if (!(await isAdmin(req, env))) return json({ error: "unauthorized" }, 401);
      const b = await readBody();
      if (!b || b.confirm !== "RESET") return json({ error: "confirm" }, 400);
      return json(await store.reset());
    }

    return json({ error: "not_found" }, 404);
  },
};
