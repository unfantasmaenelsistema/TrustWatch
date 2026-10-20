// api/headers.js — analiza las cabeceras de seguridad de una URL pública.
// Bloquea redes internas (también tras redirecciones) y corta a los 8 s.
import { cors, parsePublicUrl, assertPublicHost } from './_security.js';

const HEADERS = {
  'Strict-Transport-Security': { required: true },
  'Content-Security-Policy': { required: true },
  'X-Content-Type-Options': { required: true },
  'X-Frame-Options': { required: true },
  'Referrer-Policy': { required: false },
  'Permissions-Policy': { required: false },
};

async function fetchFollowing(url, signal) {
  let current = url;
  for (let i = 0; i < 5; i++) {
    await assertPublicHost(current.hostname);
    const res = await fetch(current, {
      method: 'GET',
      redirect: 'manual',
      signal,
      headers: { 'User-Agent': 'TrustWatch-HeaderCheck/2.0 (+https://github.com/unfantasmaenelsistema/TrustWatch)' },
    });
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) {
      const next = parsePublicUrl(new URL(loc, current).href);
      if (!next) throw new Error('Invalid redirect');
      current = next;
      continue;
    }
    if (res.body && res.body.cancel) res.body.cancel().catch(() => {});
    return { res, finalUrl: current.href, redirected: i > 0 };
  }
  throw new Error('Too many redirects');
}

export default async (req, res) => {
  if (cors(req, res, 'GET')) return;
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });
  const url = parsePublicUrl(req.query.url);
  if (!url) return res.status(400).json({ error: 'Invalid url' });

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const { res: r, finalUrl, redirected } = await fetchFollowing(url, ctrl.signal);
    let score = 0;
    const results = {};
    for (const [name, cfg] of Object.entries(HEADERS)) {
      const value = r.headers.get(name);
      let status = value ? 'PRESENT' : cfg.required ? 'MISSING' : 'OPTIONAL_MISSING';
      if (name === 'X-Content-Type-Options' && value && value.trim().toLowerCase() !== 'nosniff') status = 'MISCONFIGURED';
      if (name === 'X-Frame-Options' && value && !['deny', 'sameorigin'].includes(value.trim().toLowerCase())) status = 'MISCONFIGURED';
      if (name === 'Strict-Transport-Security' && value && !/max-age=\s*[1-9]/i.test(value)) status = 'MISCONFIGURED';
      if (cfg.required && status === 'PRESENT') score++;
      results[name] = { status, value: value ? value.slice(0, 1000) : 'N/A' };
    }
    res.status(200).json({ url: finalUrl, status: r.status, redirected, results, score: Math.round((score / 4) * 100) });
  } catch (e) {
    const msg = e.name === 'AbortError' ? 'Timeout' : e.message === 'Host not allowed' ? 'Host not allowed' : 'Could not reach the site';
    res.status(502).json({ error: msg });
  } finally {
    clearTimeout(timer);
  }
};
