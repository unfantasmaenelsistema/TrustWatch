// api/_security.js — utilidades compartidas por los proxies.
// Vercel no lo publica como ruta porque el nombre empieza por "_".
import { lookup } from 'node:dns/promises';
import net from 'node:net';

// Webs que pueden usar el proxy desde el navegador
const ALLOWED_ORIGINS = [
  'https://unfantasmaenelsistema.github.io',
  'http://localhost:8000', 'http://127.0.0.1:8000', 'http://127.0.0.1:8765',
];

/** CORS limitado a las webs de la casa. Devuelve true si era un preflight ya respondido. */
export function cors(req, res, methods) {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', methods + ', OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return true;
  }
  return false;
}

/** URL http(s) razonable (sin credenciales ni puertos raros), o null. */
export function parsePublicUrl(raw) {
  if (typeof raw !== 'string' || raw.length > 2048) return null;
  let s = raw.trim();
  // Con esquema explícito solo vale http(s); sin esquema se asume https
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) || /^(javascript|data|file|vbscript|ftp|mailto|blob):/i.test(s)) {
    if (!/^https?:\/\//i.test(s)) return null;
  } else {
    s = 'https://' + s;
  }
  try {
    const u = new URL(s);
    if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) return null;
    if (u.port && !['80', '443', '8080', '8443'].includes(u.port)) return null;
    return u;
  } catch {
    return null;
  }
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
  }
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return isPrivateIp(v.slice(7));
  return v === '::' || v === '::1' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80') || v.startsWith('ff');
}

/** Evita usar el proxy contra redes internas (SSRF): todas las IP del host deben ser públicas. */
export async function assertPublicHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '');
  if (/^(localhost|.*\.local|.*\.internal)$/i.test(host)) throw new Error('Host not allowed');
  const addrs = net.isIP(host) ? [{ address: host }] : await lookup(host, { all: true, verbatim: true });
  if (!addrs.length || addrs.some(a => isPrivateIp(a.address))) throw new Error('Host not allowed');
}
