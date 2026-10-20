/* ── TrustWatch — lógica sin interfaz (navegador y Node) ──
   Generador y medidor de contraseñas, validaciones y lectura de las
   respuestas de XposedOrNot, Google DNS y RDAP. */
(function (root) {
  'use strict';

  // ════════════ Contraseñas ════════════
  const SETS = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    digits: '0123456789',
    symbols: '!@#$%^&*()-_=+[]{};:,.<>/?~|',
  };
  const AMBIGUOUS = /[Il1O0o|`'"]/g;

  function defaultRandom(n) {
    const a = new Uint32Array(n);
    (root.crypto || globalThis.crypto).getRandomValues(a);
    return a;
  }

  /** Entero uniforme en [0, max) sin sesgo de módulo (muestreo por rechazo). */
  function randInt(max, rnd) {
    const limit = Math.floor(0x100000000 / max) * max;
    for (;;) {
      const v = rnd(1)[0];
      if (v < limit) return v % max;
    }
  }

  /**
   * Contraseña con crypto.getRandomValues. Garantiza al menos un carácter
   * de cada tipo elegido y baraja el resultado (Fisher-Yates).
   */
  function generatePassword(opts, rnd) {
    rnd = rnd || defaultRandom;
    const o = Object.assign({ length: 16, upper: true, lower: true, digits: true, symbols: true, noAmbiguous: false }, opts);
    const length = Math.max(4, Math.min(128, Math.floor(o.length) || 16));
    const pools = ['upper', 'lower', 'digits', 'symbols'].filter(k => o[k])
      .map(k => (o.noAmbiguous ? SETS[k].replace(AMBIGUOUS, '') : SETS[k]));
    if (!pools.length) return '';
    const all = pools.join('');
    const chars = pools.map(p => p[randInt(p.length, rnd)]);
    while (chars.length < length) chars.push(all[randInt(all.length, rnd)]);
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randInt(i + 1, rnd);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
  }

  // Contraseñas y palabras muy usadas (versión reducida de las listas públicas)
  const COMMON = ('123456 password 123456789 12345678 12345 qwerty 1234567 111111 123123 abc123 password1 1234 iloveyou 1q2w3e4r ' +
    '000000 qwerty123 zaq12wsx dragon sunshine princess letmein 654321 monkey 27653 1qaz2wsx 123321 qwertyuiop superman asdfghjkl ' +
    'football baseball welcome admin master hello login shadow michael jordan liverpool chelsea arsenal barcelona madrid ' +
    'contraseña contrasena clave secreto hola amor teamo tequiero españa espana futbol real barca madrid123 america mexico ' +
    'argentina colombia jesus dios familia mama papa casa perro gato pokemon naruto minecraft fortnite starwars batman ' +
    'administrator root toor pass passw0rd p@ssw0rd changeme default guest test qwe123 asd123 a1b2c3 trustno1 whatever ' +
    'computer internet samsung google iphone summer winter spring autumn verano invierno').split(' ');
  const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx3edc', 'qwertzuiop'];
  const LEET = { '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o', '$': 's', '5': 's', '7': 't', '+': 't' };

  function unleet(s) { return s.toLowerCase().replace(/[@4310!$57+]/g, c => LEET[c] || c); }

  /**
   * Estimación de fuerza: entropía por longitud y tipos de carácter,
   * con penalizaciones por palabras comunes, secuencias, repeticiones y años.
   */
  function estimateStrength(pw) {
    const s = String(pw || '');
    const warnings = [];
    if (!s) return { bits: 0, score: 0, warnings };
    let pool = 0;
    if (/[a-z]/.test(s)) pool += 26;
    if (/[A-Z]/.test(s)) pool += 26;
    if (/[0-9]/.test(s)) pool += 10;
    if (/[^A-Za-z0-9]/.test(s)) pool += 33;
    let bits = s.length * Math.log2(Math.max(pool, 2));

    const lower = s.toLowerCase();
    const plain = unleet(s);
    const core = plain.replace(/[^a-zñ]/g, '');
    const common = COMMON.find(w => w.length >= 4 && (plain.includes(w) || core === w));
    if (COMMON.includes(lower) || COMMON.includes(plain)) {
      bits = Math.min(bits, 10);
      warnings.push('w_common');
    } else if (common) {
      // La palabra común aporta poco: cuenta sobre todo lo que queda alrededor
      const rest = plain.replace(common, '').length;
      bits = Math.min(bits - common.length * 3.5, rest * Math.log2(Math.max(pool, 2)) + 12);
      warnings.push('w_word');
    }
    for (const seq of SEQUENCES) {
      for (let len = Math.min(seq.length, lower.length); len >= 4; len--) {
        let found = false;
        for (let i = 0; i + len <= seq.length; i++) {
          const part = seq.slice(i, i + len);
          if (lower.includes(part) || lower.includes([...part].reverse().join(''))) { found = true; break; }
        }
        if (found) { bits -= len * 3; warnings.push('w_sequence'); break; }
      }
      if (warnings.includes('w_sequence')) break;
    }
    if (/(.)\1{2,}/.test(s)) { bits -= 8; warnings.push('w_repeat'); }
    if (/(19[5-9]\d|20[0-4]\d)/.test(s)) { bits -= 6; warnings.push('w_year'); }
    if (/^[A-Z]?[a-z]+\d{1,4}[^A-Za-z0-9]?$/.test(s)) { bits -= 8; warnings.push('w_pattern'); }
    if (s.length < 12) warnings.push('w_short');
    bits = Math.max(0, Math.round(bits));
    const score = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
    return { bits, score, warnings: [...new Set(warnings)] };
  }

  /** Tiempo para probar la mitad del espacio (segundos) a `rate` intentos por segundo. */
  function crackSeconds(bits, rate) { return Math.pow(2, Math.max(0, bits - 1)) / rate; }

  /** SHA-1 en hexadecimal (mayúsculas) con Web Crypto, para Pwned Passwords. */
  async function sha1Hex(text) {
    const c = root.crypto || globalThis.crypto;
    const buf = await c.subtle.digest('SHA-1', new TextEncoder().encode(text));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  /** Cuenta las apariciones del sufijo en la respuesta de /range/{prefijo}. */
  function pwnedCount(rangeText, suffix) {
    for (const line of String(rangeText).split(/\r?\n/)) {
      const [suf, count] = line.trim().split(':');
      if (suf && suf.toUpperCase() === suffix) return parseInt(count, 10) || 0;
    }
    return 0;
  }

  // ════════════ Validaciones ════════════
  const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]+@([a-z0-9-]+\.)+[a-z]{2,}$/i;
  const DOMAIN_RE = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i;
  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

  function isEmail(v) { return EMAIL_RE.test(String(v).trim()); }

  /** Admite "https://www.ejemplo.com/ruta" y devuelve solo el dominio. */
  function cleanDomain(v) {
    let s = String(v || '').trim().toLowerCase();
    try { if (/^[a-z]+:\/\//.test(s)) s = new URL(s).hostname; } catch (e) { return ''; }
    s = s.replace(/^www\./, '').replace(/\.$/, '').split('/')[0];
    return DOMAIN_RE.test(s) ? s : '';
  }

  function isIPv4(v) { return IPV4_RE.test(String(v).trim()); }
  function isIPv6(v) {
    const s = String(v).trim();
    if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return false;
    try { return new URL('http://[' + s + ']/').hostname.length > 2; } catch (e) { return false; }
  }

  /** URL http(s) válida; añade https:// si falta. Devuelve '' si no vale. */
  function normalizeUrl(v) {
    let s = String(v || '').trim();
    if (!s) return '';
    if (/^(javascript|data|file|vbscript|ftp|mailto|blob):/i.test(s)) return '';
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
    try {
      const u = new URL(s);
      if (!['http:', 'https:'].includes(u.protocol) || !u.hostname.includes('.')) return '';
      return u.href;
    } catch (e) { return ''; }
  }

  // ════════════ XposedOrNot ════════════
  /** Normaliza check-email ({"breaches":[[...]]} o {"Error":"Not found"}) a una lista plana. */
  function parseCheckEmail(data) {
    if (!data || !data.breaches) return [];
    return [...new Set([].concat(...[].concat(data.breaches).map(x => [].concat(x))))].filter(Boolean).map(String);
  }

  /** breach-analytics → lista de brechas con detalles, de la más reciente a la más antigua. */
  function parseAnalytics(data) {
    const list = data && data.ExposedBreaches && data.ExposedBreaches.breaches_details;
    if (!Array.isArray(list)) return null;
    const risk = data.BreachMetrics && Array.isArray(data.BreachMetrics.risk) ? data.BreachMetrics.risk[0] : null;
    const breaches = list.map(b => ({
      name: String(b.breach || ''),
      domain: String(b.domain || ''),
      year: String(b.xposed_date || ''),
      records: Number(b.xposed_records) || 0,
      data: String(b.xposed_data || '').split(';').map(x => x.trim()).filter(Boolean),
      details: String(b.details || ''),
      industry: String(b.industry || ''),
      passwordRisk: String(b.password_risk || ''),
      verified: b.verified === 'Yes',
    })).sort((a, b) => (b.year || '').localeCompare(a.year || '') || a.name.localeCompare(b.name));
    return { breaches, risk: risk ? { label: String(risk.risk_label || ''), score: Number(risk.risk_score) || 0 } : null };
  }

  // ════════════ DNS ════════════
  const DNS_TYPES = { A: 1, AAAA: 28, CNAME: 5, MX: 15, NS: 2, TXT: 16, SOA: 6, CAA: 257 };

  /** Respuesta de dns.google → { status: 'ok'|'nxdomain'|'empty'|'error', records } */
  function parseDns(data, type) {
    if (!data) return { status: 'error', records: [] };
    if (data.Status === 3) return { status: 'nxdomain', records: [] };
    if (data.Status !== 0) return { status: 'error', code: data.Status, records: [] };
    const want = DNS_TYPES[type];
    const records = (data.Answer || []).filter(r => !want || r.type === want)
      .map(r => ({ name: String(r.name || ''), type: r.type, ttl: r.TTL, data: String(r.data || '').replace(/^"|"$/g, '').replace(/" "/g, '') }));
    return { status: records.length ? 'ok' : 'empty', records, dnssec: !!data.AD };
  }

  /** Revisa SPF y DMARC a partir de los TXT del dominio y de _dmarc. */
  function mailSecurity(txtRoot, txtDmarc) {
    const spf = txtRoot.filter(t => /^v=spf1\b/i.test(t));
    const dmarc = txtDmarc.filter(t => /^v=DMARC1\b/i.test(t));
    const out = { spf: null, dmarc: null };
    if (spf.length === 1) {
      const all = (spf[0].match(/([~?+-]?)all\b/i) || [])[1];
      out.spf = { record: spf[0], level: all === '-' ? 'strict' : all === '~' ? 'soft' : all === '?' || all === '+' || all === '' ? 'weak' : 'noall' };
    } else if (spf.length > 1) {
      out.spf = { record: spf.join(' | '), level: 'multiple' };
    }
    if (dmarc.length) {
      const p = ((dmarc[0].match(/;\s*p=(\w+)/i) || [])[1] || 'none').toLowerCase();
      out.dmarc = { record: dmarc[0], policy: p };
    }
    return out;
  }

  // ════════════ RDAP ════════════
  function vcardName(entity) {
    const card = entity && entity.vcardArray && entity.vcardArray[1];
    if (!Array.isArray(card)) return '';
    const fn = card.find(v => v[0] === 'fn');
    return fn ? String(fn[3] || '') : '';
  }

  function parseRdap(d) {
    if (!d || !d.ldhName) return null;
    const ev = a => { const e = (d.events || []).find(x => x.eventAction === a); return e ? String(e.eventDate || '').slice(0, 10) : ''; };
    const registrar = (d.entities || []).find(e => (e.roles || []).includes('registrar'));
    return {
      name: String(d.ldhName).toLowerCase(),
      registered: ev('registration'),
      expires: ev('expiration'),
      updated: ev('last changed'),
      registrar: vcardName(registrar),
      status: (d.status || []).map(String),
      nameservers: (d.nameservers || []).map(n => String(n.ldhName || '').toLowerCase()).filter(Boolean),
      dnssec: !!(d.secureDNS && d.secureDNS.delegationSigned),
    };
  }

  const api = {
    SETS, COMMON, generatePassword, estimateStrength, crackSeconds, sha1Hex, pwnedCount,
    isEmail, cleanDomain, isIPv4, isIPv6, normalizeUrl,
    parseCheckEmail, parseAnalytics, DNS_TYPES, parseDns, mailSecurity, parseRdap,
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.TWCore = api;
})(typeof window !== 'undefined' ? window : globalThis);
