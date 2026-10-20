/* ── TrustWatch — interfaz ──
   Todo lo que llega de fuera (registros DNS, cabeceras de la web analizada,
   nombres de brechas, datos RDAP) se pinta como texto: nunca se interpreta
   como HTML. */
'use strict';

const C = window.TWCore;
const PROXY = 'https://trust-watch.vercel.app/api';
const $ = id => document.getElementById(id);
const state = { lang: document.documentElement.lang === 'en' ? 'en' : 'es', tab: 'breaches', render: null };

// ─── Utilidades ───
function t(key, params) {
  const d = window.TW_I18N[state.lang] || window.TW_I18N.es;
  let s = d[key] !== undefined ? d[key] : (window.TW_I18N.es[key] !== undefined ? window.TW_I18N.es[key] : key);
  if (params) for (const k in params) s = s.split('{' + k + '}').join(String(params[k]));
  return s;
}

/** h('div', {class: 'x'}, 'texto', otroNodo) — los textos van siempre como nodos de texto. */
function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const nf = n => new Intl.NumberFormat(state.lang === 'es' ? 'es-ES' : 'en-GB').format(n);
const extLink = (href, text, cls) => h('a', { href, target: '_blank', rel: 'noopener noreferrer', class: cls }, text);

/** Muestra un resultado y recuerda cómo repintarlo al cambiar de idioma. */
function show(renderFn) {
  state.render = renderFn;
  $('results').replaceChildren(...[].concat(renderFn()));
}

const alertBox = (kind, title, ...body) => h('div', { class: 'alert ' + kind, role: kind === 'danger' ? 'alert' : null }, h('p', { class: 'alert-title' }, title), ...body);
const info = msg => show(() => alertBox('warn', msg));

function loadingOn(form) {
  const btn = form && form.querySelector('button[type=submit]');
  if (btn) { btn.disabled = true; btn.dataset.label = btn.textContent; btn.textContent = t('loading'); }
  $('results').replaceChildren(h('p', { class: 'loading' }, t('loading')));
  return () => { if (btn) { btn.disabled = false; btn.textContent = btn.dataset.label; } };
}

async function getJson(url, init, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs || 15000);
  try {
    const res = await fetch(url, Object.assign({ signal: ctrl.signal, referrerPolicy: 'no-referrer' }, init));
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    return { ok: res.ok, status: res.status, data };
  } finally { clearTimeout(timer); }
}

function connError(svc) { show(() => alertBox('danger', t('conn_error', { svc }))); }

function fmtDuration(sec) {
  if (sec < 1) return t('t_instant');
  const units = [[60, 't_seconds'], [3600, 't_minutes', 60], [86400, 't_hours', 3600], [31557600, 't_days', 86400], [3.15576e9, 't_years', 31557600]];
  if (sec < 60) return t('t_seconds', { n: Math.round(sec) });
  for (let i = 1; i < units.length; i++) if (sec < units[i][0]) return t(units[i][1], { n: nf(Math.round(sec / units[i][2])) });
  return t('t_centuries');
}

function daysSince(iso) {
  const d = Date.parse(iso);
  return isNaN(d) ? null : Math.floor((Date.now() - d) / 86400000);
}

// ─── Pestañas ───
function setTab(name, push) {
  if (!document.querySelector('[data-panel="' + name + '"]')) name = 'breaches';
  state.tab = name;
  document.querySelectorAll('[data-tab]').forEach(b => {
    const on = b.dataset.tab === name;
    b.classList.toggle('active', on);
    b.setAttribute('aria-selected', on ? 'true' : 'false');
  });
  document.querySelectorAll('[data-panel]').forEach(p => { p.hidden = p.dataset.panel !== name; });
  state.render = null;
  $('results').replaceChildren();
  if (push && location.hash !== '#' + name) history.replaceState(null, '', '#' + name);
  if (name === 'password' && !$('genOutput').value) generate();
}

// ════════════ Brechas ════════════
async function checkBreaches(ev) {
  ev.preventDefault();
  const email = $('emailInput').value.trim();
  if (!C.isEmail(email)) return info(t('bad_email'));
  const done = loadingOn(ev.target);
  try {
    const r = await getJson('https://api.xposedornot.com/v1/breach-analytics?email=' + encodeURIComponent(email), null, 20000);
    let parsed = r.ok ? C.parseAnalytics(r.data) : null;
    if (!parsed) {
      // Respaldo: el endpoint simple solo da nombres
      const r2 = await getJson('https://api.xposedornot.com/v1/check-email/' + encodeURIComponent(email));
      if (!r2.ok && r2.status !== 404) throw new Error('xon');
      const names = C.parseCheckEmail(r2.data);
      parsed = { breaches: names.map(name => ({ name, data: [], records: 0, year: '', details: '' })), risk: null };
    }
    show(() => renderBreaches(email, parsed));
  } catch (e) {
    connError('XposedOrNot');
  } finally { done(); }
}

function renderBreaches(email, { breaches, risk }) {
  if (!breaches.length) {
    return alertBox('ok', '✅ ' + t('breaches_none', { email }), h('p', null, t('breaches_none_tip')));
  }
  const head = alertBox('danger', '🚨 ' + (breaches.length === 1 ? t('breaches_found_one', { email }) : t('breaches_found', { email, n: nf(breaches.length) })),
    risk && risk.label ? h('p', null, t('breaches_risk', { label: risk.label, score: risk.score })) : null,
    h('p', { class: 'alert-sub' }, t('breaches_todo')),
    h('ol', null, h('li', null, t('todo_1')), h('li', null, t('todo_2')), h('li', null, t('todo_3'))));
  const card = b => h('article', { class: 'breach' },
    h('div', { class: 'breach-head' },
      h('b', null, b.name),
      b.year ? h('span', { class: 'chip' }, b.year) : null,
      b.records ? h('span', { class: 'chip' }, t('records', { n: nf(b.records) })) : null,
      b.passwordRisk === 'plaintext' ? h('span', { class: 'chip bad' }, t('pw_plain')) : null,
      b.passwordRisk === 'easytocrack' ? h('span', { class: 'chip warn' }, t('pw_easy')) : null,
      b.verified === false && b.details ? h('span', { class: 'chip' }, t('unverified')) : null),
    b.data.length ? h('p', { class: 'exposed' }, h('span', null, t('exposed') + ': '), b.data.join(', ')) : null,
    b.details ? h('details', null, h('summary', null, t('more_info')), h('p', null, b.details)) : null);
  const first = breaches.slice(0, 12).map(card);
  const rest = breaches.slice(12);
  const list = h('div', { class: 'breach-list' }, first);
  if (rest.length) {
    const more = h('button', { class: 'btn-ghost', type: 'button', onclick: () => { more.replaceWith(...rest.map(card)); } }, t('show_more', { n: rest.length }));
    list.append(more);
  }
  return [head, list];
}

// ════════════ Contraseñas ════════════
function genOptions() {
  return {
    length: +$('passLength').value, upper: $('optUpper').checked, lower: $('optLower').checked,
    digits: $('optDigits').checked, symbols: $('optSymbols').checked, noAmbiguous: $('optAmbig').checked,
  };
}

function generate() {
  const pw = C.generatePassword(genOptions());
  $('genOutput').value = pw;
  if (!pw) info(t('gen_none'));
  else if (state.tab === 'password' && state.render) { state.render = null; $('results').replaceChildren(); }
}

async function copyGenerated() {
  const v = $('genOutput').value;
  if (!v) return;
  try { await navigator.clipboard.writeText(v); } catch (e) { $('genOutput').select(); document.execCommand('copy'); }
  const b = $('copyBtn');
  b.textContent = t('copied');
  setTimeout(() => { b.textContent = t('copy'); }, 1500);
}

function updateStrength() {
  const pw = $('pwInput').value;
  const r = C.estimateStrength(pw);
  const colors = ['var(--bad)', '#f97316', 'var(--warn)', '#84cc16', 'var(--ok)'];
  $('meterBar').style.width = pw ? Math.max(6, Math.min(100, r.bits / 1.2)) + '%' : '0';
  $('meterBar').style.background = colors[r.score];
  const out = $('strengthOut');
  if (!pw) { out.replaceChildren(); return; }
  out.replaceChildren(
    h('p', { class: 'strength-label', style: 'color:' + colors[r.score] }, t('s' + r.score)),
    h('p', { class: 'muted' }, t('bits', { bits: r.bits })),
    h('p', { class: 'muted' }, t('crack_offline', { t: fmtDuration(C.crackSeconds(r.bits, 1e10)) })),
    h('p', { class: 'muted' }, t('crack_online', { t: fmtDuration(C.crackSeconds(r.bits, 100 / 3600)) })),
    r.warnings.length ? h('ul', { class: 'warnings' }, r.warnings.map(w => h('li', null, t(w)))) : null);
}

async function checkPwned() {
  const pw = $('pwInput').value;
  if (!pw) return info(t('pwned_empty'));
  const btn = $('pwnedBtn');
  btn.disabled = true;
  try {
    const hash = await C.sha1Hex(pw);
    const res = await fetch('https://api.pwnedpasswords.com/range/' + hash.slice(0, 5), { headers: { 'Add-Padding': 'true' }, referrerPolicy: 'no-referrer' });
    if (!res.ok) throw new Error('hibp');
    const n = C.pwnedCount(await res.text(), hash.slice(5));
    show(() => (n ? alertBox('danger', t('pwned_yes', { n: nf(n) })) : alertBox('ok', t('pwned_no'))));
  } catch (e) {
    connError('Have I Been Pwned');
  } finally { btn.disabled = false; }
}

// ════════════ URL segura ════════════
async function checkUrl(ev) {
  ev.preventDefault();
  const url = C.normalizeUrl($('urlInput').value);
  if (!url) return info(t('bad_url'));
  const done = loadingOn(ev.target);
  try {
    const r = await getJson(PROXY + '/safebrowsing', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
    if (!r.ok || !r.data || !r.data.status) {
      show(() => alertBox('danger', t('proxy_error', { msg: (r.data && r.data.error) || 'HTTP ' + r.status })));
      return;
    }
    const matches = r.data.matches || [];
    show(() => (r.data.status === 'DANGEROUS'
      ? alertBox('danger', '🚨 ' + t('url_danger', { url }),
        h('ul', null, [...new Set(matches.map(m => m.threatType))].map(tt => h('li', null, t(tt)))))
      : alertBox('ok', '✅ ' + t('url_safe', { url }), h('p', null, t('url_safe_tip')))));
  } catch (e) {
    connError('Safe Browsing');
  } finally { done(); }
}

// ════════════ Cabeceras ════════════
async function checkHeaders(ev) {
  ev.preventDefault();
  const url = C.normalizeUrl($('headersInput').value);
  if (!url) return info(t('bad_url'));
  const done = loadingOn(ev.target);
  try {
    const r = await getJson(PROXY + '/headers?url=' + encodeURIComponent(url), null, 20000);
    if (!r.ok || !r.data || !r.data.results) {
      show(() => alertBox('danger', t('proxy_error', { msg: (r.data && (r.data.details || r.data.error)) || 'HTTP ' + r.status })));
      return;
    }
    show(() => renderHeaders(r.data));
  } catch (e) {
    connError('TrustWatch proxy');
  } finally { done(); }
}

function renderHeaders(d) {
  const score = Math.max(0, Math.min(100, Number(d.score) || 0));
  const kind = score >= 75 ? 'ok' : score >= 50 ? 'warn' : 'danger';
  const head = alertBox(kind, t('headers_score', { score }), h('p', { class: 'mono small' }, t('headers_final', { url: String(d.url || ''), status: String(d.status || '') })),
    h('div', { class: 'meter big' }, h('div', { style: 'width:' + score + '%;background:var(--' + (kind === 'ok' ? 'ok' : kind === 'warn' ? 'warn' : 'bad') + ')' })));
  const rows = Object.entries(d.results).map(([name, r]) => {
    const st = String(r.status || '');
    const cls = st === 'PRESENT' ? 'ok' : st === 'MISCONFIGURED' ? 'warn' : st === 'MISSING' ? 'bad' : 'muted';
    return h('article', { class: 'header-row ' + cls },
      h('div', { class: 'header-name' }, h('b', { class: 'mono' }, name), h('span', { class: 'chip ' + cls }, t('h_' + st))),
      h('p', { class: 'muted' }, t('hd_' + name) !== 'hd_' + name ? t('hd_' + name) : String(r.description || '')),
      r.value && r.value !== 'N/A' ? h('code', { class: 'header-value' }, String(r.value)) : null);
  });
  return [head, h('div', { class: 'header-list' }, rows)];
}

// ════════════ Dominio ════════════
async function dnsQuery(name, type) {
  const r = await getJson('https://dns.google/resolve?name=' + encodeURIComponent(name) + '&type=' + type, { headers: { Accept: 'application/dns-json' } });
  if (!r.ok) throw new Error('dns');
  return C.parseDns(r.data, type);
}

async function checkDomain(ev) {
  ev.preventDefault();
  const domain = C.cleanDomain($('domainInput').value);
  if (!domain) return info(t('bad_domain'));
  const done = loadingOn(ev.target);
  try {
    const [rdapRes, mx, txt, dmarc] = await Promise.all([
      getJson('https://rdap.org/domain/' + encodeURIComponent(domain), null, 15000).catch(() => null),
      dnsQuery(domain, 'MX'), dnsQuery(domain, 'TXT'), dnsQuery('_dmarc.' + domain, 'TXT'),
    ]);
    if (mx.status === 'nxdomain' && txt.status === 'nxdomain') {
      show(() => alertBox('danger', t('nxdomain', { d: domain })));
      return;
    }
    const rdap = rdapRes && rdapRes.ok ? C.parseRdap(rdapRes.data) : null;
    const mail = C.mailSecurity(txt.records.map(r => r.data), dmarc.records.map(r => r.data));
    show(() => renderDomain(domain, rdap, mx, mail));
  } catch (e) {
    connError('RDAP / DNS');
  } finally { done(); }
}

function kv(label, value) { return h('div', { class: 'kv' }, h('span', null, label), h('b', null, value)); }

function renderDomain(domain, rdap, mx, mail) {
  const out = [];
  if (rdap) {
    const age = daysSince(rdap.registered);
    const ageText = age === null ? '' : age < 730 ? ' (' + t('age_days', { n: nf(age) }) + ')' : ' (' + t('age_years', { n: Math.floor(age / 365.25) }) + ')';
    out.push(h('section', { class: 'box' }, h('h2', null, '🌐 ' + t('reg_title') + ' · ' + rdap.name),
      age !== null && age < 90 ? alertBox('danger', t('young')) : null,
      h('div', { class: 'kv-grid' },
        rdap.registered ? kv(t('registered'), rdap.registered + ageText) : null,
        rdap.expires ? kv(t('expires'), rdap.expires) : null,
        rdap.updated ? kv(t('updated'), rdap.updated) : null,
        rdap.registrar ? kv(t('registrar'), rdap.registrar) : null,
        kv(t('dnssec'), rdap.dnssec ? t('yes') : t('no')),
        rdap.status.length ? kv(t('status'), rdap.status.join(', ')) : null,
        rdap.nameservers.length ? kv(t('nameservers'), rdap.nameservers.join(', ')) : null)));
  } else {
    out.push(alertBox('warn', t('rdap_none')));
  }
  const spfKey = mail.spf ? 'spf_' + mail.spf.level : 'spf_none';
  const dmarcKey = mail.dmarc ? (['reject', 'quarantine', 'none'].includes(mail.dmarc.policy) ? 'dmarc_' + mail.dmarc.policy : 'dmarc_none') : 'dmarc_missing';
  const level = k => (/strict|reject/.test(k) ? 'ok' : /soft|quarantine/.test(k) ? 'warn' : 'bad');
  out.push(h('section', { class: 'box' }, h('h2', null, '✉️ ' + t('mail_title')),
    h('p', { class: 'muted' }, t('mx')),
    mx.records.length ? h('ul', { class: 'mono list' }, mx.records.map(r => h('li', null, r.data))) : h('p', null, t('mx_none')),
    h('p', { class: 'check-line ' + level(spfKey) }, t(spfKey)),
    mail.spf ? h('code', { class: 'header-value' }, mail.spf.record) : null,
    h('p', { class: 'check-line ' + level(dmarcKey) }, t(dmarcKey)),
    mail.dmarc ? h('code', { class: 'header-value' }, mail.dmarc.record) : null));
  return out;
}

// ════════════ DNS ════════════
async function checkDns(ev) {
  ev.preventDefault();
  const domain = C.cleanDomain($('dnsInput').value);
  const type = $('dnsType').value;
  if (!domain) return info(t('bad_domain'));
  const done = loadingOn(ev.target);
  try {
    const r = await dnsQuery(domain, type);
    show(() => {
      if (r.status === 'nxdomain') return alertBox('danger', t('nxdomain', { d: domain }));
      if (r.status === 'empty') return alertBox('warn', t('dns_empty', { d: domain, t: type }));
      if (r.status === 'error') return alertBox('danger', t('dns_error', { code: r.code }));
      return [alertBox('ok', t('dns_ok', { n: r.records.length, t: type, d: domain }), r.dnssec ? h('p', null, '🔏 ' + t('dnssec_ok')) : null),
        h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, h('th', null, t('col_name')), h('th', null, t('col_ttl')), h('th', null, t('col_data')))),
          h('tbody', null, r.records.map(rec => h('tr', null, h('td', { class: 'mono' }, rec.name), h('td', null, String(rec.ttl)), h('td', { class: 'mono break' }, rec.data))))))];
    });
  } catch (e) {
    connError('Google Public DNS');
  } finally { done(); }
}

// ════════════ IP ════════════
async function checkIp(ev) {
  ev.preventDefault();
  const ip = $('ipInput').value.trim();
  if (ip && !C.isIPv4(ip) && !C.isIPv6(ip)) return info(t('bad_ip'));
  const done = loadingOn(ev.target);
  try {
    const r = await getJson('https://ipapi.co/' + (ip ? encodeURIComponent(ip) + '/' : '') + 'json/');
    const d = r.data || {};
    if (d.reserved || /reserved|private/i.test(String(d.reason || ''))) return show(() => alertBox('warn', t('ip_private')));
    if (r.status === 429 || /rate/i.test(String(d.reason || ''))) return show(() => alertBox('warn', t('ip_limit')));
    if (!r.ok || !d.ip) throw new Error('ip');
    show(() => {
      const lat = Number(d.latitude), lon = Number(d.longitude);
      const map = isFinite(lat) && isFinite(lon) ? 'https://www.openstreetmap.org/?mlat=' + lat + '&mlon=' + lon + '#map=10/' + lat + '/' + lon : null;
      return h('section', { class: 'box' }, h('h2', { class: 'mono' }, '📍 ' + String(d.ip)),
        h('div', { class: 'kv-grid' },
          kv(t('country'), [d.country_name, d.country_code && '(' + d.country_code + ')'].filter(Boolean).join(' ') || '—'),
          kv(t('city'), [d.city, d.region].filter(Boolean).join(', ') || '—'),
          kv(t('coords'), isFinite(lat) ? lat + ', ' + lon : '—'),
          kv(t('timezone'), String(d.timezone || '—')),
          kv(t('org'), String(d.org || '—')),
          kv(t('asn'), String(d.asn || '—'))),
        map ? extLink(map, '🗺️ ' + t('map'), 'btn-ghost') : null,
        h('p', { class: 'note' }, t('ip_note')));
    });
  } catch (e) {
    connError('ipapi.co');
  } finally { done(); }
}

// ════════════ Teléfono ════════════
function checkPhone(ev) {
  ev.preventDefault();
  const raw = $('phoneInput').value.trim();
  let p = null;
  try {
    p = window.libphonenumber.parsePhoneNumberFromString(raw, state.lang === 'es' ? 'ES' : undefined);
  } catch (e) { p = null; }
  if (!p || !p.isValid()) return info(t('bad_phone'));
  const e164 = p.number;
  const digits = e164.replace('+', '');
  let region = '';
  try { region = new Intl.DisplayNames([state.lang], { type: 'region' }).of(p.country); } catch (e) { region = p.country || ''; }
  const type = p.getType() || 'UNKNOWN';
  show(() => h('section', { class: 'box' },
    h('h2', null, '✅ ' + t('phone_valid')),
    h('div', { class: 'kv-grid' },
      kv(t('intl'), p.formatInternational()), kv(t('national'), p.formatNational()), kv(t('e164'), e164),
      kv(t('country'), region + (p.country ? ' (' + p.country + ', +' + p.countryCallingCode + ')' : '')),
      kv(t('type'), t(type))),
    type === 'PREMIUM_RATE' ? alertBox('danger', t('PREMIUM_RATE')) : null,
    h('p', { class: 'muted' }, t('reputation')),
    h('div', { class: 'links' },
      extLink('https://www.tellows.es/num/' + encodeURIComponent(digits), 'tellows', 'btn-ghost'),
      extLink('https://www.listaspam.com/busca.php?Telefono=' + encodeURIComponent(p.nationalNumber), 'ListaSpam', 'btn-ghost'),
      extLink('https://www.google.com/search?q=' + encodeURIComponent('"' + p.formatNational() + '" OR "' + e164 + '"'), 'Google', 'btn-ghost')),
    h('p', { class: 'note' }, t('phone_tip'))));
}

// ─── Idioma y tema ───
function applyI18n() {
  document.documentElement.lang = state.lang;
  document.title = state.lang === 'es' ? 'TrustWatch — Comprobaciones de seguridad' : 'TrustWatch — Security checks';
  document.querySelectorAll('[data-i18n]').forEach(n => { n.textContent = t(n.dataset.i18n); });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(n => { n.placeholder = t(n.dataset.i18nPlaceholder); });
  document.querySelectorAll('[data-i18n-title]').forEach(n => { n.title = t(n.dataset.i18nTitle); n.setAttribute('aria-label', n.title); });
  $('langBtn').textContent = state.lang === 'es' ? 'EN' : 'ES';
  $('showPw').textContent = $('pwInput').type === 'password' ? t('show') : t('hide');
  updateStrength();
  if (state.render) $('results').replaceChildren(...[].concat(state.render()));
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  $('themeBtn').textContent = theme === 'dark' ? '☀️' : '🌙';
  try { localStorage.setItem('tw_theme', theme); } catch (e) { /* sin almacenamiento */ }
}

// ─── Inicio ───
document.addEventListener('DOMContentLoaded', () => {
  applyI18n();
  setTheme(document.documentElement.getAttribute('data-theme') || 'dark');
  $('tabs').addEventListener('click', e => { const b = e.target.closest('[data-tab]'); if (b) setTab(b.dataset.tab, true); });
  $('tabs').addEventListener('keydown', e => {
    if (!['ArrowRight', 'ArrowLeft'].includes(e.key)) return;
    const tabs = [...document.querySelectorAll('[data-tab]')];
    const i = tabs.findIndex(b => b.dataset.tab === state.tab) + (e.key === 'ArrowRight' ? 1 : -1);
    const next = tabs[(i + tabs.length) % tabs.length];
    setTab(next.dataset.tab, true);
    next.focus();
  });
  $('breachesForm').addEventListener('submit', checkBreaches);
  $('urlForm').addEventListener('submit', checkUrl);
  $('headersForm').addEventListener('submit', checkHeaders);
  $('domainForm').addEventListener('submit', checkDomain);
  $('dnsForm').addEventListener('submit', checkDns);
  $('ipForm').addEventListener('submit', checkIp);
  $('phoneForm').addEventListener('submit', checkPhone);
  $('genBtn').addEventListener('click', generate);
  $('copyBtn').addEventListener('click', copyGenerated);
  $('passLength').addEventListener('input', () => { $('lenOut').textContent = $('passLength').value; generate(); });
  ['optUpper', 'optLower', 'optDigits', 'optSymbols', 'optAmbig'].forEach(id => $(id).addEventListener('change', generate));
  $('pwInput').addEventListener('input', updateStrength);
  $('showPw').addEventListener('click', () => {
    const i = $('pwInput');
    i.type = i.type === 'password' ? 'text' : 'password';
    $('showPw').textContent = i.type === 'password' ? t('show') : t('hide');
  });
  $('pwnedBtn').addEventListener('click', checkPwned);
  $('langBtn').addEventListener('click', () => {
    state.lang = state.lang === 'es' ? 'en' : 'es';
    try { localStorage.setItem('tw_lang', state.lang); } catch (e) { /* sin almacenamiento */ }
    applyI18n();
  });
  $('themeBtn').addEventListener('click', () => setTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'));
  setTab((location.hash || '#breaches').slice(1), false);
});
