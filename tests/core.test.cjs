// Pruebas de js/core.js (sin dependencias): node tests/core.test.cjs
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

// core.js es UMD; el paquete es "type": "module", así que se carga a mano
const mod = { exports: {} };
new Function('module', 'exports', fs.readFileSync(path.join(__dirname, '..', 'js', 'core.js'), 'utf8'))(mod, mod.exports);
const C = mod.exports;

let n = 0;
const test = (name, fn) => Promise.resolve(fn()).then(() => { n++; console.log('  ✓ ' + name); });

(async () => {
  await test('generador: longitud y todos los tipos elegidos', () => {
    for (let i = 0; i < 200; i++) {
      const p = C.generatePassword({ length: 12 });
      assert.strictEqual(p.length, 12);
      assert.ok(/[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p), p);
    }
  });
  await test('generador: sin caracteres confusos ni símbolos', () => {
    for (let i = 0; i < 200; i++) {
      const p = C.generatePassword({ length: 20, symbols: false, noAmbiguous: true });
      assert.ok(!/[Il1O0o|]/.test(p) && /^[A-Za-z0-9]+$/.test(p), p);
    }
  });
  await test('generador: sin tipos elegidos devuelve vacío', () => {
    assert.strictEqual(C.generatePassword({ upper: false, lower: false, digits: false, symbols: false }), '');
  });
  await test('generador: distribución sin sesgo evidente', () => {
    const counts = {};
    for (let i = 0; i < 4000; i++) for (const ch of C.generatePassword({ length: 10, upper: false, digits: false, symbols: false })) counts[ch] = (counts[ch] || 0) + 1;
    const v = Object.values(counts);
    assert.strictEqual(v.length, 26);
    assert.ok(Math.max(...v) / Math.min(...v) < 1.35, JSON.stringify(counts));
  });
  await test('fuerza: contraseñas típicas son débiles', () => {
    for (const p of ['123456', 'password', 'Password1!', 'qwerty123', 'Barcelona1987', 'P@ssw0rd2024']) {
      assert.ok(C.estimateStrength(p).score <= 1, p + ' ' + JSON.stringify(C.estimateStrength(p)));
    }
  });
  await test('fuerza: aleatorias y frases largas son fuertes', () => {
    for (const p of ['x7#Kq9!vLm2$Wz4', 'correct horse battery staple', C.generatePassword({ length: 20 })]) {
      assert.ok(C.estimateStrength(p).score >= 3, p);
    }
  });
  await test('Pwned Passwords: SHA-1 y búsqueda del sufijo', async () => {
    const h = await C.sha1Hex('password');
    assert.strictEqual(h, '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
    assert.strictEqual(C.pwnedCount('0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n', h.slice(5)), 3861493);
    assert.strictEqual(C.pwnedCount('AAAA:2', h.slice(5)), 0);
  });
  await test('XposedOrNot: lista anidada se aplana (antes contaba 1 brecha)', () => {
    assert.deepStrictEqual(C.parseCheckEmail({ breaches: [['Adobe', 'LinkedIn', 'Dropbox']] }), ['Adobe', 'LinkedIn', 'Dropbox']);
    assert.deepStrictEqual(C.parseCheckEmail({ Error: 'Not found' }), []);
  });
  await test('XposedOrNot: breach-analytics ordenado por fecha', () => {
    const r = C.parseAnalytics({
      ExposedBreaches: { breaches_details: [
        { breach: 'Old', xposed_date: '2012', xposed_records: 10, xposed_data: 'Email addresses;Passwords' },
        { breach: 'New', xposed_date: '2024', xposed_records: 5, xposed_data: 'Names' },
      ] },
      BreachMetrics: { risk: [{ risk_label: 'High', risk_score: 80 }] },
    });
    assert.deepStrictEqual(r.breaches.map(b => b.name), ['New', 'Old']);
    assert.deepStrictEqual(r.breaches[1].data, ['Email addresses', 'Passwords']);
    assert.deepStrictEqual(r.risk, { label: 'High', score: 80 });
    assert.strictEqual(C.parseAnalytics({ ExposedBreaches: null }), null);
  });
  await test('validaciones', () => {
    assert.ok(C.isEmail('a.b+c@ejemplo.es') && !C.isEmail('a@b') && !C.isEmail('<x>@y.com'));
    assert.strictEqual(C.cleanDomain('https://www.Ejemplo.com/ruta?x=1'), 'ejemplo.com');
    assert.strictEqual(C.cleanDomain('-malo.com'), '');
    assert.ok(C.isIPv4('8.8.8.8') && !C.isIPv4('256.1.1.1') && C.isIPv6('2001:4860:4860::8888') && !C.isIPv6('hola'));
    assert.strictEqual(C.normalizeUrl('ejemplo.com'), 'https://ejemplo.com/');
    assert.strictEqual(C.normalizeUrl('javascript:alert(1)'), '');
    assert.strictEqual(C.normalizeUrl('ftp://ejemplo.com'), '');
  });
  await test('DNS: NXDOMAIN, vacío y registros', () => {
    assert.strictEqual(C.parseDns({ Status: 3 }, 'A').status, 'nxdomain');
    assert.strictEqual(C.parseDns({ Status: 0, Answer: [] }, 'MX').status, 'empty');
    const r = C.parseDns({ Status: 0, AD: true, Answer: [{ name: 'x.com.', type: 16, TTL: 60, data: '"v=spf1 -all"' }, { name: 'x.com.', type: 5, TTL: 60, data: 'y.' }] }, 'TXT');
    assert.strictEqual(r.records.length, 1);
    assert.strictEqual(r.records[0].data, 'v=spf1 -all');
    assert.ok(r.dnssec);
  });
  await test('SPF y DMARC', () => {
    assert.strictEqual(C.mailSecurity(['v=spf1 mx -all'], []).spf.level, 'strict');
    assert.strictEqual(C.mailSecurity(['v=spf1 ~all'], []).spf.level, 'soft');
    assert.strictEqual(C.mailSecurity(['v=spf1 a', 'v=spf1 b'], []).spf.level, 'multiple');
    assert.strictEqual(C.mailSecurity([], []).spf, null);
    assert.strictEqual(C.mailSecurity([], ['v=DMARC1; p=quarantine']).dmarc.policy, 'quarantine');
  });
  await test('RDAP', () => {
    const r = C.parseRdap({
      ldhName: 'EXAMPLE.COM', status: ['client delete prohibited'],
      events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }, { eventAction: 'expiration', eventDate: '2026-08-13T04:00:00Z' }],
      entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'RESERVED-IANA']]] }],
      nameservers: [{ ldhName: 'A.IANA-SERVERS.NET' }], secureDNS: { delegationSigned: true },
    });
    assert.deepStrictEqual([r.name, r.registered, r.expires, r.registrar, r.dnssec], ['example.com', '1995-08-14', '2026-08-13', 'RESERVED-IANA', true]);
    assert.strictEqual(C.parseRdap({}), null);
  });
  console.log(`\n${n} pruebas correctas`);
})().catch(e => { console.error(e); process.exit(1); });
