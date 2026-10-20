// Pruebas de las funciones de Vercel con req/res simulados: node tests/api.test.mjs
// Las comprobaciones contra internet se saltan con OFFLINE=1.
import assert from 'node:assert';
import { parsePublicUrl, assertPublicHost, cors } from '../api/_security.js';
import headers from '../api/headers.js';

let n = 0;
const test = async (name, fn) => { await fn(); n++; console.log('  ✓ ' + name); };

function fakeRes() {
  const r = { code: 200, headers: {}, body: undefined };
  r.setHeader = (k, v) => { r.headers[k.toLowerCase()] = v; };
  r.status = c => { r.code = c; return r; };
  r.json = b => { r.body = b; return r; };
  r.end = () => r;
  return r;
}

await test('URL: solo http(s), sin credenciales ni puertos raros', () => {
  assert.ok(parsePublicUrl('ejemplo.com'));
  assert.strictEqual(parsePublicUrl('file:///etc/passwd'), null);
  assert.strictEqual(parsePublicUrl('http://user:pw@ejemplo.com'), null);
  assert.strictEqual(parsePublicUrl('http://ejemplo.com:6379'), null);
  assert.strictEqual(parsePublicUrl({}), null);
});

await test('SSRF: se bloquean direcciones internas', async () => {
  for (const host of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '169.254.169.254', '172.16.0.1', '[::1]', 'localhost', 'router.local', '0.0.0.0']) {
    await assert.rejects(assertPublicHost(host), /not allowed/, host);
  }
  await assertPublicHost('8.8.8.8');
});

await test('CORS: solo los orígenes de la casa', () => {
  const ok = fakeRes();
  cors({ method: 'GET', headers: { origin: 'https://unfantasmaenelsistema.github.io' } }, ok, 'GET');
  assert.strictEqual(ok.headers['access-control-allow-origin'], 'https://unfantasmaenelsistema.github.io');
  const bad = fakeRes();
  cors({ method: 'GET', headers: { origin: 'https://evil.example' } }, bad, 'GET');
  assert.strictEqual(bad.headers['access-control-allow-origin'], undefined);
  const pre = fakeRes();
  assert.strictEqual(cors({ method: 'OPTIONS', headers: {} }, pre, 'GET'), true);
  assert.strictEqual(pre.code, 204);
});

await test('cabeceras: URL interna rechazada', async () => {
  const res = fakeRes();
  await headers({ method: 'GET', headers: {}, query: { url: 'http://169.254.169.254/latest/meta-data/' } }, res);
  assert.strictEqual(res.code, 502);
  assert.strictEqual(res.body.error, 'Host not allowed');
});

if (!process.env.OFFLINE) {
  await test('cabeceras: análisis real de github.com', async () => {
    const res = fakeRes();
    await headers({ method: 'GET', headers: {}, query: { url: 'https://github.com' } }, res);
    assert.strictEqual(res.code, 200, JSON.stringify(res.body));
    assert.strictEqual(res.body.results['Strict-Transport-Security'].status, 'PRESENT');
    assert.ok(res.body.score >= 75);
  });
}
console.log(`\n${n} pruebas correctas`);
