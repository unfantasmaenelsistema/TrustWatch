// api/safebrowsing.js — consulta Google Safe Browsing (Lookup API v4) sin exponer la clave.
// La clave va en la variable de entorno GOOGLE_SAFEBROWSING_API_KEY del proyecto de Vercel.
import { cors, parsePublicUrl } from './_security.js';

const API_KEY = process.env.GOOGLE_SAFEBROWSING_API_KEY;

export default async (req, res) => {
  if (cors(req, res, 'POST')) return;
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!API_KEY) return res.status(500).json({ error: 'Safe Browsing API key is not configured' });

  const url = parsePublicUrl(req.body && req.body.url);
  if (!url) return res.status(400).json({ error: 'Invalid url' });

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + encodeURIComponent(API_KEY), {
      method: 'POST',
      signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'trustwatch', clientVersion: '2.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: url.href }],
        },
      }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) return res.status(502).json({ error: 'Safe Browsing returned ' + r.status });
    const matches = (data.matches || []).map(m => ({ threatType: m.threatType, platformType: m.platformType }));
    res.status(200).json(matches.length ? { status: 'DANGEROUS', matches } : { status: 'SAFE' });
  } catch (e) {
    res.status(502).json({ error: e.name === 'AbortError' ? 'Timeout' : 'Could not reach Safe Browsing' });
  } finally {
    clearTimeout(timer);
  }
};
