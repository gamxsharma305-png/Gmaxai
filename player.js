const crypto = require('crypto');

function getDeviceSafe(id) {
  const s = String(id || 'XXXX').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
  return (s + 'XXXXXXXX').slice(0, 8);
}

function signToken(payload, secret) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return data + '.' + sig;
}

function verifyToken(token, secret) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  if (!data || !sig) return null;
  const expect = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  // timing-safe compare
  try {
    const a = Buffer.from(sig);
    const b = Buffer.from(expect);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  } catch (_) {
    return null;
  }
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (!payload || !payload.exp || Date.now() > payload.exp) return null;
    if (!payload.d) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const secret = process.env.KEY_SECRET || process.env.AROLINKS_TOKEN || 'change-me';
  const playerUrl = process.env.PLAYER_URL || '';

  if (!playerUrl) {
    return res.status(500).json({ ok: false, error: 'PLAYER_URL not set in Vercel env' });
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (_) { body = {}; }
  }
  body = body || {};

  const token = String(body.token || '');
  const deviceId = getDeviceSafe(body.deviceId);

  const payload = verifyToken(token, secret);
  if (!payload) {
    return res.status(401).json({ ok: false, error: 'Invalid or expired token' });
  }

  // Token must match this device
  if (getDeviceSafe(payload.d) !== deviceId) {
    return res.status(401).json({ ok: false, error: 'Token device mismatch' });
  }

  // Only return URL — never log it in response headers unnecessarily
  return res.status(200).json({
    ok: true,
    url: playerUrl,
    exp: payload.exp,
  });
};

// Export helpers for verify.js reuse pattern (optional)
module.exports.signToken = signToken;
module.exports.getDeviceSafe = getDeviceSafe;
