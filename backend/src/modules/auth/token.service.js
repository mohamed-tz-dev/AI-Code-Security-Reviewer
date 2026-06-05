const crypto = require('crypto');
const { env } = require('../../config/env');

const TOKEN_TTL_SECONDS = 12 * 60 * 60;

function base64UrlEncode(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function base64UrlDecode(value) {
  return JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
}

function sign(value) {
  return crypto.createHmac('sha256', env.authSessionSecret).update(value).digest('base64url');
}

function createToken(user) {
  const header = base64UrlEncode({ alg: 'HS256', typ: 'JWT' });
  const payload = base64UrlEncode({
    sub: user.id,
    email: user.email,
    role: user.role,
    exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS
  });
  const unsigned = `${header}.${payload}`;

  return `${unsigned}.${sign(unsigned)}`;
}

function verifyToken(token) {
  try {
    const [header, payload, signature] = String(token).split('.');

    if (!header || !payload || !signature) {
      return null;
    }

    const unsigned = `${header}.${payload}`;
    const expectedSignature = sign(unsigned);
    const signatureBuffer = Buffer.from(signature);
    const expectedSignatureBuffer = Buffer.from(expectedSignature);

    if (
      signatureBuffer.length !== expectedSignatureBuffer.length ||
      !crypto.timingSafeEqual(signatureBuffer, expectedSignatureBuffer)
    ) {
      return null;
    }

    const claims = base64UrlDecode(payload);
    if (!claims.exp || claims.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return claims;
  } catch (_error) {
    return null;
  }
}

module.exports = { createToken, verifyToken };
