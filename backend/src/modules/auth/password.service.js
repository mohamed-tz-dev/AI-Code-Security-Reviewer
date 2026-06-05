const crypto = require('crypto');

const KEY_LENGTH = 64;

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, KEY_LENGTH).toString('hex');
  return `scrypt:${salt}:${hash}`;
}

function verifyPassword(password, passwordHash) {
  const [algorithm, salt, storedHash] = String(passwordHash).split(':');

  if (algorithm !== 'scrypt' || !salt || !storedHash) {
    return false;
  }

  const hash = crypto.scryptSync(password, salt, KEY_LENGTH);
  const stored = Buffer.from(storedHash, 'hex');

  return stored.length === hash.length && crypto.timingSafeEqual(stored, hash);
}

module.exports = { hashPassword, verifyPassword };
