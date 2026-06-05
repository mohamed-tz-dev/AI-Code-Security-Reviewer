const userRepository = require('../modules/users/user.repository');
const { verifyToken } = require('../modules/auth/token.service');

async function attachCurrentUser(req, res, next) {
  const authorizationHeader = req.get('authorization') || '';
  const token = authorizationHeader.startsWith('Bearer ')
    ? authorizationHeader.slice('Bearer '.length)
    : null;
  const claims = token ? verifyToken(token) : null;

  if (!claims?.sub) {
    return res.status(401).json({ error: { message: 'Authentication required.' } });
  }

  try {
    const user = await userRepository.findUserById(claims.sub);

    if (!user) {
      return res.status(401).json({ error: { message: 'Invalid session.' } });
    }

    req.currentUser = {
      id: user.id,
      email: user.email,
      role: user.role,
      isAdmin: user.role === 'admin'
    };

    return next();
  } catch (error) {
    return next(error);
  }
}

function requireAdmin(req, res, next) {
  if (!req.currentUser?.isAdmin) {
    return res.status(403).json({ error: { message: 'Admin access required.' } });
  }

  return next();
}

module.exports = { attachCurrentUser, requireAdmin };
