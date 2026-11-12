function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).end();
  return next();
}

function requireRole(role) {
  return (req, res, next) => (req.user && req.user.role === role ? next() : res.status(403).end());
}

module.exports = { requireAuth, requireRole };
