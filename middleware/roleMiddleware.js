export default function (requiredRole) {
    return (req, res, next) => {
      if (req.user.role !== requiredRole) {
        return res.status(403).json({ error: 'Forbidden - insufficient role' });
      }
      next();
    };
  };
  