import pkg from 'jsonwebtoken';
const { verify } = pkg;
import { query } from '../models/db.js';

export const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Session expired. Please login again' });

  try {
    const decoded = verify(token, process.env.JWT_SECRET);

    // Get user from DB using the query function
    const result = await query(
      'SELECT id, email, role FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = result.rows[0];
    req.user = {
      id: user.id,
      email: user.email,
      role: user.role,
    };

    next();
  } catch (err) {
    console.error('Authentication error:', err);
    res.status(403).json({ message: 'Invalid or expired token' });
  }
};

export const authenticateJWT = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = verify(token, process.env.JWT_SECRET);

    // Get user from DB using the query function
    const result = await query(
      'SELECT id, email, role FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = result.rows[0];
    req.user = {
      id: user.id,
      email: user.email,
      role: user.role,
    };

    next();
  } catch (err) {
    console.error('Authentication error:', err);
    res.status(403).json({ message: 'Invalid or expired token' });
  }
};
