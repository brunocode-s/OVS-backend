import pkg from 'jsonwebtoken';

const { sign } = pkg;

export function generateToken(user) {
  // You can adjust the payload and options as needed
  const payload = {
    id: user.id,
    role: user.role,
  };
  const options = { expiresIn: '1h' }; // Token expiration time can be adjusted
  return sign(payload, process.env.JWT_SECRET, options);
}

export function verifyToken(token) {
  try {
    return pkg.verify(token, process.env.JWT_SECRET);
  }
  catch (err) {
    return null; // Token is invalid or expired
  }
}
