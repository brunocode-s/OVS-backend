import { hash, compare } from 'bcrypt';
import { query } from '../models/db.js';
import { generateToken } from '../utils/jwt.js';

const register = async (req, res) => {
  const { firstname, lastname, email, password, role } = req.body;

  try {
    // Check if the user already exists
    const existingUser = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await hash(password, 10);

    // Insert new user with firstName and lastName
    const newUser = await query(
      `INSERT INTO users (firstname, lastname, email, password, role)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, firstName, lastName, email, role`,
      [firstname, lastname, email, hashedPassword, role || 'voter']
    );

    const token = generateToken(newUser.rows[0]);

    res.status(201).json({ user: newUser.rows[0], token });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) return res.status(404).json({ message: 'User not found' });

    const valid = await compare(password, user.rows[0].password);
    if (!valid) return res.status(401).json({ message: 'Invalid credentials' });

    const token = generateToken({
      id: user.rows[0].id,
      firstName: user.rows[0].firstname,
      lastName: user.rows[0].lastname,
      email: user.rows[0].email,
      role: user.rows[0].role
    });

    res.status(200).json({
      user: {
        id: user.rows[0].id,
        firstName: user.rows[0].firstname,
        lastName: user.rows[0].lastname,
        email: user.rows[0].email,
        role: user.rows[0].role
      },
      token
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

export default { register, login };
