import { hash, compare } from 'bcryptjs';
import { query } from '../models/db.js';
import { Fido2Lib } from 'fido2-lib';
import { generateToken } from '../utils/jwt.js';
import { sendEmail } from '../utils/email.js';
import jwt from 'jsonwebtoken';
import base64url from 'base64url';

const fido2 = new Fido2Lib({
  timeout: 60000,
  rpId: 'localhost',
  rpName: 'Online Voting System',
  challengeSize: 64,
  attestation: 'none',
  authenticatorAttachment: 'platform',
  authenticatorRequireResidentKey: false,
  authenticatorUserVerification: 'required',
});

// Helper function to send password reset email
const sendPasswordResetEmail = async (email, resetLink) => {
  const subject = 'Password Reset Request';
  const text = `Click this link to reset your password: ${resetLink}`;
  const html = `
    <h2>Reset your password</h2>
    <p>Click the link below to reset your password:</p>
    <a href="${resetLink}">${resetLink}</a>
  `;
  await sendEmail(email, subject, text, html);
};

const register = async (req, res) => {
  const { firstName, lastName, email, password, role, fingerprintId } = req.body;

  try {
    const existingUser = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await hash(password, 10);

    const newUser = await query(
      `INSERT INTO users (firstname, lastname, email, password, role, fingerprint_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, firstname, lastname, email, role, fingerprint_id`,
      [firstName, lastName, email, hashedPassword, role || 'voter', fingerprintId]
    );

    const token = generateToken(newUser.rows[0]);

    res.status(201).json({ user: newUser.rows[0], token });
  } catch (err) {
    console.error('Error during registration:', err);
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
    console.error('Error during login:', err);
    res.status(500).json({ message: err.message });
  }
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const resetLink = `https://ovs-frontend-drab.vercel.app/reset-password/${resetToken}`;

    await sendPasswordResetEmail(email, resetLink);

    res.status(200).json({ message: 'Password reset email sent' });
  } catch (err) {
    console.error('Error in forgot password:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const resetPassword = async (req, res) => {
  const { password } = req.body;
  const token = req.params.token;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const hashedPassword = await hash(password, 10);
    const result = await query('UPDATE users SET password = $1 WHERE email = $2', [
      hashedPassword,
      decoded.email
    ]);

    if (result.rowCount > 0) {
      res.status(200).json({ message: 'Password has been successfully reset' });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (err) {
    console.error('Error in reset password:', err);
    res.status(400).json({ message: 'Invalid or expired token' });
  }
};


const hasFingerprint = async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await query('SELECT fingerprint_id FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const hasFingerprint = !!result.rows[0].fingerprint_id;

    res.json({ hasFingerprint });
  } catch (err) {
    console.error('Error checking fingerprint:', err);
    res.status(500).json({ message: err.message });
  }
};

const startFingerprintRegister = async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await query('SELECT * FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = result.rows[0];
    await query('UPDATE users SET challenge = NULL WHERE id = $1', [userId]);

    const registrationOptions = await fido2.attestationOptions({
      user: {
        id: Buffer.from(userId.toString()),
        name: `${user.firstname} ${user.lastname}`,
        displayName: `${user.firstname} ${user.lastname}`,
      },
      timeout: 60000,
      rp: {
        name: 'Online Voting System',
        id: 'localhost'
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 }
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required'
      },
      attestation: 'none'
    });

    const formattedOptions = {
      ...registrationOptions,
      challenge: base64url.encode(registrationOptions.challenge),
      user: {
        ...registrationOptions.user,
        id: base64url.encode(registrationOptions.user.id)
      }
    };

    await query('UPDATE users SET challenge = $1 WHERE id = $2', [
      registrationOptions.challenge.toString('base64'),
      userId
    ]);

    res.json(formattedOptions);
  } catch (err) {
    console.error('Error during fingerprint register start:', err);
    res.status(500).json({ message: err.message });
  }
};

const verifyFingerprintRegister = async (req, res) => {
  const { id, rawId, response, type } = req.body;

  try {
    const userId = req.user.id;

    const result = await query('SELECT * FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = result.rows[0];
    const expected = {
      challenge: Buffer.from(user.challenge, 'base64'),
      origin: 'https://ovs-frontend-drab.vercel.app',
      factor: 'either',
      rpId: 'localhost'
    };

    const attestationResult = await fido2.attestationResult(
      { id, rawId, response, type },
      expected
    );

    if (attestationResult.verified) {
      await query('UPDATE users SET fingerprint_id = $1 WHERE id = $2', [rawId, userId]);
      res.status(200).json({ success: true });
    } else {
      res.status(400).json({ message: 'Fingerprint verification failed' });
    }
  } catch (err) {
    console.error('Error during fingerprint verification:', err);
    res.status(500).json({ message: err.message });
  }
};

const startFingerprintLogin = async (req, res) => {
  try {
    const { email } = req.body;

    const userResult = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = userResult.rows[0];

    const options = await fido2.assertionOptions();

    options.challenge = base64url.encode(options.challenge);
    options.allowCredentials = [
      {
        type: 'public-key',
        id: user.fingerprint_id,
        transports: ['internal'],
      }
    ];

    await query('UPDATE users SET challenge = $1 WHERE id = $2', [
      Buffer.from(options.challenge, 'base64').toString('base64'),
      user.id
    ]);

    res.json(options);
  } catch (err) {
    console.error('Error during fingerprint login start:', err);
    res.status(500).json({ message: err.message });
  }
};

export {
  register,
  login,
  forgotPassword,
  resetPassword,
  hasFingerprint,
  startFingerprintRegister,
  verifyFingerprintRegister,
  startFingerprintLogin
};
