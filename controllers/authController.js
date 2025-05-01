import { hash, compare } from 'bcryptjs';
import { query } from '../models/db.js';
import { Fido2Lib } from 'fido2-lib';
import { generateToken } from '../utils/jwt.js';
import base64url from 'base64url';

const fido2 = new Fido2Lib({
  timeout: 60000,
  rpId: 'ovs-frontend-drab.vercel.app', // Replace with your domain in production
  rpName: 'Online Voting System',
  challengeSize: 64,
  attestation: 'none',
  authenticatorAttachment: 'platform',
  authenticatorRequireResidentKey: false,
  authenticatorUserVerification: 'required',
});

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

// WebAuthn register start
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
        id: Buffer.from(userId.toString()), // Required to be a Buffer
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
    
    // 🔁 Encode binary fields before sending to frontend
    const formattedOptions = {
      ...registrationOptions,
      challenge: base64url.encode(registrationOptions.challenge),
      user: {
        ...registrationOptions.user,
        id: base64url.encode(registrationOptions.user.id)
      }
    };

    // Store challenge in DB
    await query('UPDATE users SET challenge = $1 WHERE id = $2', [
      registrationOptions.challenge.toString('base64'),
      userId
    ]);

    res.json(registrationOptions);
  } catch (err) {
    console.error('Error during fingerprint register start:', err);
    res.status(500).json({ message: err.message });
  }
};

// WebAuthn register verify
const verifyFingerprintRegister = async (req, res) => {
  const { id, rawId, response, type } = req.body;
  console.log('Received WebAuthn response:', req.body);

  try {
    const userId = req.user.id;

    const result = await query('SELECT * FROM users WHERE id = $1', [userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = result.rows[0];

    const expected = {
      challenge: Buffer.from(user.challenge, 'base64'),
      origin: 'https://ovs-frontend-drab.vercel.app', // your frontend origin
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
    console.error('Error during fingerprint registration verification:', err);
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

    // Save challenge to DB
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
  hasFingerprint,
  startFingerprintRegister,
  verifyFingerprintRegister,
  startFingerprintLogin
};
