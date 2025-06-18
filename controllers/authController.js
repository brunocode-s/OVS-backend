import { hash, compare } from 'bcryptjs';
import { query } from '../models/db.js';
// import { Fido2Lib } from 'fido2-lib';
import { generateToken } from '../utils/jwt.js';
import { sendEmail } from '../utils/email.js';
import jwt from 'jsonwebtoken';
// import base64url from 'base64url';

// const fido2 = new Fido2Lib({
//   timeout: 60000,
//   rpId: 'ovs-frontend-drab.vercel.app',
//   rpName: 'Online Voting System',
//   challengeSize: 64,
//   attestation: 'none',
//   authenticatorAttachment: 'platform',
//   authenticatorRequireResidentKey: false,
//   authenticatorUserVerification: 'required',
// });

// Helper function to send password reset email
const sendPasswordResetEmail = async (email, firstName, resetLink) => {
  const appName = 'Online Voting System';
  const logoUrl = 'https://yourdomain.com/logo.png'; // Replace with your logo URL
  const subject = `${appName} - Password Reset Request`;
  const text = `Hello ${firstName},\n\nYou requested to reset your password on ${appName}. Click this link to reset it: ${resetLink}`;

  const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: auto; padding: 20px;">
      <div style="text-align: center;">
        <img src="${logoUrl}" alt="${appName} Logo" style="max-width: 150px; margin-bottom: 20px;" />
      </div>
      <h2 style="color: #2c3e50;">Reset Your Password</h2>
      <p>Hi <strong>${firstName}</strong>,</p>
      <p>You requested to reset your password on <strong>${appName}</strong>. Click the button below to proceed:</p>
      <p style="text-align: center;">
        <a href="${resetLink}" style="display: inline-block; padding: 10px 20px; background-color: #3498db; color: #fff; text-decoration: none; border-radius: 5px;">
          Reset Password
        </a>
      </p>
      <p>If the button doesn't work, copy and paste this link into your browser:</p>
      <p style="word-break: break-word; color: #555;">${resetLink}</p>
      <hr style="margin: 30px 0;" />
      <footer style="font-size: 12px; color: #999; text-align: center;">
        <p>If you didn't request this, you can safely ignore this email.</p>
        <p>— The ${appName} Team</p>
        <div style="margin-top: 10px;">
          <a href="https://twitter.com/yourapp" style="margin: 0 5px; text-decoration: none; color: #3498db;">Twitter</a> |
          <a href="https://facebook.com/yourapp" style="margin: 0 5px; text-decoration: none; color: #3498db;">Facebook</a> |
          <a href="https://yourapp.com" style="margin: 0 5px; text-decoration: none; color: #3498db;">Website</a>
        </div>
      </footer>
    </div>
  `;

  await sendEmail(email, subject, text, html);
};

const register = async (req, res) => {
  const { firstName, lastName, email, password, role } = req.body;

  try {
    const existingUser = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await hash(password, 10);

    const newUser = await query(
      `INSERT INTO users (firstname, lastname, email, password, role)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, firstname, lastname, email, role`,
      [firstName, lastName, email, hashedPassword, role || 'voter']
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

    await sendPasswordResetEmail(email, user.firstName, resetLink);

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

    // Query count of authenticators for user
    const result = await query('SELECT COUNT(*) FROM authenticators WHERE user_id = $1', [userId]);

    // result.rows[0].count is a string, so parseInt
    const count = parseInt(result.rows[0].count, 10);

    // If count is 0, no fingerprint registered
    const hasFingerprint = count > 0;

    // Optionally check if user exists in users table first if needed

    res.json({ hasFingerprint });
  } catch (err) {
    console.error('Error checking fingerprint for user', req.user.id, ':', err);
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
};


// const startFingerprintLogin = async (req, res) => {
//   try {
//     const { email } = req.body;

//     // Step 1: Get user by email
//     const userResult = await query('SELECT * FROM users WHERE email = $1', [email]);
//     if (userResult.rows.length === 0) {
//       return res.status(404).json({ message: 'User not found' });
//     }

//     const user = userResult.rows[0];

//     // Step 2: Get all authenticators for this user
//     const authResult = await query('SELECT * FROM authenticators WHERE user_id = $1', [user.id]);
//     if (authResult.rows.length === 0) {
//       return res.status(404).json({ message: 'No fingerprint authenticators found for this user' });
//     }

//     // Step 3: Format allowCredentials from authenticators
//     const allowCredentials = authResult.rows.map((authenticator) => ({
//       type: 'public-key',
//       id: Buffer.from(authenticator.credential_id, 'base64'),
//       transports: ['internal'],
//     }));

//     // Step 4: Generate assertion options
//     const options = await fido2.assertionOptions();
//     options.challenge = base64url.encode(options.challenge);
//     options.allowCredentials = allowCredentials;

//     // Step 5: Save challenge in users table
//     await query('UPDATE users SET challenge = $1 WHERE id = $2', [
//       options.challenge,
//       user.id
//     ]);

//     // Step 6: Respond with options
//     res.json(options);
//   } catch (err) {
//     console.error('Error during fingerprint login start:', err);
//     res.status(500).json({ message: 'Internal server error' });
//   }
// };


// const verifyFingerprintLogin = async (req, res) => {
//   const { id, rawId, response, type } = req.body;

//   try {
//     const credentialId = base64url.encode(Buffer.from(rawId, 'base64'));

//     const authResult = await query('SELECT * FROM authenticators WHERE credential_id = $1', [credentialId]);
//     if (authResult.rows.length === 0) {
//       return res.status(404).json({ message: 'Authenticator not found' });
//     }

//     const authenticator = authResult.rows[0];

//     const userResult = await query('SELECT * FROM users WHERE id = $1', [authenticator.user_id]);
//     if (userResult.rows.length === 0) {
//       return res.status(404).json({ message: 'User not found' });
//     }

//     const user = userResult.rows[0];

//     const expected = {
//       challenge: user.challenge,
//       origin: 'https://ovs-frontend-drab.vercel.app',
//       factor: 'either',
//       publicKey: authenticator.public_key,
//       prevCounter: authenticator.counter,
//       userHandle: null,
//       rpId: 'ovs-frontend-drab.vercel.app'
//     };

//     const assertionResult = await fido2.assertionResult(
//       { id, rawId, response, type },
//       expected
//     );

//     if (assertionResult.verified) {
//       // Update counter
//       await query('UPDATE authenticators SET counter = $1 WHERE credential_id = $2', [
//         assertionResult.authnrData.get('counter'),
//         credentialId
//       ]);

//       const token = generateToken({
//         id: user.id,
//         firstName: user.firstname,
//         lastName: user.lastname,
//         email: user.email,
//         role: user.role
//       });

//       return res.status(200).json({
//         user: {
//           id: user.id,
//           firstName: user.firstname,
//           lastName: user.lastname,
//           email: user.email,
//           role: user.role
//         },
//         token
//       });
//     } else {
//       return res.status(401).json({ message: 'Fingerprint verification failed' });
//     }
//   } catch (err) {
//     console.error('Error during fingerprint login verification:', err);
//     res.status(500).json({ message: 'Internal server error' });
//   }
// };

export {
  register,
  login,
  forgotPassword,
  resetPassword,
  hasFingerprint,
  // startFingerprintLogin,
  // verifyFingerprintLogin
};
