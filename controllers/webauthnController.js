import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { query } from '../models/db.js';

const ORIGIN = 'https://ovs-frontend-drab.vercel.app';

const getRpID = () => 'ovs-frontend-drab.vercel.app';

// ======== Registration ========

export const getRegistrationOptions = async (req, res) => {
  const user = req.user;
  const rpID = getRpID(req);

  try {
    const authenticators = await query(
      'SELECT credential_id, transports FROM authenticators WHERE user_id = $1',
      [user.id]
    );
    
    const excludedCredentials = authenticators.rows.map(auth => ({
      id: isoBase64URL.fromBuffer(auth.credential_id),
      type: 'public-key',
      transports: auth.transports || undefined
    }));      

    const options = await generateRegistrationOptions({
      rpName: 'Online Voting System',
      rpID,
      userID: Buffer.from(user.id.toString(), 'utf8'),
      userName: user.email,
      timeout: 60000,
      attestationType: 'none',
      authenticatorSelection: {
        userVerification: 'required',
        authenticatorAttachment: 'platform',
      },
      excludedCredentials,
    });

    req.session.challenge = options.challenge;
    req.session.challengeExpiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    req.session.rpID = rpID;

    await req.session.save();

    console.log('Generated registration options:', options);
    res.json(options);
  } catch (err) {
    console.error('Error generating registration options:', err);
    res.status(500).json({ message: 'Error generating registration options' });
  }
};

export const verifyRegistration = async (req, res) => {
  const body = req.body;
  const expectedChallenge = req.session.challenge;
  const challengeExpiresAt = req.session.challengeExpiresAt;
  const rpID = req.session.rpID;

  try {
    if (!expectedChallenge || !challengeExpiresAt || Date.now() > challengeExpiresAt) {
      return res.status(400).json({ message: 'Challenge expired' });
    }

    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: rpID,
    });

    if (!verification.verified) {
      return res.status(400).json({ success: false });
    }

    const {
      credential: {
        id: credentialID,
        publicKey: credentialPublicKey,
        counter,
        transports,
      },
    } = verification.registrationInfo;

    const transportsFormatted = transports && transports.length > 0
      ? `{${transports.join(',')}}`
    : '{}';

    await query(
      `INSERT INTO authenticators (user_id, credential_id, public_key, counter, transports)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        req.user.id,
        credentialID, // Buffer
        credentialPublicKey.toString('base64'), // base64 string
        counter,
        transportsFormatted, 
      ]
    );

    req.session.challenge = null;
    req.session.challengeExpiresAt = null;
    req.session.rpID = null;

    res.json({ success: true });
  } catch (err) {
    console.error('Error verifying registration:', err);
    res.status(500).json({ message: 'Error verifying registration' });
  }
};

// ======== Authentication ========

export const getAuthenticationOptions = async (req, res) => {
  const { email } = req.body;
  const rpID = getRpID(req);

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  try {
    // Get user ID by email
    const userRes = await query('SELECT id FROM users WHERE email = $1', [email]);

    if (userRes.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const userId = userRes.rows[0].id;

    // Get authenticators for the user
    const authRows = await query(
      'SELECT credential_id FROM authenticators WHERE user_id = $1',
      [userId]
    );

    const allowCredentials = authRows.rows.map((auth) => {
      const id = isoBase64URL.fromBuffer(auth.credential_id);
      return {
        id,
        type: 'public-key',
      };
    });

    if (!allowCredentials.length) {
      return res.status(400).json({ message: 'No registered authenticators found' });
    }

    // Generate authentication options
    const options = await generateAuthenticationOptions({
      timeout: 60000,
      rpID,
      allowCredentials,
      userVerification: 'preferred',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
      },
    });

    // Save session challenge if you're using session
    req.session.challenge = options.challenge;
    req.session.challengeExpiresAt = Date.now() + 5 * 60 * 1000;
    req.session.rpID = rpID;

    await req.session.save();

    res.json(options);
  } catch (err) {
    console.error('Error generating authentication options:', err);
    res.status(500).json({ message: 'Error generating authentication options' });
  }
};

export const verifyAuthentication = async (req, res) => {
  const body = req.body;
  const expectedChallenge = req.session.challenge;
  const rpID = req.session.rpID;

  // Log challenge and received challenge
  console.log('Expected Challenge:', expectedChallenge);
  console.log(
    'Received Challenge:',
    JSON.parse(Buffer.from(body.response.clientDataJSON, 'base64')).challenge
  );
  console.log('Received rawId:', body.rawId);

  try {
    const credentialIDBuffer = isoBase64URL.toBuffer(body.rawId);  // Convert to Buffer
    console.log('Received credential ID as buffer:', credentialIDBuffer);

    const authRow = await query(
      'SELECT * FROM authenticators WHERE credential_id = $1',
      [credentialIDBuffer]
    );

    if (authRow.rows.length === 0) {
      return res.status(400).json({ message: 'Authenticator not found' });
    }

    const auth = authRow.rows[0];

    console.log('Comparing credential ID:', {
      storedCredentialID: auth.credential_id.toString('base64'),
      receivedCredentialID: body.rawId,
    });

    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: rpID,
      authenticator: {
        credentialID: auth.credential_id, // Stored as Buffer
        credentialPublicKey: Buffer.from(auth.public_key, 'base64'), // Stored as base64 text
        counter: auth.counter,
      },
    });

    if (verification.verified) {
      await query(
        'UPDATE authenticators SET counter = $1 WHERE id = $2',
        [verification.authenticationInfo.newCounter, auth.id]
      );

      req.session.challenge = null;
      req.session.rpID = null;

      return res.json({ success: true });
    }

    res.status(400).json({ success: false });
  } catch (err) {
    console.error('Error verifying authentication:', err);
    res.status(500).json({ message: 'Error verifying authentication' });
  }
};

// ======== Check Fingerprint ========
export const checkFingerprintRegistration = async (req, res) => {
  console.log('🧪 Checking fingerprint registration for user:', req.user);

  try {
    const result = await query(
      'SELECT 1 FROM authenticators WHERE user_id = $1 LIMIT 1',
      [req.user.id]
    );

    console.log(`🧩 Found ${result.rows.length} authenticators for user_id ${req.user.id}`);

    res.json({ isRegistered: result.rows.length > 0 });
  } catch (err) {
    console.error('❌ Error checking fingerprint registration:', err);
    res.status(500).json({ message: 'Error checking fingerprint registration' });
  }
};

