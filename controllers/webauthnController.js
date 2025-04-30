import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { query } from '../models/db.js';

const ORIGIN = 'http://localhost:5173';

const getRpID = (req) => req.get('host').split(':')[0];

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
  const user = req.user;
  const rpID = getRpID(req);

  try {
    const authRows = await query(
      'SELECT credential_id FROM authenticators WHERE user_id = $1',
      [user.id]
    );
    console.log('Auth Rows:', authRows.rows);

    const allowCredentials = authRows.rows.map((auth) => {
      console.log('auth credential_id buffer:', auth.credential_id);
      
      // Convert the Buffer to a Base64URL string
      const id = isoBase64URL.fromBuffer(auth.credential_id);  // Convert to Base64URL string
      
      console.log('Mapped credential id:', id);
      
      return {
        id,  // Use the Base64URL string here
        type: 'public-key',
      };
    });

    console.log('allowCredentials to send:', allowCredentials);

    if (!allowCredentials.length) {
      console.log('No valid found for user');
      return res.status(400).json({ message: 'No registered authenticators' });
    }

    const options = await generateAuthenticationOptions({
      timeout: 60000,
      rpID,
      allowCredentials,
      userVerification: 'preferred',
      authenticatorSelection: {
        authenticatorAttachment: "platform", // this forces built-in options (like fingerprint)
        userVerification: "required" // enforce biometric check
      },
    });

    console.log('Generated authentication options:', options);

    req.session.challenge = options.challenge;
    console.log('Current session challenge:', req.session.challenge);
    req.session.challengeExpiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    req.session.rpID = rpID;

    await req.session.save();

    console.log('Current session after save:', req.session);
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

