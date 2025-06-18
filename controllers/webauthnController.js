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

// ========= REGISTER =========

export const getRegistrationOptions = async (req, res) => {
  const user = req.user;
  const rpID = getRpID();

  try {
    const existingAuthenticators = await query(
      'SELECT credential_id, transports FROM authenticators WHERE user_id = $1',
      [user.id]
    );

    const excludedCredentials = existingAuthenticators.rows.map(auth => ({
      id: isoBase64URL.fromBuffer(auth.credential_id),
      type: 'public-key',
      transports: auth.transports || undefined,
    }));

    // Convert numeric user ID to Buffer (UInt32BE = 4 bytes)
    const userIDBuffer = Buffer.alloc(4);
    userIDBuffer.writeUInt32BE(user.id);

    const options = await generateRegistrationOptions({
      rpName: 'Online Voting System',
      rpID,
      userID: userIDBuffer,
      userName: user.email,
      timeout: 60000,
      attestationType: 'none',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
      },
      excludeCredentials: excludedCredentials,
    });

    req.session.challenge = options.challenge;
    req.session.challengeExpiresAt = Date.now() + 5 * 60 * 1000;
    req.session.rpID = rpID;

    await req.session.save();
    res.json(options);
  } catch (err) {
    console.error('Error generating registration options:', err);
    res.status(500).json({ message: 'Failed to generate registration options' });
  }
};

export const verifyRegistration = async (req, res) => {
  const { body } = req;
  const expectedChallenge = req.session.challenge;
  const rpID = req.session.rpID;

  if (!expectedChallenge || Date.now() > req.session.challengeExpiresAt) {
    return res.status(400).json({ message: 'Challenge expired or missing' });
  }

  try {
    console.log('🔍 Starting registration verification...');
    
    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: rpID,
    });

    console.log('Registration verification result:', verification.verified);

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

    // FIXED: Store public key as Buffer (not base64 string)
    const credentialIDBuffer = isoBase64URL.toBuffer(credentialID);
    // FIXED: Ensure counter is properly handled
    const counterValue = Number(counter) || 0;

    console.log('📝 Storing authenticator:', {
      user_id: req.user.id,
      credential_id_length: credentialIDBuffer.length,
      public_key_length: credentialPublicKey.length,
      counter: counterValue,
      transports: transports
    });

    await query(
      `INSERT INTO authenticators (user_id, credential_id, public_key, counter, transports)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        req.user.id,
        credentialIDBuffer, 
        credentialPublicKey, // Store as Buffer directly
        counterValue,
        transports || [],
      ]
    );

    console.log('✅ Authenticator stored successfully');

    req.session.challenge = null;
    req.session.challengeExpiresAt = null;
    req.session.rpID = null;

    res.json({ success: true });
  } catch (err) {
    console.error('Registration verification failed:', err);
    res.status(500).json({ message: 'Verification failed', error: err.message });
  }
};

// ========= AUTH =========

export const getAuthenticationOptions = async (req, res) => {
  const { email } = req.body;
  const rpID = getRpID();

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  try {
    const userRes = await query('SELECT id FROM users WHERE email = $1', [email]);

    if (userRes.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const userId = userRes.rows[0].id;

    const auths = await query(
      'SELECT credential_id FROM authenticators WHERE user_id = $1',
      [userId]
    );

    if (!auths.rows.length) {
      return res.status(400).json({ message: 'No authenticators found for user' });
    }

    const allowCredentials = auths.rows.map(auth => ({
      id: isoBase64URL.fromBuffer(auth.credential_id),
      type: 'public-key',
    }));

    const options = await generateAuthenticationOptions({
      timeout: 60000,
      rpID,
      allowCredentials,
      userVerification: 'required',
    });

    req.session.challenge = options.challenge; // 🔥 critical fix
    req.session.challengeExpiresAt = Date.now() + 5 * 60 * 1000;
    req.session.rpID = rpID;
    req.session.userId = userId;

    await req.session.save();
    res.json(options);
  } catch (err) {
    console.error('Error generating authentication options:', err);
    res.status(500).json({ message: 'Failed to generate options' });
  }
};

export const verifyAuthentication = async (req, res) => {
  const body = req.body;
  const expectedChallenge = req.session.challenge;
  const rpID = req.session.rpID;

  try {
    console.log('🧪 Starting WebAuthn verification...');
    
    // Debug session data
    console.log('🔍 Session data:', {
      hasChallenge: !!expectedChallenge,
      challengeLength: expectedChallenge?.length,
      rpID,
      challengeExpiresAt: req.session.challengeExpiresAt,
      currentTime: Date.now(),
      challengeValid: req.session.challengeExpiresAt && Date.now() <= req.session.challengeExpiresAt
    });

    // Validate session data
    if (!expectedChallenge || Date.now() > req.session.challengeExpiresAt) {
      return res.status(400).json({ message: 'Challenge expired or missing' });
    }

    // Validate response structure
    console.log('🔍 Request body structure:', {
      hasRawId: !!body.rawId,
      rawIdLength: body.rawId?.length,
      hasResponse: !!body.response,
      hasAuthenticatorData: !!body.response?.authenticatorData,
      hasSignature: !!body.response?.signature,
      hasClientDataJSON: !!body.response?.clientDataJSON,
    });

    if (
      !body.response?.authenticatorData ||
      !body.response?.signature ||
      !body.response?.clientDataJSON
    ) {
      return res.status(400).json({ message: 'Invalid WebAuthn response structure' });
    }

    // Convert rawId to buffer
    const credentialIDBuffer = isoBase64URL.toBuffer(body.rawId);
    console.log('✅ Converted rawId to buffer');

    // Query for authenticator by credential_id (stored as Buffer)
    const authRow = await query(
      'SELECT * FROM authenticators WHERE credential_id = $1',
      [credentialIDBuffer]
    );

    if (!authRow.rows.length) {
      console.log('❌ No authenticator found in database');
      return res.status(400).json({ message: 'Authenticator not found' });
    }

    const auth = authRow.rows[0];
    console.log('✅ Found authenticator:', {
      id: auth.id,
      counter: auth.counter,
      counterType: typeof auth.counter,
      hasCounter: auth.counter !== null && auth.counter !== undefined,
      publicKey: auth.public_key ? '(exists)' : '(missing)',
    });

    // Normalize counter value safely
    let counterValue = 0;
    if (auth.counter !== null && auth.counter !== undefined) {
      if (typeof auth.counter === 'string') {
        counterValue = parseInt(auth.counter, 10);
        if (isNaN(counterValue)) counterValue = 0;
      } else if (typeof auth.counter === 'number') {
        counterValue = auth.counter;
      } else if (typeof auth.counter === 'bigint') {
        counterValue = Number(auth.counter);
      } else {
        console.warn('⚠️ Unexpected counter type:', typeof auth.counter, auth.counter);
        counterValue = 0;
      }
    }
    counterValue = Math.max(0, Math.floor(counterValue) || 0);
    console.log('✅ Counter value determined:', counterValue);

    // Decode stored public key (assumes Base64 text in DB)
    const publicKeyBuffer = Buffer.isBuffer(auth.public_key)
      ? auth.public_key
      : Buffer.from(auth.public_key, 'base64');

    // Prepare credential object expected by verifyAuthenticationResponse()
    // Note: Parameter name is 'credential', not 'authenticator'
    const credential = {
      id: body.rawId, // Use the raw credential ID from the response
      publicKey: publicKeyBuffer,
      counter: counterValue,
      transports: Array.isArray(auth.transports) ? auth.transports : [],
    };

    // Log final credential object
    console.log('👁 Final credential:', {
      id: credential.id,
      publicKeyLength: credential.publicKey.length,
      counter: credential.counter,
      counterType: typeof credential.counter,
      transports: credential.transports,
    });

    // Safety checks before verification
    if (!credential.id || !credential.publicKey) {
      throw new Error('Invalid credential: missing id or publicKey');
    }
    if (typeof credential.counter !== 'number' || isNaN(credential.counter)) {
      throw new Error(`Invalid credential counter: ${credential.counter}`);
    }

    // Perform verification using simplewebauthn
    // IMPORTANT: Parameter name is 'credential', not 'authenticator'
    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: rpID,
      credential: credential, // This is the correct parameter name
      requireUserVerification: true,
    });

    console.log('✅ Verification result:', verification.verified);

    if (verification.verified) {
      const newCounter = verification.authenticationInfo?.newCounter;

      if (newCounter !== undefined && newCounter !== null) {
        console.log('🔄 Updating counter from', counterValue, 'to', newCounter);
        await query(
          'UPDATE authenticators SET counter = $1 WHERE id = $2',
          [newCounter, auth.id]
        );
      }

      // Clear session challenge and save user ID in session
      req.session.challenge = null;
      req.session.challengeExpiresAt = null;
      req.session.rpID = null;
      req.session.userId = auth.user_id;
      await req.session.save();

      return res.json({ success: true });
    } else {
      return res.status(400).json({ success: false });
    }
  } catch (err) {
    console.error('❌ Authentication failed:', err);
    console.error('Stack trace:', err.stack);
    res.status(500).json({
      message: 'Authentication failed',
      error: err.message,
    });
  }
};

// ========= CHECK =========

export const checkFingerprintRegistration = async (req, res) => {
  try {
    const result = await query(
      'SELECT 1 FROM authenticators WHERE user_id = $1 LIMIT 1',
      [req.user.id]
    );
    res.json({ isRegistered: result.rows.length > 0 });
  } catch (err) {
    console.error('Check fingerprint error:', err);
    res.status(500).json({ message: 'Check failed' });
  }
};