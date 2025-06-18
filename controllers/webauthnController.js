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

    // ✅ Convert numeric user ID to Buffer (UInt32BE = 4 bytes)
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

    // ✅ FIXED: Ensure we're storing the public key as base64 string
    const publicKeyBase64 = credentialPublicKey.toString('base64');
    const credentialIDBuffer = isoBase64URL.toBuffer(credentialID);

    console.log('📝 Storing authenticator:', {
      user_id: req.user.id,
      credential_id_length: credentialIDBuffer.length,
      public_key_base64_length: publicKeyBase64.length,
      counter: counter,
      transports: transports
    });

    await query(
      `INSERT INTO authenticators (user_id, credential_id, public_key, counter, transports)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        req.user.id,
        credentialIDBuffer, 
        publicKeyBase64, // ✅ Definitely base64 string
        counter || 0, // ✅ Ensure counter has a default value
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
    console.error('Full error details:', err);
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

    req.session.challenge = options.challenge;
    req.session.challengeExpiresAt = Date.now() + 5 * 60 * 1000;
    req.session.rpID = rpID;

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
    
    // Validate session data first
    if (!expectedChallenge || Date.now() > req.session.challengeExpiresAt) {
      return res.status(400).json({ message: 'Challenge expired or missing' });
    }
    
    // Validate response structure
    if (!body.response || !body.response.authenticatorData || !body.response.signature || !body.response.clientDataJSON) {
      console.log('❌ Invalid response structure - missing required fields');
      return res.status(400).json({ 
        message: 'Invalid WebAuthn response structure'
      });
    }
    
    const cleanedBody = {
      id: body.id,
      rawId: body.rawId,
      type: body.type,
      response: {
        authenticatorData: body.response.authenticatorData,
        signature: body.response.signature,
        clientDataJSON: body.response.clientDataJSON,
        userHandle: body.response.userHandle
      }
    };

    const credentialIDBuffer = isoBase64URL.toBuffer(body.rawId);
    console.log('Looking up authenticator for credential ID...');

    const authRow = await query(
      'SELECT * FROM authenticators WHERE credential_id = $1',
      [credentialIDBuffer]
    );

    if (!authRow.rows.length) {
      console.log('❌ Authenticator not found in database');
      return res.status(400).json({ message: 'Authenticator not found' });
    }

    const auth = authRow.rows[0];
    console.log('Found authenticator:', {
      id: auth.id,
      user_id: auth.user_id,
      counter: auth.counter,
      counter_type: typeof auth.counter
    });

    // ✅ CRITICAL FIX: Ensure counter is properly handled
    let counterValue = 0;
    if (auth.counter !== null && auth.counter !== undefined) {
      if (typeof auth.counter === 'string') {
        counterValue = parseInt(auth.counter, 10);
      } else if (typeof auth.counter === 'number') {
        counterValue = auth.counter;
      }
      // Handle BigInt from PostgreSQL BIGINT columns
      else if (typeof auth.counter === 'bigint') {
        counterValue = Number(auth.counter);
      }
    }
    
    // Ensure counter is a valid number
    if (isNaN(counterValue) || counterValue < 0) {
      counterValue = 0;
    }

    console.log('Processed counter value:', counterValue);

    // ✅ CRITICAL FIX: Create authenticator object with all required properties
    const authenticatorDevice = {
      credentialID: Buffer.isBuffer(auth.credential_id) 
        ? auth.credential_id 
        : Buffer.from(auth.credential_id, 'hex'),
      credentialPublicKey: Buffer.from(auth.public_key, 'base64'),
      counter: counterValue, // This must be a number, not undefined
      transports: Array.isArray(auth.transports) ? auth.transports : []
    };

    // ✅ VALIDATION: Double-check the authenticator object
    console.log('Authenticator device validation:', {
      hasCredentialID: !!authenticatorDevice.credentialID,
      hasPublicKey: !!authenticatorDevice.credentialPublicKey,
      counter: authenticatorDevice.counter,
      counterType: typeof authenticatorDevice.counter,
      counterIsNumber: typeof authenticatorDevice.counter === 'number',
      transports: authenticatorDevice.transports
    });

    // ✅ FAIL FAST: If any required property is missing or wrong type
    if (!Buffer.isBuffer(authenticatorDevice.credentialID)) {
      console.error('❌ credentialID is not a Buffer');
      return res.status(500).json({ message: 'Invalid credential ID format' });
    }
    
    if (!Buffer.isBuffer(authenticatorDevice.credentialPublicKey)) {
      console.error('❌ credentialPublicKey is not a Buffer');
      return res.status(500).json({ message: 'Invalid public key format' });
    }
    
    if (typeof authenticatorDevice.counter !== 'number') {
      console.error('❌ counter is not a number:', typeof authenticatorDevice.counter, authenticatorDevice.counter);
      return res.status(500).json({ message: 'Invalid counter format' });
    }

    console.log('✅ All authenticator validations passed');

    // ✅ FINAL CHECK: Log the exact object being passed
    console.log('About to call verifyAuthenticationResponse with:', {
      responseExists: !!cleanedBody,
      challengeExists: !!expectedChallenge,
      originExists: !!ORIGIN,
      rpIDExists: !!rpID,
      authenticatorExists: !!authenticatorDevice,
      authenticatorProps: Object.keys(authenticatorDevice),
      authenticatorCounter: authenticatorDevice.counter
    });

    const verification = await verifyAuthenticationResponse({
      response: cleanedBody,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: rpID,
      authenticator: authenticatorDevice, // This object MUST have counter property
    });

    console.log('Verification result:', verification.verified);

    if (verification.verified && verification.authenticationInfo) {
      const newCounter = verification.authenticationInfo.newCounter ?? counterValue;

      console.log('Updating counter from', counterValue, 'to', newCounter);

      await query(
        'UPDATE authenticators SET counter = $1 WHERE id = $2',
        [newCounter, auth.id]
      );

      // Clear session
      req.session.challenge = null;
      req.session.challengeExpiresAt = null;
      req.session.rpID = null;

      // Set user session
      req.session.userId = auth.user_id;
      await req.session.save();

      return res.json({ success: true });
    } else {
      console.log('Verification failed');
      return res.status(400).json({ success: false });
    }
    
  } catch (err) {
    console.error('Authentication verification failed:', err.message);
    console.error('Error stack:', err.stack);
    res.status(500).json({ message: 'Authentication failed', error: err.message });
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
