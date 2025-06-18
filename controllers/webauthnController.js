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
    console.log('Session data:', { 
      hasChallenge: !!expectedChallenge, 
      hasRpID: !!rpID,
      challengeExpiry: req.session.challengeExpiresAt,
      currentTime: Date.now()
    });
    
    // Validate session data first
    if (!expectedChallenge || Date.now() > req.session.challengeExpiresAt) {
      return res.status(400).json({ message: 'Challenge expired or missing' });
    }
    
    // Validate response structure
    if (!body.response || !body.response.authenticatorData || !body.response.signature || !body.response.clientDataJSON) {
      console.log('❌ Invalid response structure');
      return res.status(400).json({ message: 'Invalid WebAuthn response structure' });
    }

    console.log('Raw ID from request:', body.rawId);
    console.log('Raw ID type:', typeof body.rawId);
    console.log('Raw ID length:', body.rawId?.length);

    let credentialIDBuffer;
    try {
      credentialIDBuffer = isoBase64URL.toBuffer(body.rawId);
      console.log('✅ Successfully converted rawId to buffer:', credentialIDBuffer.toString('hex'));
    } catch (bufferError) {
      console.error('❌ Failed to convert rawId to buffer:', bufferError.message);
      return res.status(400).json({ message: 'Invalid credential ID format' });
    }

    console.log('🔍 Looking up authenticator in database...');
    console.log('Query params:', {
      credentialIDBuffer: credentialIDBuffer.toString('hex'),
      bufferLength: credentialIDBuffer.length
    });

    const authRow = await query(
      'SELECT * FROM authenticators WHERE credential_id = $1',
      [credentialIDBuffer]
    );

    console.log('Database query result:', {
      rowCount: authRow.rows.length,
      rows: authRow.rows.map(row => ({
        id: row.id,
        user_id: row.user_id,
        credential_id_hex: row.credential_id?.toString('hex'),
        public_key_length: row.public_key?.length,
        counter: row.counter,
        counter_type: typeof row.counter
      }))
    });

    if (!authRow.rows.length) {
      console.log('❌ No authenticator found in database');
      
      // Debug: Let's see what credential IDs exist in the database
      const allCreds = await query('SELECT id, credential_id FROM authenticators LIMIT 5');
      console.log('Available credential IDs in database:', 
        allCreds.rows.map(row => ({
          id: row.id,
          credential_id_hex: row.credential_id?.toString('hex')
        }))
      );
      
      return res.status(400).json({ message: 'Authenticator not found' });
    }

    const auth = authRow.rows[0];
    console.log('Found authenticator record:', {
      id: auth.id,
      user_id: auth.user_id,
      has_credential_id: !!auth.credential_id,
      has_public_key: !!auth.public_key,
      counter: auth.counter,
      counter_type: typeof auth.counter,
      counter_is_null: auth.counter === null,
      counter_is_undefined: auth.counter === undefined
    });

    // CRITICAL: Check if auth object is valid
    if (!auth) {
      console.error('❌ Auth object is falsy after database query');
      return res.status(500).json({ message: 'Database returned invalid authenticator' });
    }

    if (!auth.credential_id) {
      console.error('❌ Missing credential_id in database record');
      return res.status(500).json({ message: 'Invalid authenticator: missing credential_id' });
    }

    if (!auth.public_key) {
      console.error('❌ Missing public_key in database record');
      return res.status(500).json({ message: 'Invalid authenticator: missing public_key' });
    }

    // Handle counter with extreme care
    let counterValue = 0;
    console.log('Processing counter value:', {
      raw: auth.counter,
      type: typeof auth.counter,
      isNull: auth.counter === null,
      isUndefined: auth.counter === undefined,
      toString: String(auth.counter)
    });

    if (auth.counter !== null && auth.counter !== undefined) {
      if (typeof auth.counter === 'string') {
        const parsed = parseInt(auth.counter, 10);
        counterValue = isNaN(parsed) ? 0 : parsed;
      } else if (typeof auth.counter === 'number') {
        counterValue = auth.counter;
      } else if (typeof auth.counter === 'bigint') {
        counterValue = Number(auth.counter);
      } else {
        console.warn('⚠️  Unknown counter type, defaulting to 0:', typeof auth.counter);
        counterValue = 0;
      }
    }

    if (counterValue < 0) {
      console.warn('⚠️  Negative counter value, setting to 0:', counterValue);
      counterValue = 0;
    }

    console.log('Final counter value:', counterValue, typeof counterValue);

    // Create authenticator device with extensive validation
    let authenticatorDevice;
    
    try {
      console.log('🔧 Creating authenticator device object...');
      
      // Ensure credential ID is a proper Buffer
      let credentialIDForDevice;
      if (Buffer.isBuffer(auth.credential_id)) {
        credentialIDForDevice = auth.credential_id;
      } else if (typeof auth.credential_id === 'string') {
        credentialIDForDevice = Buffer.from(auth.credential_id, 'hex');
      } else {
        throw new Error('credential_id is not a Buffer or string');
      }

      // Ensure public key is a proper Buffer
      let publicKeyBuffer;
      try {
        publicKeyBuffer = Buffer.from(auth.public_key, 'base64');
      } catch (publicKeyError) {
        throw new Error(`Failed to decode public key from base64: ${publicKeyError.message}`);
      }

      authenticatorDevice = {
        credentialID: credentialIDForDevice,
        credentialPublicKey: publicKeyBuffer,
        counter: counterValue,
        transports: Array.isArray(auth.transports) ? auth.transports : []
      };

      console.log('✅ Authenticator device created:', {
        credentialID_isBuffer: Buffer.isBuffer(authenticatorDevice.credentialID),
        credentialID_length: authenticatorDevice.credentialID?.length,
        credentialPublicKey_isBuffer: Buffer.isBuffer(authenticatorDevice.credentialPublicKey),
        credentialPublicKey_length: authenticatorDevice.credentialPublicKey?.length,
        counter: authenticatorDevice.counter,
        counter_type: typeof authenticatorDevice.counter,
        transports: authenticatorDevice.transports,
        allKeys: Object.keys(authenticatorDevice)
      });

    } catch (deviceError) {
      console.error('❌ Failed to create authenticator device:', deviceError.message);
      return res.status(500).json({ 
        message: 'Failed to create authenticator device', 
        error: deviceError.message 
      });
    }

    // Final validation before calling SimpleWebAuthn
    const validationChecks = {
      authenticatorDevice_exists: !!authenticatorDevice,
      authenticatorDevice_type: typeof authenticatorDevice,
      has_credentialID: !!authenticatorDevice.credentialID,
      credentialID_isBuffer: Buffer.isBuffer(authenticatorDevice.credentialID),
      has_credentialPublicKey: !!authenticatorDevice.credentialPublicKey,
      credentialPublicKey_isBuffer: Buffer.isBuffer(authenticatorDevice.credentialPublicKey),
      has_counter: authenticatorDevice.hasOwnProperty('counter'),
      counter_value: authenticatorDevice.counter,
      counter_type: typeof authenticatorDevice.counter,
      counter_isNumber: typeof authenticatorDevice.counter === 'number'
    };

    console.log('🔍 Final validation checks:', validationChecks);

    // Check each required property
    if (!authenticatorDevice) {
      console.error('❌ CRITICAL: authenticatorDevice is falsy');
      return res.status(500).json({ message: 'Authenticator device is undefined' });
    }

    if (!authenticatorDevice.hasOwnProperty('counter')) {
      console.error('❌ CRITICAL: authenticatorDevice missing counter property');
      return res.status(500).json({ message: 'Authenticator device missing counter property' });
    }

    if (typeof authenticatorDevice.counter !== 'number') {
      console.error('❌ CRITICAL: counter is not a number:', typeof authenticatorDevice.counter);
      return res.status(500).json({ message: 'Authenticator counter must be a number' });
    }

    // Prepare verification parameters
    const verificationParams = {
      response: {
        id: body.id,
        rawId: body.rawId,
        type: body.type,
        response: {
          authenticatorData: body.response.authenticatorData,
          signature: body.response.signature,
          clientDataJSON: body.response.clientDataJSON,
          userHandle: body.response.userHandle
        }
      },
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: rpID,
      authenticator: authenticatorDevice
    };

    console.log('🚀 About to call verifyAuthenticationResponse with params:', {
      response_exists: !!verificationParams.response,
      expectedChallenge_exists: !!verificationParams.expectedChallenge,
      expectedOrigin_exists: !!verificationParams.expectedOrigin,
      expectedRPID_exists: !!verificationParams.expectedRPID,
      authenticator_exists: !!verificationParams.authenticator,
      authenticator_is_object: typeof verificationParams.authenticator === 'object',
      authenticator_has_counter: verificationParams.authenticator?.hasOwnProperty('counter'),
      authenticator_counter_value: verificationParams.authenticator?.counter
    });

    // THIS IS THE CRITICAL CALL - if it fails, we know the authenticator object is the problem
    const verification = await verifyAuthenticationResponse(verificationParams);

    console.log('✅ Verification completed:', {
      verified: verification.verified,
      hasAuthInfo: !!verification.authenticationInfo
    });

    if (verification.verified && verification.authenticationInfo) {
      const newCounter = verification.authenticationInfo.newCounter ?? counterValue;
      
      await query(
        'UPDATE authenticators SET counter = $1 WHERE id = $2',
        [newCounter, auth.id]
      );

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
    console.error('❌ Authentication verification failed:', err.message);
    console.error('Error name:', err.name);
    console.error('Error stack:', err.stack);
    
    // Log the specific line that failed
    if (err.stack.includes('verifyAuthenticationResponse.js:144')) {
      console.error('🚨 ERROR AT LINE 144 - This means authenticator parameter is undefined');
      console.error('The authenticatorDevice object was not properly passed to SimpleWebAuthn');
    }
    
    res.status(500).json({ 
      message: 'Authentication failed', 
      error: err.message,
      line: err.stack.includes('verifyAuthenticationResponse.js:144') ? 'Line 144 - authenticator undefined' : 'Other error'
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
