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

    await query(
      `INSERT INTO authenticators (user_id, credential_id, public_key, counter, transports)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        req.user.id,
        isoBase64URL.toBuffer(credentialID), 
        credentialPublicKey.toString('base64'),
        counter,
        transports || [],
      ]
    );

    req.session.challenge = null;
    req.session.challengeExpiresAt = null;
    req.session.rpID = null;

    res.json({ success: true });
  } catch (err) {
    console.error('Registration verification failed:', err);
    res.status(500).json({ message: 'Verification failed' });
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
    console.log('Expected Challenge:', expectedChallenge);
    console.log('Request rawId:', body.rawId);
    console.log('Session rpID:', rpID);
    
    // Log the entire request body structure
    console.log('🔍 REQUEST BODY STRUCTURE:');
    console.log('- body.id:', body.id);
    console.log('- body.rawId:', body.rawId);
    console.log('- body.type:', body.type);
    console.log('- body.response exists:', !!body.response);
    
    if (body.response) {
      console.log('- body.response.authenticatorData:', body.response.authenticatorData?.substring(0, 50) + '...');
      console.log('- body.response.signature:', body.response.signature?.substring(0, 50) + '...');
      console.log('- body.response.clientDataJSON:', body.response.clientDataJSON?.substring(0, 50) + '...');
      console.log('- body.response.userHandle:', body.response.userHandle);
      
      console.log('- authenticatorData length:', body.response.authenticatorData?.length);
      console.log('- signature length:', body.response.signature?.length);
      console.log('- clientDataJSON length:', body.response.clientDataJSON?.length);
    }
    
    // Validate response structure
    if (!body.response || !body.response.authenticatorData || !body.response.signature || !body.response.clientDataJSON) {
      console.log('❌ Invalid response structure - missing required fields');
      return res.status(400).json({ 
        message: 'Invalid WebAuthn response structure',
        missing: {
          response: !body.response,
          authenticatorData: !body.response?.authenticatorData,
          signature: !body.response?.signature,
          clientDataJSON: !body.response?.clientDataJSON
        }
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
    
    console.log('🧹 Using cleaned request body for verification');

    const credentialIDBuffer = isoBase64URL.toBuffer(body.rawId);
    console.log('Parsed Credential ID Buffer:', credentialIDBuffer.toString('hex'));

    const authRow = await query(
      'SELECT * FROM authenticators WHERE credential_id = $1',
      [credentialIDBuffer]
    );
    console.log('Authenticator lookup result:', authRow.rows);

    if (!authRow.rows.length) {
      return res.status(400).json({ message: 'Authenticator not found' });
    }

    const auth = authRow.rows[0];

    // ✅ FIXED: Better counter handling with explicit type checking
    console.log('Raw auth counter value:', auth.counter, 'type:', typeof auth.counter);
    
    // Ensure counter is a valid number
    let counterValue = 0;
    if (auth.counter !== null && auth.counter !== undefined) {
      const parsedCounter = parseInt(auth.counter, 10);
      if (!isNaN(parsedCounter)) {
        counterValue = parsedCounter;
      }
    }
    
    console.log('Processed counter value:', counterValue);

    // Add detailed logging before creating authenticator device
    console.log('Auth object details:', {
      id: auth.id,
      counter: auth.counter,
      counterProcessed: counterValue,
      public_key_type: typeof auth.public_key,
      public_key_length: auth.public_key?.length,
      credential_id_type: typeof auth.credential_id,
      credential_id_is_buffer: Buffer.isBuffer(auth.credential_id)
    });

    // ✅ FIXED: More robust authenticator device creation with safety checks
    let authenticatorDevice;
    
    try {
      // Ensure we have the required data
      if (!auth.credential_id) {
        throw new Error('Missing credential_id in database record');
      }
      if (!auth.public_key) {
        throw new Error('Missing public_key in database record');
      }
      
      authenticatorDevice = {
        credentialID: Buffer.isBuffer(auth.credential_id) 
          ? auth.credential_id 
          : Buffer.from(auth.credential_id, 'hex'),
        credentialPublicKey: Buffer.from(auth.public_key, 'base64'),
        counter: counterValue,
        transports: auth.transports || []
      };
      
      console.log('✅ Authenticator device created successfully');
      
    } catch (deviceCreationError) {
      console.error('❌ Failed to create authenticator device:', deviceCreationError.message);
      return res.status(500).json({ 
        message: 'Failed to create authenticator device', 
        error: deviceCreationError.message 
      });
    }
    
    // ✅ ADDED: Validate authenticator device before using it
    if (!Buffer.isBuffer(authenticatorDevice.credentialID)) {
      console.error('❌ credentialID is not a Buffer:', typeof authenticatorDevice.credentialID);
      return res.status(500).json({ message: 'Invalid authenticator credential ID format' });
    }
    
    if (!Buffer.isBuffer(authenticatorDevice.credentialPublicKey)) {
      console.error('❌ credentialPublicKey is not a Buffer:', typeof authenticatorDevice.credentialPublicKey);
      return res.status(500).json({ message: 'Invalid authenticator public key format' });
    }
    
    if (typeof authenticatorDevice.counter !== 'number') {
      console.error('❌ counter is not a number:', typeof authenticatorDevice.counter, authenticatorDevice.counter);
      return res.status(500).json({ message: 'Invalid authenticator counter format' });
    }

    console.log('✅ Authenticator device validation passed:', {
      credentialIDIsBuffer: Buffer.isBuffer(authenticatorDevice.credentialID),
      credentialPublicKeyIsBuffer: Buffer.isBuffer(authenticatorDevice.credentialPublicKey),
      counter: authenticatorDevice.counter,
      counterType: typeof authenticatorDevice.counter
    });

    // ✅ CRITICAL DEBUG: Log everything right before the call
    console.log('🚨 FINAL PRE-VERIFICATION CHECK:');
    console.log('- cleanedBody exists:', !!cleanedBody);
    console.log('- expectedChallenge exists:', !!expectedChallenge);
    console.log('- ORIGIN exists:', !!ORIGIN);
    console.log('- rpID exists:', !!rpID);
    console.log('- authenticatorDevice exists:', !!authenticatorDevice);
    console.log('- authenticatorDevice type:', typeof authenticatorDevice);
    
    if (authenticatorDevice) {
      console.log('- authenticatorDevice.counter:', authenticatorDevice.counter);
      console.log('- authenticatorDevice has counter property:', authenticatorDevice.hasOwnProperty('counter'));
      console.log('- authenticatorDevice keys:', Object.keys(authenticatorDevice));
    } else {
      console.error('❌ CRITICAL: authenticatorDevice is falsy!');
      return res.status(500).json({ message: 'Authenticator device is undefined' });
    }
    
    // Create verification params object for additional debugging
    const verificationParams = {
      response: cleanedBody,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: rpID,
      authenticator: authenticatorDevice,
    };
    
    console.log('🔍 Verification params structure:');
    console.log('- response exists:', !!verificationParams.response);
    console.log('- expectedChallenge exists:', !!verificationParams.expectedChallenge);
    console.log('- expectedOrigin exists:', !!verificationParams.expectedOrigin);
    console.log('- expectedRPID exists:', !!verificationParams.expectedRPID);
    console.log('- authenticator exists:', !!verificationParams.authenticator);
    
    // Ensure ORIGIN is defined
    if (!ORIGIN) {
      console.error('❌ ORIGIN is undefined!');
      return res.status(500).json({ message: 'Server configuration error: ORIGIN not defined' });
    }

    const verification = await verifyAuthenticationResponse(verificationParams);

    console.log('Verification result:', {
      verified: verification.verified,
      hasAuthInfo: !!verification.authenticationInfo,
      authInfo: verification.authenticationInfo
    });

    if (verification.verified && verification.authenticationInfo) {
      const newCounter = verification.authenticationInfo.newCounter ?? 0;

      console.log('Updating counter from', counterValue, 'to', newCounter);

      await query(
        'UPDATE authenticators SET counter = $1 WHERE id = $2',
        [newCounter, auth.id]
      );

      // Clear challenge and rpID from session
      req.session.challenge = null;
      req.session.rpID = null;

      // Optional: attach user session (auto-login)
      req.session.userId = auth.user_id;
      await req.session.save();

      return res.json({ success: true });
    } else {
      console.log('Verification failed - not verified or missing auth info');
      return res.status(400).json({ 
        success: false, 
        reason: 'Not verified',
        details: {
          verified: verification.verified,
          hasAuthInfo: !!verification.authenticationInfo
        }
      });
    }
  } catch (err) {
    console.error('Authentication verification failed:', err.message);
    console.error('Full error:', err);
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
