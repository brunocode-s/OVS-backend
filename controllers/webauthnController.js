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
    // Critical debugging - check the response structure
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
      
      // Check if these are valid base64url strings
      console.log('- authenticatorData length:', body.response.authenticatorData?.length);
      console.log('- signature length:', body.response.signature?.length);
      console.log('- clientDataJSON length:', body.response.clientDataJSON?.length);
    }
    
    // Try to validate the response format before passing to library
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
    
    // Clean the body to remove extra fields that might confuse the library
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

    // Add additional logging before verification
    console.log('Auth object:', {
      id: auth.id,
      counter: auth.counter,
      public_key_type: typeof auth.public_key,
      public_key_preview: auth.public_key.substring(0, 50) + '...'
    });

    // Ensure all required properties are present and correctly typed
    const authenticatorDevice = {
      credentialID: Buffer.from(auth.credential_id), // confirm it's Buffer
      credentialPublicKey: Buffer.from(auth.public_key, 'base64'), // ✅ FIXED
      counter: auth.counter ?? 0, // must be a number
      transports: auth.transports || [] // optional
    };
    

    console.log('Authenticator device structure:', {
      credentialID: authenticatorDevice.credentialID,
      credentialIDType: typeof authenticatorDevice.credentialID,
      credentialIDIsBuffer: Buffer.isBuffer(authenticatorDevice.credentialID),
      credentialPublicKeyType: typeof authenticatorDevice.credentialPublicKey,
      credentialPublicKeyIsBuffer: Buffer.isBuffer(authenticatorDevice.credentialPublicKey),
      counter: authenticatorDevice.counter,
      counterType: typeof authenticatorDevice.counter,
      transports: authenticatorDevice.transports,
      transportsType: typeof authenticatorDevice.transports
    });

    const verification = await verifyAuthenticationResponse({
      response: cleanedBody, // Use cleaned body instead of original body
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: rpID,
      authenticator: authenticatorDevice,
    });

    console.log('Verification result:', {
      verified: verification.verified,
      hasAuthInfo: !!verification.authenticationInfo,
      authInfo: verification.authenticationInfo
    });

    if (verification.verified && verification.authenticationInfo) {
      const newCounter = verification.authenticationInfo.newCounter ?? 0;

      console.log('Updating counter from', auth.counter, 'to', newCounter);

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
