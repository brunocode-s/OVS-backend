import express from 'express';
import {
  getRegistrationOptions,
  verifyRegistration,
  getAuthenticationOptions,
  verifyAuthentication,
  checkFingerprintRegistration
} from '../controllers/webauthnController.js';
import { authenticate } from '../middleware/authMiddleware.js';

const router = express.Router();

router.post('/generate-registration-options', authenticate, getRegistrationOptions);
router.post('/verify-registration', authenticate, verifyRegistration);
router.get('/check-registration', authenticate, checkFingerprintRegistration);

router.post('/generate-authentication-options', getAuthenticationOptions);
router.post('/verify-authentication', verifyAuthentication);

export default router;
