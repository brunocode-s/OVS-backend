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
router.post('/generate-authentication-options', authenticate, getAuthenticationOptions);
router.post('/verify-authentication', authenticate, verifyAuthentication);
router.get('/check-registration', authenticate, checkFingerprintRegistration);

export default router;
