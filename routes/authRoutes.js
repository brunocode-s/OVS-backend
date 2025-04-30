import { Router } from 'express';
import { register, login, hasFingerprint, startFingerprintRegister, verifyFingerprintRegister,
    startFingerprintLogin
 } from '../controllers/authController.js'; // Use named imports
import { authenticateJWT } from '../middleware/authMiddleware.js';

const router = Router();

router.post('/register', register);
router.post('/login', login);        
router.post('/start-fingerprint-register', authenticateJWT, startFingerprintRegister); // Start fingerprint registration
router.post('/start-fingerprint-login', startFingerprintLogin); // Start fingerprint login 
router.get('/has-fingerprint', authenticateJWT, hasFingerprint); // Check if user has fingerprint registered

export default router;
