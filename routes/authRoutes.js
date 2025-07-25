import { Router } from 'express';
import { register, login, forgotPassword, resetPassword, hasFingerprint
 } from '../controllers/authController.js'; // Use named imports
import { authenticateJWT } from '../middleware/authMiddleware.js';

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password/:token', resetPassword);        
// router.post('/start-fingerprint-login', startFingerprintLogin); // Start fingerprint login 
router.get('/has-fingerprint', authenticateJWT, hasFingerprint); // Check if user has fingerprint registered

export default router;
