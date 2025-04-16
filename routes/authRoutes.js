import { Router } from 'express';
import authController from '../controllers/authController.js'; // Import default export

const router = Router();

router.post('/register', authController.register);  // Use authController for methods
router.post('/login', authController.login);        // Corrected typo
// router.post('/logout', authController.logout);      // Uncomment if you implement logout

export default router;
