import { Router } from 'express';
import { authenticate } from '../middleware/authMiddleware.js';
import { castVote, checkVoteStatus } from '../controllers/voteController.js';

const router = Router();

router.post('/elections/:electionId', authenticate, castVote);
router.get('/check/:electionId', authenticate, checkVoteStatus);
export default router;
