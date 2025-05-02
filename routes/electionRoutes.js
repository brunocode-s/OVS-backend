import { Router } from 'express';
const router = Router();
import { authenticate } from '../middleware/authMiddleware.js'; 
import { createElection, getElections, getElectionById } from '../controllers/electionController.js';
import { castVote } from '../controllers/voteController.js';

router.post('/', authenticate, createElection);  // Admin creates an election
router.get('/', authenticate, getElections);                   // All users can view elections
router.get('/:id', getElectionById);             // Get a specific election by ID
router.post('/:electionId/vote', authenticate, castVote); // User casts a vote

export default router;  // Ensure default export here
