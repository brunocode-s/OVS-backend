import { Router } from 'express';
import { 
  createElection, 
  editElection, 
  cancelElection, 
  getElectionStats 
} from '../controllers/adminController.js'; // make sure path is correct
// import { authenticate } from '../middleware/authMiddleware.js';

const router = Router();

// Admin Dashboard test route (optional)
router.get('/', (req, res) => {
  res.send('Admin Dashboard');
});

// Actual route your frontend is trying to POST to
router.post('/create-election', authenticate, createElection);
router.put('/edit-election/:id', editElection);
router.delete('/cancel-election/:id', cancelElection);

router.get('/election-stats/:electionId', getElectionStats); // Get election statistics


export default router;
