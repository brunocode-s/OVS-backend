import { query } from '../models/db.js';
import { getIO } from '../socket.js';

const castVote = async (req, res) => {
  const { candidateId } = req.body;
  const { electionId } = req.params;
  const userId = req.user.id;
  console.log('User ID', req.user);

  try {
    // 1. Check if election is active
    const electionResult = await query(
      'SELECT * FROM elections WHERE id = $1 AND NOW() BETWEEN start_date AND end_date',
      [electionId]
    );

    if (electionResult.rows.length === 0) {
      return res.status(404).json({ message: 'Election not found or has ended' });
    }

    // 2. Check candidate in election
    const candidateResult = await query(
      'SELECT * FROM candidates WHERE id = $1 AND election_id = $2',
      [candidateId, electionId]
    );

    if (candidateResult.rows.length === 0) {
      return res.status(404).json({ message: 'Candidate not found in this election' });
    }

    // 3. Prevent double voting
    const voteCheckResult = await query(
      'SELECT * FROM votes WHERE election_id = $1 AND user_id = $2',
      [electionId, userId]
    );

    if (voteCheckResult.rows.length > 0) {
      return res.status(400).json({ message: 'You have already voted in this election' });
    }
    const testVotes = await query('SELECT * FROM votes');
    console.log('Votes in DB:', testVotes.rows);


    // 4. Record the vote
    await query(
      'INSERT INTO votes (election_id, candidate_id, user_id) VALUES ($1, $2, $3)',
      [electionId, candidateId, userId]
    );

    // 5. Update candidate's vote count
    await query(
      'UPDATE candidates SET votes = votes + 1 WHERE id = $1',
      [candidateId]
    );

    // 6. Emit real-time update
    const io = getIO();
    io.emit(`vote-update-${electionId}`, { electionId });

    // 7. Success
    res.status(200).json({ message: 'Vote cast successfully' });

  } catch (err) {
    console.error('Error casting vote:', err);
    res.status(500).json({ error: 'Something went wrong' });
  }
};

const checkVoteStatus = async (req, res) => {
  const { electionId } = req.params;
  const userId = req.user.id;

  try {
    const result = await query(
      'SELECT * FROM votes WHERE election_id = $1 AND user_id = $2',
      [electionId, userId]
    );

    res.status(200).json({ hasVoted: result.rows.length > 0 });
  } catch (err) {
    console.error('Error checking vote status:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export { castVote, checkVoteStatus };
