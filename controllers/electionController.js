import pkg from 'pg';
const { Pool } = pkg;
import { query } from '../models/db.js';

const pool = new Pool({
  connectionString: process.env.DB_URL,
});

// Create a new election (Admin only)
const createElection = async (req, res) => {
  const { title, candidates, start_time, end_time, description } = req.body;

  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied' });
  }

  if (!title || !candidates || !Array.isArray(candidates) || candidates.length < 2) {
    return res.status(400).json({ message: 'Title and at least 2 candidates are required' });
  }

  try {
    const result = await query(
      `INSERT INTO elections (title, description, start_time, end_time) 
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [title, description || '', start_time, end_time]
    );

    const electionId = result.rows[0].id;

    for (const name of candidates) {
      await query(
        'INSERT INTO candidates (name, election_id) VALUES ($1, $2)',
        [name, electionId]
      );
    }

    res.status(201).json({ message: 'Election created', election: result.rows[0] });
  } catch (err) {
    console.error('Error creating election:', err);
    res.status(500).json({ error: err.message });
  }
};

// Get all elections (Public)
const getElections = async (req, res) => {
  try {
    const result = await query('SELECT * FROM elections ORDER BY created_at DESC');
    const elections = result.rows;

    for (const election of elections) {
      const candidateResult = await query(
        'SELECT id, name, votes FROM candidates WHERE election_id = $1',
        [election.id]
      );
      election.candidates = candidateResult.rows;
    }

    res.status(200).json(elections);
  } catch (err) {
    console.error('Error fetching elections:', err);
    res.status(500).json({ error: err.message });
  }
};

// Get election by ID (Public)
const getElectionById = async (req, res) => {
  const { id } = req.params;

  try {
    const electionResult = await query('SELECT * FROM elections WHERE id = $1', [id]);

    if (electionResult.rows.length === 0) {
      return res.status(404).json({ message: 'Election not found' });
    }

    const election = electionResult.rows[0];

    // 🛠️ Get candidates with vote counts using LEFT JOIN
    const candidateResult = await query(
      `
      SELECT 
        c.id, 
        c.name, 
        COUNT(v.id) AS votes
      FROM candidates c
      LEFT JOIN votes v ON c.id = v.candidate_id
      WHERE c.election_id = $1
      GROUP BY c.id, c.name
      `,
      [id]
    );

    // Convert vote counts from string to number (PostgreSQL returns COUNT as string)
    election.candidates = candidateResult.rows.map(c => ({
      ...c,
      votes: parseInt(c.votes, 10)
    }));

    res.status(200).json(election);
  } catch (err) {
    console.error('Error fetching election by ID:', err);
    res.status(500).json({ error: 'Server error' });
  }
};


const castVote = async (req, res) => {
  const electionId = req.params.id;
  const { candidateId } = req.body;
  const voterId = req.user?.id; // assumes user is authenticated

  try {
    // Check if election exists and is active
    const electionRes = await query(
      'SELECT * FROM elections WHERE id = $1',
      [electionId]
    );

    if (electionRes.rows.length === 0) {
      return res.status(404).json({ message: 'Election not found' });
    }

    const election = electionRes.rows[0];
    const now = new Date();
    if (now < new Date(election.start_time) || now > new Date(election.end_time)) {
      return res.status(400).json({ message: 'Election is not active' });
    }

    // Prevent double voting
    const voteCheck = await query(
      'SELECT * FROM votes WHERE election_id = $1 AND voter_id = $2',
      [electionId, voterId]
    );

    if (voteCheck.rows.length > 0) {
      return res.status(400).json({ message: 'You have already voted in this election' });
    }

    // Cast vote
    await query(
      'INSERT INTO votes (election_id, candidate_id, voter_id) VALUES ($1, $2, $3)',
      [electionId, candidateId, voterId]
    );

    // Optionally increment candidate's vote count
    await query(
      'UPDATE candidates SET votes = votes + 1 WHERE id = $1',
      [candidateId]
    );

    res.status(201).json({ message: 'Vote cast successfully' });
  } catch (err) {
    console.error('Error casting vote:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

export { createElection, getElections, getElectionById, castVote };
