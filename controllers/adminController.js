import { query } from '../models/db.js';

// Create election (Admin only)
export const createElection = async (req, res) => {
  console.log('Creating election with body:', req.body);
  try {
    const { title, description, candidates, start_date, end_date } = req.body;

    // Validate input
    if (!title || !description || !Array.isArray(candidates) || candidates.length < 2 || !start_date || !end_date) {
      return res.status(400).json({ error: 'Missing or invalid fields' });
    }

    // Step 1: Insert the election
    const electionResult = await query(
      `INSERT INTO elections (title, description, start_date, end_date, admin_id, created_by)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [title, description, start_date, end_date, req.user.id, req.user.id]
    );

    const election = electionResult.rows[0];
    const electionId = election.id;

    // Step 2: Insert candidates
    for (let name of candidates) {
      await query(
        `INSERT INTO candidates (name, election_id)
         VALUES ($1, $2)`,
        [name, electionId]
      );
    }

    return res.status(201).json({
      message: 'Election created successfully',
      election,
    });
  } catch (error) {
    console.error('Error creating election:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// Edit election (Admin only)
export const editElection = async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, start_date, end_date, candidates } = req.body;

    // Optional: validate admin role if you have req.user.role
    // if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });

    // Check required fields
    if (!title || !description || !start_date || !end_date || !Array.isArray(candidates) || candidates.length < 2) {
      return res.status(400).json({ error: 'Missing or invalid fields' });
    }

    // Step 1: Update election details
    const updateResult = await query(
      `UPDATE elections 
       SET title = $1, description = $2, start_date = $3, end_date = $4 
       WHERE id = $5 
       RETURNING *`,
      [title, description, start_date, end_date, id]
    );

    const updatedElection = updateResult.rows[0];
    if (!updatedElection) {
      return res.status(404).json({ error: 'Election not found' });
    }

    // Step 2: Delete existing candidates
    await query(`DELETE FROM candidates WHERE election_id = $1`, [id]);

    // Step 3: Re-insert updated candidates
    for (let name of candidates) {
      await query(
        `INSERT INTO candidates (name, election_id) VALUES ($1, $2)`,
        [name, id]
      );
    }

    // Optional: fetch the updated list of candidates
    const candidatesResult = await query(`SELECT name FROM candidates WHERE election_id = $1`, [id]);
    const updatedCandidates = candidatesResult.rows.map((row) => row.name);

    // Send back the updated election data
    return res.status(200).json({
      ...updatedElection,
      candidates: updatedCandidates,
    });

  } catch (error) {
    console.error('Error editing election:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};


export const cancelElection = async (req, res) => {
  const { id } = req.params;

  try {
    
    const result = await query('DELETE FROM elections WHERE id = $1 RETURNING *', [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Election not found' });
    }

    res.status(200).json({ message: 'Election canceled successfully' });
  } catch (err) {
    console.error('Error canceling election:', err);
    res.status(500).json({ error: err.message });
  }
}

export const getElectionStats = async (req, res) => {
  const { electionId } = req.params;

  try {
    const result = await query(
      `SELECT candidates.id, candidates.name, COUNT(votes.id) AS votes
       FROM candidates
       LEFT JOIN votes ON candidates.id = votes.candidate_id
       WHERE candidates.election_id = $1
       GROUP BY candidates.id, candidates.name`,
      [electionId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching election stats:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};
