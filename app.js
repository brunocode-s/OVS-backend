import express from 'express';
import cors from 'cors';
import authRoutes from './routes/authRoutes.js';
import electionRoutes from './routes/electionRoutes.js';
import voteRoutes from './routes/voteRoutes.js';
import adminRoutes from './routes/adminRoutes.js';

const app = express();

// CORS options (you can configure it as needed)
const corsOptions = {
  origin: 'http://localhost:5173', // Set your frontend URL here
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true, // Enable cookies if required
};

// Apply CORS and JSON parsing middleware
app.use(cors(corsOptions));  // Use the cors options
app.use(express.json());     // Body parser for JSON requests

// Use routes for different API endpoints
app.use('/api/auth', authRoutes);
app.use('/api/elections', electionRoutes);
app.use('/api/votes', voteRoutes);
app.use('/api/admin', adminRoutes);

export default app;
