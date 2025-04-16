import express from 'express';
import http from 'http';
import cors from 'cors';
import dotenv from 'dotenv';
import authRoutes from './routes/authRoutes.js';
import electionRoutes from './routes/electionRoutes.js';
import adminRoutes from './routes/adminRoutes.js';
import voteRoutes from './routes/voteRoutes.js';
import { getElections, getElectionById } from './controllers/electionController.js';
import { setupSocket } from './socket.js';  // Import the socket setup

dotenv.config();  // Load environment variables

const app = express();
const server = http.createServer(app);

// Define CORS options
const corsOptions = {
  origin: 'http://localhost:5173',  // Replace with your frontend's origin
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  
  credentials: true,  // Enable if you need to handle cookies or authentication
};

// Apply CORS middleware before your routes
app.use(cors(corsOptions));

// Middleware for JSON parsing
app.use(express.json());

// Use your routes
app.use('/api/auth', authRoutes);
app.use('/api/elections', electionRoutes);
app.get('/api/elections', getElections);  // All users can view elections
app.get('/api/elections/:id', getElectionById);  // Get a specific election by ID 
app.use('/api/admin', adminRoutes);  // Admin routes
app.use('/api/vote', voteRoutes);  // Voting routes

// Call `setupSocket` to initialize Socket.io
setupSocket(server);

// Define the port and start the server
const PORT = process.env.PORT || 5001;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
});
