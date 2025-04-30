import express from 'express';
import http from 'http';
import cors from 'cors';
import dotenv from 'dotenv';
import session from 'express-session';
import authRoutes from './routes/authRoutes.js';
import electionRoutes from './routes/electionRoutes.js';
import adminRoutes from './routes/adminRoutes.js';
import voteRoutes from './routes/voteRoutes.js';
import { getElections, getElectionById } from './controllers/electionController.js';
import webauthnRoutes from './routes/webauthnRoutes.js';
import { setupSocket } from './socket.js';  // Import the socket setup

dotenv.config();  // Load environment variables

const app = express();
const server = http.createServer(app);

// ====== SESSION SETUP (put first) ======
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // true in production with HTTPS
  })
);

// ====== CORS SETUP ======
const corsOptions = {
  origin: 'http://localhost:5173', // Your frontend origin
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true, // This must match session settings
};
app.use(cors(corsOptions));

// ====== Body parser ======
app.use(express.json());

// ====== Routes ======
app.use('/api/auth', authRoutes);
app.use('/api/elections', electionRoutes);
app.get('/api/elections', getElections);
app.get('/api/elections/:id', getElectionById);
app.use('/api/admin', adminRoutes);
app.use('/api/vote', voteRoutes);
app.use('/api/webauthn', webauthnRoutes);

// ====== Socket.io Setup ======
setupSocket(server);

// ====== Start Server ======
const PORT = process.env.PORT || 5001;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
});
