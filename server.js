import express from 'express';
import http from 'http';
import cors from 'cors';
import dotenv from 'dotenv';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple'; // PostgreSQL session store
import authRoutes from './routes/authRoutes.js';
import electionRoutes from './routes/electionRoutes.js';
import adminRoutes from './routes/adminRoutes.js';
import voteRoutes from './routes/voteRoutes.js';
import { getElections, getElectionById } from './controllers/electionController.js';
import webauthnRoutes from './routes/webauthnRoutes.js';
import { setupSocket } from './socket.js';  // Import the socket setup
import { query } from './db.js'; // Import the query function from db.js

dotenv.config();  // Load environment variables

const app = express();
const server = http.createServer(app);

// ====== SESSION SETUP (using PostgreSQL for sessions) ======
const PgSession = connectPgSimple(session);

// Use the pool from db.js for session store
app.use(
  session({
    store: new PgSession({
      pool: query, // Use the query function from db.js to access the PostgreSQL pool
      tableName: 'session', // Optional: change table name for sessions
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,  // Ensure only initialized sessions are saved
    cookie: { secure: process.env.NODE_ENV === 'production' }, // secure cookies in production
  })
);

// ====== CORS SETUP ======
const corsOptions = {
  origin: 'https://ovs-frontend-drab.vercel.app', // Your frontend origin
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
