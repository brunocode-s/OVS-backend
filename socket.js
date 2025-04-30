import { Server } from 'socket.io';  // Use import instead of require

let io;  // Declare the io variable globally to be shared across modules

// Function to set up the Socket.io server
const setupSocket = (server) => {
  const socketIO = new Server(server, {
    cors: {
      origin: 'ovs-frontend-drab.vercel.app',  // Frontend URL
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      credentials: true,  // Allow credentials if needed
    },
  });

  io = socketIO;  // Assign the initialized socket server to `io`

  // When a new client connects
  socketIO.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    // When the client disconnects
    socket.on('disconnect', () => {
      console.log('Client disconnected:', socket.id);
    });

    // Example of listening to a custom event
    socket.on('vote-cast', (data) => {
      console.log('Vote cast event:', data);
      // Broadcast the event to other clients
      io.emit('vote-update', data);  // Send to all clients
    });
  });
};

// Function to get the io instance
const getIO = () => {
  if (!io) throw new Error('Socket.io not initialized');
  return io;
};

export { setupSocket, getIO };
