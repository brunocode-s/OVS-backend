import dotenv from 'dotenv';
dotenv.config(); // Load environment variables from .env file

import pkg from 'pg';
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DB_URL,
});

export { pool };

export function query(text, params) {
  return pool.query(text, params);
}
