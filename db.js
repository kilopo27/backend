import { MongoClient } from 'mongodb';

// MongoDB connection string from environment variable
// For Railway: Set MONGODB_URI in Railway environment variables
// For local: Create .env file with MONGODB_URI=your-connection-string
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  throw new Error('MONGODB_URI environment variable is required. Please set it in Railway or .env file.');
}

const DB_NAME = process.env.DB_NAME || 'messaging_app';

let client = null;
let db = null;

export async function connectDB() {
  if (db) {
    return db;
  }

  try {
    client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db(DB_NAME);
    console.log('✅ Connected to MongoDB');
    return db;
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    throw error;
  }
}

export function getDB() {
  if (!db) {
    throw new Error('Database not connected. Call connectDB() first.');
  }
  return db;
}

export async function closeDB() {
  if (client) {
    await client.close();
    db = null;
    client = null;
    console.log('MongoDB connection closed');
  }
}

