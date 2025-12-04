import { getDB } from '../db.js';
import bcrypt from 'bcryptjs';
import { ObjectId } from 'mongodb';

export class User {
  static async create(username, email, password) {
    const db = getDB();
    const usersCollection = db.collection('users');

    // Check if user already exists
    const existingUser = await usersCollection.findOne({
      $or: [
        { username: username.toLowerCase() },
        { email: email.toLowerCase() }
      ]
    });

    if (existingUser) {
      throw new Error('Username or email already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password: hashedPassword,
      createdAt: new Date()
    };

    const result = await usersCollection.insertOne(user);
    return {
      id: result.insertedId.toString(),
      username: user.username,
      email: user.email,
      createdAt: user.createdAt
    };
  }

  static async findByUsername(username) {
    const db = getDB();
    const usersCollection = db.collection('users');
    return await usersCollection.findOne({ username: username.toLowerCase() });
  }

  static async findByEmail(email) {
    const db = getDB();
    const usersCollection = db.collection('users');
    return await usersCollection.findOne({ email: email.toLowerCase() });
  }

  static async findById(id) {
    const db = getDB();
    const usersCollection = db.collection('users');
    return await usersCollection.findOne({ _id: new ObjectId(id) });
  }

  static async verifyPassword(plainPassword, hashedPassword) {
    return await bcrypt.compare(plainPassword, hashedPassword);
  }

  static async searchUsers(query, excludeUserId, limit = 20) {
    const db = getDB();
    const usersCollection = db.collection('users');
    
    const excludeId = excludeUserId ? new ObjectId(excludeUserId) : null;
    
    const searchQuery = {
      username: { $regex: query, $options: 'i' }
    };
    
    if (excludeId) {
      searchQuery._id = { $ne: excludeId };
    }
    
    const users = await usersCollection
      .find(searchQuery)
      .limit(limit)
      .toArray();
    
    return users.map(user => ({
      id: user._id.toString(),
      username: user.username,
      email: user.email
    }));
  }
}

