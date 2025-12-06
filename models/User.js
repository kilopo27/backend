import { getDB } from '../db.js';
import bcrypt from 'bcryptjs';
import { ObjectId } from 'mongodb';
import crypto from 'crypto';

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

    // Generate verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const verificationCodeExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    const user = {
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password: hashedPassword,
      emailVerified: false,
      verificationCode: verificationCode,
      verificationCodeExpiry: verificationCodeExpiry,
      createdAt: new Date()
    };

    const result = await usersCollection.insertOne(user);
    return {
      id: result.insertedId.toString(),
      username: user.username,
      email: user.email,
      emailVerified: user.emailVerified,
      verificationCode: verificationCode, // Return code to send via email
      createdAt: user.createdAt
    };
  }

  static async verifyEmail(email, code) {
    const db = getDB();
    const usersCollection = db.collection('users');

    const user = await usersCollection.findOne({ email: email.toLowerCase() });

    if (!user) {
      throw new Error('User not found');
    }

    if (user.emailVerified) {
      throw new Error('Email already verified');
    }

    if (user.verificationCode !== code) {
      throw new Error('Invalid verification code');
    }

    if (new Date() > user.verificationCodeExpiry) {
      throw new Error('Verification code expired');
    }

    // Update user to verified
    await usersCollection.updateOne(
      { _id: user._id },
      {
        $set: {
          emailVerified: true,
          verificationCode: null,
          verificationCodeExpiry: null
        }
      }
    );

    return {
      id: user._id.toString(),
      username: user.username,
      email: user.email,
      emailVerified: true
    };
  }

  static async resendVerificationCode(email) {
    const db = getDB();
    const usersCollection = db.collection('users');

    const user = await usersCollection.findOne({ email: email.toLowerCase() });

    if (!user) {
      throw new Error('User not found');
    }

    if (user.emailVerified) {
      throw new Error('Email already verified');
    }

    // Generate new verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const verificationCodeExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await usersCollection.updateOne(
      { _id: user._id },
      {
        $set: {
          verificationCode: verificationCode,
          verificationCodeExpiry: verificationCodeExpiry
        }
      }
    );

    return verificationCode;
  }

  static async createPasswordResetToken(email) {
    const db = getDB();
    const usersCollection = db.collection('users');

    const user = await usersCollection.findOne({ email: email.toLowerCase() });

    if (!user) {
      // Don't reveal if user exists or not for security
      return null;
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await usersCollection.updateOne(
      { _id: user._id },
      {
        $set: {
          resetToken: resetToken,
          resetTokenExpiry: resetTokenExpiry
        }
      }
    );

    return resetToken;
  }

  static async resetPassword(token, newPassword) {
    const db = getDB();
    const usersCollection = db.collection('users');

    const user = await usersCollection.findOne({ resetToken: token });

    if (!user) {
      throw new Error('Invalid or expired reset token');
    }

    if (new Date() > user.resetTokenExpiry) {
      throw new Error('Reset token expired');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password and clear reset token
    await usersCollection.updateOne(
      { _id: user._id },
      {
        $set: {
          password: hashedPassword,
          resetToken: null,
          resetTokenExpiry: null
        }
      }
    );

    return {
      id: user._id.toString(),
      username: user.username,
      email: user.email
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

