import Fastify from 'fastify';
import cors from '@fastify/cors';
import jwt from '@fastify/jwt';
import { ObjectId } from 'mongodb';
import { connectDB } from './db.js';
import { User } from './models/User.js';
import { Message } from './models/Message.js';
import { Group } from './models/Group.js';
import { sendVerificationEmail, sendPasswordResetEmail } from './services/email.js';

const fastify = Fastify({
  logger: true
});

// Register CORS plugin
// Allow requests from Netlify frontend and localhost for development
const allowedOrigins = [
  'https://goymessage.netlify.app',
  'http://localhost:3000',
  'http://localhost:3001'
];

// Add CORS_ORIGIN from environment if set
if (process.env.CORS_ORIGIN) {
  allowedOrigins.push(process.env.CORS_ORIGIN);
}

await fastify.register(cors, {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin) || process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    
    // Log for debugging
    fastify.log.warn(`CORS blocked origin: ${origin}`);
    
    // In production, only allow specific origins
    callback(new Error('Not allowed by CORS'), false);
  },
  credentials: true
});

// Register JWT plugin
await fastify.register(jwt, {
  secret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production'
});

// Connect to MongoDB
await connectDB();

// Authentication middleware
const authenticate = async (request, reply) => {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.code(401).send({ error: 'Unauthorized' });
  }
};

// Health check route
fastify.get('/health', async (request, reply) => {
  return { status: 'ok', message: 'Server is running' };
});

// Register endpoint
fastify.post('/api/auth/register', async (request, reply) => {
  try {
    const { username, email, password } = request.body;

    // Validation
    if (!username || !email || !password) {
      return reply.code(400).send({ 
        error: 'Username, email, and password are required' 
      });
    }

    if (username.length < 3 || username.length > 20) {
      return reply.code(400).send({ 
        error: 'Username must be between 3 and 20 characters' 
      });
    }

    if (password.length < 6) {
      return reply.code(400).send({ 
        error: 'Password must be at least 6 characters' 
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return reply.code(400).send({ 
        error: 'Invalid email format' 
      });
    }

    // Create user (with verification code)
    const user = await User.create(username, email, password);

    // Send verification email
    try {
      await sendVerificationEmail(user.email, user.verificationCode);
    } catch (emailError) {
      fastify.log.error('Failed to send verification email:', emailError);
      // Don't fail registration if email fails, but log it
    }

    // Don't return token yet - user needs to verify email first
    return { 
      success: true,
      message: 'Registration successful. Please verify your email.',
      email: user.email,
      requiresVerification: true
    };
  } catch (error) {
    if (error.message === 'Username or email already exists') {
      return reply.code(409).send({ error: error.message });
    }
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Registration failed' });
  }
});

// Login endpoint
fastify.post('/api/auth/login', async (request, reply) => {
  try {
    const { username, password } = request.body;

    if (!username || !password) {
      return reply.code(400).send({ 
        error: 'Username and password are required' 
      });
    }

    // Find user
    const user = await User.findByUsername(username);
    if (!user) {
      return reply.code(401).send({ error: 'Invalid credentials' });
    }

    // Verify password
    const isValid = await User.verifyPassword(password, user.password);
    if (!isValid) {
      return reply.code(401).send({ error: 'Invalid credentials' });
    }

    // Check if email is verified
    if (!user.emailVerified) {
      return reply.code(403).send({ 
        error: 'Email not verified. Please verify your email before logging in.',
        requiresVerification: true,
        email: user.email
      });
    }

    // Generate JWT token
    const token = fastify.jwt.sign({ 
      userId: user._id.toString(), 
      username: user.username 
    });

    return { 
      success: true, 
      token,
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email
      }
    };
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Login failed' });
  }
});

// Get current user endpoint
fastify.get('/api/auth/me', { preHandler: authenticate }, async (request, reply) => {
  try {
    const userId = request.user.userId;
    const user = await User.findById(userId);
    
    if (!user) {
      return reply.code(404).send({ error: 'User not found' });
    }

    return {
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        emailVerified: user.emailVerified || false
      }
    };
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to get user' });
  }
});

// Verify email endpoint
fastify.post('/api/auth/verify-email', async (request, reply) => {
  try {
    const { email, code } = request.body;

    if (!email || !code) {
      return reply.code(400).send({ 
        error: 'Email and verification code are required' 
      });
    }

    const user = await User.verifyEmail(email, code);

    // Generate JWT token after verification
    const token = fastify.jwt.sign({ 
      userId: user.id, 
      username: user.username 
    });

    return { 
      success: true,
      message: 'Email verified successfully',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        emailVerified: true
      }
    };
  } catch (error) {
    if (error.message === 'User not found' || 
        error.message === 'Invalid verification code' ||
        error.message === 'Verification code expired' ||
        error.message === 'Email already verified') {
      return reply.code(400).send({ error: error.message });
    }
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Email verification failed' });
  }
});

// Resend verification code endpoint
fastify.post('/api/auth/resend-verification', async (request, reply) => {
  try {
    const { email } = request.body;

    if (!email) {
      return reply.code(400).send({ 
        error: 'Email is required' 
      });
    }

    const verificationCode = await User.resendVerificationCode(email);

    // Send verification email
    try {
      await sendVerificationEmail(email, verificationCode);
    } catch (emailError) {
      fastify.log.error('Failed to send verification email:', emailError);
      return reply.code(500).send({ error: 'Failed to send verification email' });
    }

    return { 
      success: true,
      message: 'Verification code sent to your email'
    };
  } catch (error) {
    if (error.message === 'User not found' || 
        error.message === 'Email already verified') {
      return reply.code(400).send({ error: error.message });
    }
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to resend verification code' });
  }
});

// Forgot password endpoint
fastify.post('/api/auth/forgot-password', async (request, reply) => {
  try {
    const { email } = request.body;

    if (!email) {
      return reply.code(400).send({ 
        error: 'Email is required' 
      });
    }

    const resetToken = await User.createPasswordResetToken(email);

    // Always return success (don't reveal if user exists)
    if (resetToken) {
      try {
        await sendPasswordResetEmail(email, resetToken);
      } catch (emailError) {
        fastify.log.error('Failed to send password reset email:', emailError);
        return reply.code(500).send({ error: 'Failed to send password reset email' });
      }
    }

    return { 
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent.'
    };
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to process password reset request' });
  }
});

// Reset password endpoint
fastify.post('/api/auth/reset-password', async (request, reply) => {
  try {
    const { token, newPassword } = request.body;

    if (!token || !newPassword) {
      return reply.code(400).send({ 
        error: 'Token and new password are required' 
      });
    }

    if (newPassword.length < 6) {
      return reply.code(400).send({ 
        error: 'Password must be at least 6 characters' 
      });
    }

    const user = await User.resetPassword(token, newPassword);

    return { 
      success: true,
      message: 'Password reset successfully',
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    };
  } catch (error) {
    if (error.message === 'Invalid or expired reset token' || 
        error.message === 'Reset token expired') {
      return reply.code(400).send({ error: error.message });
    }
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Password reset failed' });
  }
});

// Search users endpoint
fastify.get('/api/users/search', { preHandler: authenticate }, async (request, reply) => {
  try {
    const { q } = request.query;
    const userId = request.user.userId;

    if (!q || q.trim().length < 1) {
      return reply.code(400).send({ error: 'Search query is required' });
    }

    const users = await User.searchUsers(q.trim(), userId, 20);
    return { users };
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to search users' });
  }
});

// Get conversations endpoint
fastify.get('/api/conversations', { preHandler: authenticate }, async (request, reply) => {
  try {
    const userId = request.user.userId;
    const conversations = await Message.getConversations(userId);
    return { conversations };
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to load conversations' });
  }
});

// Get messages between two users
fastify.get('/api/messages/:userId', { preHandler: authenticate }, async (request, reply) => {
  try {
    const currentUserId = request.user.userId;
    const { userId: otherUserId } = request.params;

    if (currentUserId === otherUserId) {
      return reply.code(400).send({ error: 'Cannot message yourself' });
    }

    // Verify other user exists
    const otherUser = await User.findById(otherUserId);
    if (!otherUser) {
      return reply.code(404).send({ error: 'User not found' });
    }

    const messages = await Message.getConversation(currentUserId, otherUserId, 100);
    
    // Mark messages as read
    await Message.markAsRead(otherUserId, currentUserId);

    return { messages };
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to load messages' });
  }
});

// Post a new message
fastify.post('/api/messages', { preHandler: authenticate }, async (request, reply) => {
  try {
    const { receiverId, groupId, text } = request.body;
    const senderId = request.user.userId;
    const senderUsername = request.user.username;

    if (!text || !text.trim()) {
      return reply.code(400).send({ 
        error: 'Message text is required' 
      });
    }

    // Group message
    if (groupId) {
      const group = await Group.findById(groupId);
      if (!group) {
        return reply.code(404).send({ error: 'Group not found' });
      }

      // Check if user is a member
      const isMember = group.members.some(memberId => memberId.toString() === senderId);
      if (!isMember) {
        return reply.code(403).send({ error: 'You are not a member of this group' });
      }

      const newMessage = await Message.create(senderId, null, senderUsername, text, groupId);
      return { 
        success: true, 
        message: newMessage 
      };
    }

    // Private message
    if (!receiverId) {
      return reply.code(400).send({ 
        error: 'Receiver ID or Group ID is required' 
      });
    }

    if (senderId === receiverId) {
      return reply.code(400).send({ 
        error: 'Cannot send message to yourself' 
      });
    }

    // Verify receiver exists
    const receiver = await User.findById(receiverId);
    if (!receiver) {
      return reply.code(404).send({ error: 'Receiver not found' });
    }

    const newMessage = await Message.create(senderId, receiverId, senderUsername, text);

    return { 
      success: true, 
      message: newMessage 
    };
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to send message' });
  }
});

// Get user's groups
fastify.get('/api/groups', { preHandler: authenticate }, async (request, reply) => {
  try {
    const userId = request.user.userId;
    const groups = await Group.getUserGroups(userId);
    return { groups };
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to load groups' });
  }
});

// Create a new group
fastify.post('/api/groups', { preHandler: authenticate }, async (request, reply) => {
  try {
    const { name, memberIds } = request.body;
    const creatorId = request.user.userId;

    if (!name || !name.trim()) {
      return reply.code(400).send({ error: 'Group name is required' });
    }

    if (!memberIds || !Array.isArray(memberIds) || memberIds.length === 0) {
      return reply.code(400).send({ error: 'At least one member is required' });
    }

    // Verify all members exist
    for (const memberId of memberIds) {
      const member = await User.findById(memberId);
      if (!member) {
        return reply.code(404).send({ error: `User ${memberId} not found` });
      }
    }

    const group = await Group.create(name, creatorId, memberIds);
    return { success: true, group };
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to create group' });
  }
});

// Get group details
fastify.get('/api/groups/:groupId', { preHandler: authenticate }, async (request, reply) => {
  try {
    const { groupId } = request.params;
    const userId = request.user.userId;

    const group = await Group.findById(groupId);
    if (!group) {
      return reply.code(404).send({ error: 'Group not found' });
    }

    // Check if user is a member
    const userIdObj = new ObjectId(userId);
    const isMember = group.members.some(memberId => memberId.equals(userIdObj));
    if (!isMember) {
      return reply.code(403).send({ error: 'You are not a member of this group' });
    }

    const members = await Group.getGroupMembers(groupId);

    return {
      group: {
        id: group._id.toString(),
        name: group.name,
        creatorId: group.creatorId.toString(),
        members: members,
        createdAt: group.createdAt,
        updatedAt: group.updatedAt
      }
    };
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to get group' });
  }
});

// Update group name
fastify.put('/api/groups/:groupId/name', { preHandler: authenticate }, async (request, reply) => {
  try {
    const { groupId } = request.params;
    const { name } = request.body;
    const userId = request.user.userId;

    if (!name || !name.trim()) {
      return reply.code(400).send({ error: 'Group name is required' });
    }

    const group = await Group.findById(groupId);
    if (!group) {
      return reply.code(404).send({ error: 'Group not found' });
    }

    // Check if user is a member
    const userIdObj = new ObjectId(userId);
    const isMember = group.members.some(memberId => memberId.equals(userIdObj));
    if (!isMember) {
      return reply.code(403).send({ error: 'You are not a member of this group' });
    }

    const updated = await Group.updateName(groupId, name);
    if (updated) {
      return { success: true, message: 'Group name updated' };
    } else {
      return reply.code(500).send({ error: 'Failed to update group name' });
    }
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to update group name' });
  }
});

// Add member to group
fastify.post('/api/groups/:groupId/members', { preHandler: authenticate }, async (request, reply) => {
  try {
    const { groupId } = request.params;
    const { userId: newMemberId } = request.body;
    const userId = request.user.userId;

    if (!newMemberId) {
      return reply.code(400).send({ error: 'User ID is required' });
    }

    const group = await Group.findById(groupId);
    if (!group) {
      return reply.code(404).send({ error: 'Group not found' });
    }

    // Check if user is a member
    const userIdObj = new ObjectId(userId);
    const isMember = group.members.some(memberId => memberId.equals(userIdObj));
    if (!isMember) {
      return reply.code(403).send({ error: 'You are not a member of this group' });
    }

    // Verify new member exists
    const newMember = await User.findById(newMemberId);
    if (!newMember) {
      return reply.code(404).send({ error: 'User not found' });
    }

    try {
      const added = await Group.addMember(groupId, newMemberId);
      if (added) {
        return { success: true, message: 'Member added to group' };
      } else {
        return reply.code(500).send({ error: 'Failed to add member' });
      }
    } catch (error) {
      if (error.message === 'User is already a member') {
        return reply.code(409).send({ error: error.message });
      }
      throw error;
    }
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to add member' });
  }
});

// Leave group
fastify.post('/api/groups/:groupId/leave', { preHandler: authenticate }, async (request, reply) => {
  try {
    const { groupId } = request.params;
    const userId = request.user.userId;

    const result = await Group.leaveGroup(groupId, userId);
    
    if (result.deleted) {
      return { success: true, message: 'Group deleted (you were the creator)' };
    } else if (result.removed) {
      return { success: true, message: 'Left group successfully' };
    } else {
      return reply.code(500).send({ error: 'Failed to leave group' });
    }
  } catch (error) {
    if (error.message === 'Creator cannot leave the group') {
      return reply.code(400).send({ error: error.message });
    }
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to leave group' });
  }
});

// Get group messages
fastify.get('/api/groups/:groupId/messages', { preHandler: authenticate }, async (request, reply) => {
  try {
    const { groupId } = request.params;
    const userId = request.user.userId;

    const group = await Group.findById(groupId);
    if (!group) {
      return reply.code(404).send({ error: 'Group not found' });
    }

    // Check if user is a member
    const userIdObj = new ObjectId(userId);
    const isMember = group.members.some(memberId => memberId.equals(userIdObj));
    if (!isMember) {
      return reply.code(403).send({ error: 'You are not a member of this group' });
    }

    const messages = await Message.getGroupMessages(groupId, 100);
    return { messages };
  } catch (error) {
    fastify.log.error(error);
    return reply.code(500).send({ error: 'Failed to load group messages' });
  }
});

// Start server
const start = async () => {
  try {
    const port = process.env.PORT || 3001;
    const host = process.env.HOST || '0.0.0.0';
    
    await fastify.listen({ 
      port: parseInt(port), 
      host: host 
    });
    console.log(`🚀 Server listening on ${host}:${port}`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
