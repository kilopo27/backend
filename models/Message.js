import { getDB } from '../db.js';
import { ObjectId } from 'mongodb';

export class Message {
  static async create(senderId, receiverId, senderUsername, text, groupId = null) {
    const db = getDB();
    const messagesCollection = db.collection('messages');

    const message = {
      senderId: new ObjectId(senderId),
      senderUsername: senderUsername,
      text: text.trim(),
      timestamp: new Date(),
      read: false
    };

    // If groupId is provided, it's a group message
    if (groupId) {
      message.groupId = new ObjectId(groupId);
      message.type = 'group';
    } else {
      // Otherwise it's a private message
      message.receiverId = new ObjectId(receiverId);
      message.type = 'private';
    }

    console.log('Creating message:', {
      senderId: message.senderId.toString(),
      receiverId: message.receiverId?.toString(),
      groupId: message.groupId?.toString(),
      type: message.type,
      senderUsername,
      text: message.text
    });

    const result = await messagesCollection.insertOne(message);
    console.log('Message created with ID:', result.insertedId.toString());
    
    return {
      id: result.insertedId.toString(),
      senderId: message.senderId.toString(),
      receiverId: message.receiverId?.toString(),
      groupId: message.groupId?.toString(),
      type: message.type,
      senderUsername: message.senderUsername,
      text: message.text,
      timestamp: message.timestamp,
      read: message.read
    };
  }

  // Get group messages
  static async getGroupMessages(groupId, limit = 100) {
    const db = getDB();
    const messagesCollection = db.collection('messages');
    
    const groupIdObj = new ObjectId(groupId);
    
    const messages = await messagesCollection
      .find({ groupId: groupIdObj })
      .sort({ timestamp: 1 })
      .limit(limit)
      .toArray();

    return messages.map(msg => ({
      id: msg._id.toString(),
      senderId: msg.senderId.toString(),
      groupId: msg.groupId.toString(),
      senderUsername: msg.senderUsername,
      text: msg.text,
      timestamp: msg.timestamp,
      read: msg.read
    }));
  }

  // Get messages between two users (only private messages)
  static async getConversation(userId1, userId2, limit = 100) {
    const db = getDB();
    const messagesCollection = db.collection('messages');
    
    const userId1Obj = new ObjectId(userId1);
    const userId2Obj = new ObjectId(userId2);
    
    const query = {
      type: 'private',
      $or: [
        { senderId: userId1Obj, receiverId: userId2Obj },
        { senderId: userId2Obj, receiverId: userId1Obj }
      ]
    };
    
    console.log('Getting conversation between:', userId1, 'and', userId2);
    console.log('Query:', JSON.stringify(query, null, 2));
    
    const messages = await messagesCollection
      .find(query)
      .sort({ timestamp: 1 })
      .limit(limit)
      .toArray();

    console.log('Found messages:', messages.length);

    return messages.map(msg => ({
      id: msg._id.toString(),
      senderId: msg.senderId.toString(),
      receiverId: msg.receiverId.toString(),
      senderUsername: msg.senderUsername,
      text: msg.text,
      timestamp: msg.timestamp,
      read: msg.read
    }));
  }

  // Get all conversations for a user (list of users they've messaged with)
  static async getConversations(userId) {
    const db = getDB();
    const messagesCollection = db.collection('messages');
    const usersCollection = db.collection('users');
    
    const userIdObj = new ObjectId(userId);
    
    // Get all unique user IDs that this user has conversations with (only private messages)
    const sentMessages = await messagesCollection.distinct('receiverId', {
      senderId: userIdObj,
      type: 'private'
    });
    
    const receivedMessages = await messagesCollection.distinct('senderId', {
      receiverId: userIdObj,
      type: 'private'
    });
    
    // Convert ObjectIds to strings and combine to get unique user IDs
    const sentUserIds = sentMessages.map(id => id.toString());
    const receivedUserIds = receivedMessages.map(id => id.toString());
    const allUserIds = [...new Set([...sentUserIds, ...receivedUserIds])];
    
    // Get last message for each conversation
    const conversations = await Promise.all(
      allUserIds.map(async (otherUserIdStr) => {
        const otherUserIdObj = new ObjectId(otherUserIdStr);
        
        const lastMessage = await messagesCollection
          .findOne({
            type: 'private',
            $or: [
              { senderId: userIdObj, receiverId: otherUserIdObj },
              { senderId: otherUserIdObj, receiverId: userIdObj }
            ]
          }, {
            sort: { timestamp: -1 }
          });
        
        if (!lastMessage) return null;
        
        // Get the other user's info
        const otherUser = await usersCollection.findOne({ _id: otherUserIdObj });
        if (!otherUser) return null;
        
        // Count unread messages
        const unreadCount = await messagesCollection.countDocuments({
          senderId: otherUserIdObj,
          receiverId: userIdObj,
          read: false
        });
        
        return {
          userId: otherUser._id.toString(),
          username: otherUser.username,
          lastMessage: {
            text: lastMessage.text,
            timestamp: lastMessage.timestamp,
            senderId: lastMessage.senderId.toString()
          },
          unreadCount
        };
      })
    );
    
    // Filter out nulls and sort by last message timestamp
    return conversations
      .filter(conv => conv !== null)
      .sort((a, b) => new Date(b.lastMessage.timestamp) - new Date(a.lastMessage.timestamp));
  }

  // Mark messages as read
  static async markAsRead(senderId, receiverId) {
    const db = getDB();
    const messagesCollection = db.collection('messages');
    
    await messagesCollection.updateMany(
      {
        senderId: new ObjectId(senderId),
        receiverId: new ObjectId(receiverId),
        read: false
      },
      {
        $set: { read: true }
      }
    );
  }
}
