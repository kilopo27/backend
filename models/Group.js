import { getDB } from '../db.js';
import { ObjectId } from 'mongodb';

export class Group {
  static async create(name, creatorId, memberIds) {
    const db = getDB();
    const groupsCollection = db.collection('groups');

    // Ensure creator is in members
    const allMemberIds = [...new Set([creatorId, ...memberIds])].map(id => new ObjectId(id));

    const group = {
      name: name.trim(),
      creatorId: new ObjectId(creatorId),
      members: allMemberIds,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await groupsCollection.insertOne(group);
    return {
      id: result.insertedId.toString(),
      name: group.name,
      creatorId: group.creatorId.toString(),
      members: group.members.map(id => id.toString()),
      createdAt: group.createdAt,
      updatedAt: group.updatedAt
    };
  }

  static async findById(id) {
    const db = getDB();
    const groupsCollection = db.collection('groups');
    return await groupsCollection.findOne({ _id: new ObjectId(id) });
  }

  static async getUserGroups(userId) {
    const db = getDB();
    const groupsCollection = db.collection('groups');
    
    const userIdObj = new ObjectId(userId);
    
    const groups = await groupsCollection
      .find({
        members: userIdObj
      })
      .sort({ updatedAt: -1 })
      .toArray();

    return groups.map(group => ({
      id: group._id.toString(),
      name: group.name,
      creatorId: group.creatorId.toString(),
      members: group.members.map(id => id.toString()),
      createdAt: group.createdAt,
      updatedAt: group.updatedAt
    }));
  }

  static async updateName(groupId, newName) {
    const db = getDB();
    const groupsCollection = db.collection('groups');
    
    const result = await groupsCollection.updateOne(
      { _id: new ObjectId(groupId) },
      {
        $set: {
          name: newName.trim(),
          updatedAt: new Date()
        }
      }
    );

    return result.modifiedCount > 0;
  }

  static async addMember(groupId, userId) {
    const db = getDB();
    const groupsCollection = db.collection('groups');
    
    const group = await this.findById(groupId);
    if (!group) {
      throw new Error('Group not found');
    }

    const userIdObj = new ObjectId(userId);
    
    // Check if user is already a member
    if (group.members.some(memberId => memberId.equals(userIdObj))) {
      throw new Error('User is already a member');
    }

    const result = await groupsCollection.updateOne(
      { _id: new ObjectId(groupId) },
      {
        $addToSet: { members: userIdObj },
        $set: { updatedAt: new Date() }
      }
    );

    return result.modifiedCount > 0;
  }

  static async removeMember(groupId, userId) {
    const db = getDB();
    const groupsCollection = db.collection('groups');
    
    const group = await this.findById(groupId);
    if (!group) {
      throw new Error('Group not found');
    }

    // Don't allow creator to leave (or handle it differently)
    if (group.creatorId.equals(new ObjectId(userId))) {
      throw new Error('Creator cannot leave the group');
    }

    const result = await groupsCollection.updateOne(
      { _id: new ObjectId(groupId) },
      {
        $pull: { members: new ObjectId(userId) },
        $set: { updatedAt: new Date() }
      }
    );

    return result.modifiedCount > 0;
  }

  static async leaveGroup(groupId, userId) {
    const db = getDB();
    const groupsCollection = db.collection('groups');
    
    const group = await this.findById(groupId);
    if (!group) {
      throw new Error('Group not found');
    }

    // If user is creator, delete the group
    if (group.creatorId.equals(new ObjectId(userId))) {
      await groupsCollection.deleteOne({ _id: new ObjectId(groupId) });
      return { deleted: true };
    }

    // Otherwise, just remove the member
    const result = await groupsCollection.updateOne(
      { _id: new ObjectId(groupId) },
      {
        $pull: { members: new ObjectId(userId) },
        $set: { updatedAt: new Date() }
      }
    );

    return { deleted: false, removed: result.modifiedCount > 0 };
  }

  static async getGroupMembers(groupId) {
    const db = getDB();
    const groupsCollection = db.collection('groups');
    const usersCollection = db.collection('users');
    
    const group = await groupsCollection.findOne({ _id: new ObjectId(groupId) });
    if (!group) {
      return [];
    }

    const members = await usersCollection
      .find({ _id: { $in: group.members } })
      .toArray();

    return members.map(user => ({
      id: user._id.toString(),
      username: user.username,
      email: user.email
    }));
  }
}


