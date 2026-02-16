const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// UPDATED CORS for production
const io = socketIo(server, {
  cors: {
    origin: [
      "http://localhost:3000",
      process.env.FRONTEND_URL,
      /\.vercel\.app$/  // Allow all Vercel preview deployments
    ],
    methods: ["GET", "POST"],
    credentials: true
  }
});

app.use(cors({
  origin: [
    "http://localhost:3000",
    process.env.FRONTEND_URL,
    /\.vercel\.app$/  // Allow all Vercel preview deployments
  ],
  credentials: true
}));

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true
}));
app.use(express.json());

// Health check endpoint for deployment
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/discord-clone')
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log(err));

// User Schema
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  avatar: { type: String, default: '' },
  status: { type: String, default: 'online' },
  customStatus: { type: String, default: '' },
  lastSeen: { type: Date, default: Date.now },
  blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  subscription: {
    tier: { type: String, default: 'free', enum: ['free', 'pro', 'premium'] },
    expiresAt: { type: Date },
    features: {
      maxServers: { type: Number, default: 10 },
      maxChannelsPerServer: { type: Number, default: 20 },
      customEmojis: { type: Boolean, default: false },
      screenShare: { type: Boolean, default: false },
      higherQualityVoice: { type: Boolean, default: false }
    }
  },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// Server Schema with Categories
const ServerSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: '' },
  icon: { type: String, default: '' },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  members: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    role: { type: String, default: 'member', enum: ['owner', 'admin', 'moderator', 'member'] },
    joinedAt: { type: Date, default: Date.now }
  }],
  categories: [{
    name: { type: String, required: true },
    position: { type: Number, default: 0 },
    channels: [{
      name: String,
      type: { type: String, default: 'text', enum: ['text', 'voice'] },
      position: { type: Number, default: 0 },
      permissions: {
        viewChannel: [{ type: String }], // role names
        sendMessages: [{ type: String }],
        manageChannel: [{ type: String }]
      },
      createdAt: { type: Date, default: Date.now }
    }]
  }],
  roles: [{
    name: { type: String, required: true },
    color: { type: String, default: '#99AAB5' },
    permissions: {
      administrator: { type: Boolean, default: false },
      manageServer: { type: Boolean, default: false },
      manageChannels: { type: Boolean, default: false },
      manageRoles: { type: Boolean, default: false },
      kickMembers: { type: Boolean, default: false },
      banMembers: { type: Boolean, default: false },
      manageMessages: { type: Boolean, default: false }
    },
    position: { type: Number, default: 0 }
  }],
  createdAt: { type: Date, default: Date.now }
});

const Server = mongoose.model('Server', ServerSchema);

// Message Schema with Pins and Threads
const MessageSchema = new mongoose.Schema({
  content: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  server: { type: mongoose.Schema.Types.ObjectId, ref: 'Server' },
  channel: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  edited: { type: Boolean, default: false },
  editedAt: { type: Date },
  pinned: { type: Boolean, default: false },
  pinnedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  pinnedAt: { type: Date },
  parentMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' }, // For threads
  threadReplies: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Message' }],
  reactions: [{
    emoji: String,
    users: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
  }],
  isDM: { type: Boolean, default: false },
  dmParticipants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

const Message = mongoose.model('Message', MessageSchema);

// Direct Message Conversation Schema
const DMConversationSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  updatedAt: { type: Date, default: Date.now }
});

const DMConversation = mongoose.model('DMConversation', DMConversationSchema);

// Unread Messages Schema
const UnreadMessageSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  server: { type: mongoose.Schema.Types.ObjectId, ref: 'Server' },
  channel: { type: String },
  count: { type: Number, default: 0 },
  lastMessageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
  updatedAt: { type: Date, default: Date.now }
});

const UnreadMessage = mongoose.model('UnreadMessage', UnreadMessageSchema);

// Auth Middleware
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Helper function to check permissions
const hasPermission = (server, userId, permission) => {
  const member = server.members.find(m => m.user.toString() === userId);
  if (!member) return false;
  
  if (member.role === 'owner') return true;
  
  const role = server.roles.find(r => r.name === member.role);
  if (!role) return false;
  
  return role.permissions.administrator || role.permissions[permission];
};

// Routes

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'your-secret-key');
    res.json({ token, user: { id: user._id, username: user.username, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'your-secret-key');
    res.json({ token, user: { id: user._id, username: user.username, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get User Profile
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get User by ID
app.get('/api/users/:userId', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('-password -email');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Custom Status
app.put('/api/users/status', authMiddleware, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.userId,
      { customStatus: req.body.customStatus },
      { new: true }
    ).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Block User
app.post('/api/users/block/:userId', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user.blockedUsers.includes(req.params.userId)) {
      user.blockedUsers.push(req.params.userId);
      await user.save();
    }
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Unblock User
app.post('/api/users/unblock/:userId', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    user.blockedUsers = user.blockedUsers.filter(id => id.toString() !== req.params.userId);
    await user.save();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Blocked Users
app.get('/api/users/blocked', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).populate('blockedUsers', 'username avatar');
    res.json(user.blockedUsers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create Server
app.post('/api/servers', authMiddleware, async (req, res) => {
  try {
    const { name } = req.body;
    
    const user = await User.findById(req.userId);
    const userServers = await Server.find({ 'members.user': req.userId });
    
    if (userServers.length >= user.subscription.features.maxServers) {
      return res.status(400).json({ 
        error: `You've reached your server limit (${user.subscription.features.maxServers}). Upgrade your subscription!` 
      });
    }

    const server = new Server({
      name,
      owner: req.userId,
      members: [{ user: req.userId, role: 'owner' }],
      categories: [
        {
          name: 'Text Channels',
          position: 0,
          channels: [
            { name: 'general', type: 'text', position: 0 },
            { name: 'random', type: 'text', position: 1 }
          ]
        },
        {
          name: 'Voice Channels',
          position: 1,
          channels: [
            { name: 'General Voice', type: 'voice', position: 0 }
          ]
        }
      ],
      roles: [
        { name: 'member', color: '#99AAB5', position: 0 },
        { name: 'moderator', color: '#5865F2', position: 1, permissions: { manageMessages: true, kickMembers: true } },
        { name: 'admin', color: '#57F287', position: 2, permissions: { administrator: true } }
      ]
    });
    await server.save();
    res.json(server);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get User's Servers
app.get('/api/servers', authMiddleware, async (req, res) => {
  try {
    const servers = await Server.find({ 'members.user': req.userId });
    res.json(servers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Server Details
app.get('/api/servers/:serverId', authMiddleware, async (req, res) => {
  try {
    const server = await Server.findById(req.params.serverId)
      .populate('members.user', 'username status customStatus avatar');
    
    if (!server.members.some(m => m.user._id.toString() === req.userId)) {
      return res.status(403).json({ error: 'Not a member' });
    }
    res.json(server);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Server Settings
app.put('/api/servers/:serverId/settings', authMiddleware, async (req, res) => {
  try {
    const server = await Server.findById(req.params.serverId);
    
    if (!hasPermission(server, req.userId, 'manageServer')) {
      return res.status(403).json({ error: 'No permission' });
    }

    const { name, description, icon } = req.body;
    server.name = name || server.name;
    server.description = description !== undefined ? description : server.description;
    server.icon = icon !== undefined ? icon : server.icon;
    
    await server.save();
    res.json(server);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete Server
app.delete('/api/servers/:serverId', authMiddleware, async (req, res) => {
  try {
    const server = await Server.findById(req.params.serverId);
    
    if (server.owner.toString() !== req.userId) {
      return res.status(403).json({ error: 'Only owner can delete server' });
    }

    await Server.findByIdAndDelete(req.params.serverId);
    await Message.deleteMany({ server: req.params.serverId });
    await UnreadMessage.deleteMany({ server: req.params.serverId });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Leave Server
app.post('/api/servers/:serverId/leave', authMiddleware, async (req, res) => {
  try {
    const server = await Server.findById(req.params.serverId);
    
    if (server.owner.toString() === req.userId) {
      return res.status(400).json({ error: 'Owner cannot leave. Transfer ownership or delete server.' });
    }

    server.members = server.members.filter(m => m.user.toString() !== req.userId);
    await server.save();
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Member Role
app.put('/api/servers/:serverId/members/:userId/role', authMiddleware, async (req, res) => {
  try {
    const server = await Server.findById(req.params.serverId);
    
    if (!hasPermission(server, req.userId, 'manageRoles')) {
      return res.status(403).json({ error: 'No permission' });
    }

    const member = server.members.find(m => m.user.toString() === req.params.userId);
    if (member) {
      member.role = req.body.role;
      await server.save();
    }
    
    res.json(server);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Kick Member
app.post('/api/servers/:serverId/kick/:userId', authMiddleware, async (req, res) => {
  try {
    const server = await Server.findById(req.params.serverId);
    
    if (!hasPermission(server, req.userId, 'kickMembers')) {
      return res.status(403).json({ error: 'No permission' });
    }

    server.members = server.members.filter(m => m.user.toString() !== req.params.userId);
    await server.save();
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create Category
app.post('/api/servers/:serverId/categories', authMiddleware, async (req, res) => {
  try {
    const server = await Server.findById(req.params.serverId);
    
    if (!hasPermission(server, req.userId, 'manageChannels')) {
      return res.status(403).json({ error: 'No permission' });
    }

    server.categories.push({
      name: req.body.name,
      position: server.categories.length,
      channels: []
    });
    
    await server.save();
    res.json(server);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create Channel in Category
app.post('/api/servers/:serverId/categories/:categoryId/channels', authMiddleware, async (req, res) => {
  try {
    const server = await Server.findById(req.params.serverId);
    
    if (!hasPermission(server, req.userId, 'manageChannels')) {
      return res.status(403).json({ error: 'No permission' });
    }

    const category = server.categories.id(req.params.categoryId);
    if (category) {
      category.channels.push({
        name: req.body.name,
        type: req.body.type || 'text',
        position: category.channels.length
      });
      await server.save();
    }
    
    res.json(server);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Generate Invite Code
app.post('/api/servers/:serverId/invite', authMiddleware, async (req, res) => {
  try {
    const server = await Server.findById(req.params.serverId);
    if (!server) {
      return res.status(404).json({ error: 'Server not found' });
    }
    
    const inviteCode = server._id.toString().substring(0, 8);
    res.json({ inviteCode, serverId: server._id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Join Server via Invite Code
app.post('/api/servers/join/:inviteCode', authMiddleware, async (req, res) => {
  try {
    const servers = await Server.find();
    const server = servers.find(s => s._id.toString().startsWith(req.params.inviteCode));
    
    if (!server) {
      return res.status(404).json({ error: 'Invalid invite code' });
    }

    if (server.members.some(m => m.user.toString() === req.userId)) {
      return res.status(400).json({ error: 'Already a member' });
    }

    server.members.push({ user: req.userId, role: 'member' });
    await server.save();
    
    res.json(server);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Messages
app.get('/api/messages/:serverId/:channelName', authMiddleware, async (req, res) => {
  try {
    const { serverId, channelName } = req.params;
    
    // Check if user is blocked
    const user = await User.findById(req.userId);
    
    const messages = await Message.find({ 
      server: serverId, 
      channel: channelName,
      parentMessage: null // Only get top-level messages, not replies
    })
      .populate('author', 'username avatar')
      .populate('reactions.users', 'username')
      .populate({
        path: 'threadReplies',
        populate: { path: 'author', select: 'username avatar' }
      })
      .sort({ timestamp: 1 })
      .limit(100);
    
    // Filter out messages from blocked users
    const filteredMessages = messages.filter(msg => 
      !user.blockedUsers.includes(msg.author._id.toString())
    );
    
    res.json(filteredMessages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Pinned Messages
app.get('/api/messages/:serverId/:channelName/pinned', authMiddleware, async (req, res) => {
  try {
    const { serverId, channelName } = req.params;
    const messages = await Message.find({ 
      server: serverId, 
      channel: channelName,
      pinned: true
    })
      .populate('author', 'username avatar')
      .populate('pinnedBy', 'username')
      .sort({ pinnedAt: -1 })
      .limit(50);
    
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Pin Message
app.post('/api/messages/:messageId/pin', authMiddleware, async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId);
    const server = await Server.findById(message.server);
    
    if (!hasPermission(server, req.userId, 'manageMessages')) {
      return res.status(403).json({ error: 'No permission to pin messages' });
    }

    message.pinned = true;
    message.pinnedBy = req.userId;
    message.pinnedAt = new Date();
    await message.save();
    
    const populatedMessage = await Message.findById(message._id)
      .populate('author', 'username avatar')
      .populate('pinnedBy', 'username');
    
    res.json(populatedMessage);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Unpin Message
app.post('/api/messages/:messageId/unpin', authMiddleware, async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId);
    const server = await Server.findById(message.server);
    
    if (!hasPermission(server, req.userId, 'manageMessages')) {
      return res.status(403).json({ error: 'No permission to unpin messages' });
    }

    message.pinned = false;
    message.pinnedBy = null;
    message.pinnedAt = null;
    await message.save();
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create Thread Reply - Save parentMessage as STRING
app.post('/api/messages/:messageId/reply', authMiddleware, async (req, res) => {
  try {
    const messageId = req.params.messageId;
    const parentMessage = await Message.findById(messageId);
    
    if (!parentMessage) {
      return res.status(404).json({ error: 'Parent message not found' });
    }

    console.log('Creating reply for message:', messageId);
    console.log('Reply content:', req.body.content);
    
    // Create the reply - save parentMessage as STRING (to match existing data)
    const reply = new Message({
      content: req.body.content,
      author: req.userId,
      server: parentMessage.server,
      channel: parentMessage.channel,
      parentMessage: messageId,  // Save as STRING, not ObjectId
      timestamp: new Date()
    });
    
    await reply.save();
    console.log('Reply saved with ID:', reply._id.toString());
    console.log('Reply parentMessage (should be string):', reply.parentMessage, typeof reply.parentMessage);
    
    // Update parent's threadReplies array
    if (!Array.isArray(parentMessage.threadReplies)) {
      parentMessage.threadReplies = [];
    }
    parentMessage.threadReplies.push(reply._id);
    await parentMessage.save();
    console.log('Parent updated, total replies:', parentMessage.threadReplies.length);
    
    // Populate and return
    const populatedReply = await Message.findById(reply._id)
      .populate('author', 'username avatar');
    
    res.json(populatedReply);
  } catch (error) {
    console.error('Error creating thread reply:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get Thread Replies - FINAL FIX
app.get('/api/messages/:messageId/replies', authMiddleware, async (req, res) => {
  try {
    const messageId = req.params.messageId;
    console.log('Fetching replies for message:', messageId);
    console.log('messageId type:', typeof messageId);
    
    // Query by STRING, not ObjectId (since it's stored as string in DB)
    const replies = await Message.find({ 
      parentMessage: messageId  // Just the string, no ObjectId conversion
    })
      .populate('author', 'username avatar')
      .sort({ timestamp: 1 });
    
    console.log(`Found ${replies.length} replies for message ${messageId}`);
    
    if (replies.length > 0) {
      console.log('Reply contents:', replies.map(r => r.content));
    } else {
      console.log('No replies found - trying with ObjectId...');
      
      // Fallback: try with ObjectId
      const repliesWithObjectId = await Message.find({ 
        parentMessage: new mongoose.Types.ObjectId(messageId)
      })
        .populate('author', 'username avatar')
        .sort({ timestamp: 1 });
      
      console.log(`Found ${repliesWithObjectId.length} replies with ObjectId`);
      
      if (repliesWithObjectId.length > 0) {
        return res.json(repliesWithObjectId);
      }
    }
    
    res.json(replies);
  } catch (error) {
    console.error('Error fetching replies:', error);
    res.status(500).json({ error: error.message });
  }
});

// Search Messages
app.get('/api/messages/search/:serverId', authMiddleware, async (req, res) => {
  try {
    const { serverId } = req.params;
    const { query } = req.query;
    
    const messages = await Message.find({
      server: serverId,
      content: { $regex: query, $options: 'i' }
    })
      .populate('author', 'username avatar')
      .sort({ timestamp: -1 })
      .limit(50);
    
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Edit Message
app.put('/api/messages/:messageId', authMiddleware, async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId);
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    if (message.author.toString() !== req.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    message.content = req.body.content;
    message.edited = true;
    message.editedAt = new Date();
    await message.save();
    
    const populatedMessage = await Message.findById(message._id)
      .populate('author', 'username avatar');
    
    res.json(populatedMessage);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete Message
app.delete('/api/messages/:messageId', authMiddleware, async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId);
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    const server = await Server.findById(message.server);
    const canDelete = message.author.toString() === req.userId || 
                      hasPermission(server, req.userId, 'manageMessages');
    
    if (!canDelete) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    await Message.findByIdAndDelete(req.params.messageId);
    res.json({ success: true, messageId: req.params.messageId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add Reaction
app.post('/api/messages/:messageId/reactions', authMiddleware, async (req, res) => {
  try {
    const { emoji } = req.body;
    const message = await Message.findById(req.params.messageId);
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    const existingReaction = message.reactions.find(r => r.emoji === emoji);
    
    if (existingReaction) {
      if (existingReaction.users.includes(req.userId)) {
        existingReaction.users = existingReaction.users.filter(u => u.toString() !== req.userId);
        if (existingReaction.users.length === 0) {
          message.reactions = message.reactions.filter(r => r.emoji !== emoji);
        }
      } else {
        existingReaction.users.push(req.userId);
      }
    } else {
      message.reactions.push({ emoji, users: [req.userId] });
    }
    
    await message.save();
    
    const populatedMessage = await Message.findById(message._id)
      .populate('author', 'username avatar')
      .populate('reactions.users', 'username');
    
    res.json(populatedMessage);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DM Routes

// Get DM Conversations
app.get('/api/dms', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    const conversations = await DMConversation.find({
      participants: req.userId
    })
      .populate('participants', 'username status avatar')
      .populate('lastMessage')
      .sort({ updatedAt: -1 });
    
    // Filter out conversations with blocked users
    const filteredConversations = conversations.filter(conv => {
      const otherUser = conv.participants.find(p => p._id.toString() !== req.userId);
      return !user.blockedUsers.includes(otherUser._id.toString());
    });
    
    res.json(filteredConversations);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create or Get DM Conversation
app.post('/api/dms', authMiddleware, async (req, res) => {
  try {
    const { recipientId } = req.body;
    
    // Check if user is blocked
    const user = await User.findById(req.userId);
    const recipient = await User.findById(recipientId);
    
    if (user.blockedUsers.includes(recipientId) || recipient.blockedUsers.includes(req.userId)) {
      return res.status(403).json({ error: 'Cannot start conversation with this user' });
    }
    
    let conversation = await DMConversation.findOne({
      participants: { $all: [req.userId, recipientId] }
    }).populate('participants', 'username status avatar');
    
    if (!conversation) {
      conversation = new DMConversation({
        participants: [req.userId, recipientId]
      });
      await conversation.save();
      await conversation.populate('participants', 'username status avatar');
    }
    
    res.json(conversation);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get DM Messages
app.get('/api/dms/:conversationId/messages', authMiddleware, async (req, res) => {
  try {
    const conversation = await DMConversation.findById(req.params.conversationId);
    
    if (!conversation.participants.includes(req.userId)) {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    const messages = await Message.find({
      isDM: true,
      dmParticipants: { $all: conversation.participants }
    })
      .populate('author', 'username avatar')
      .populate('reactions.users', 'username')
      .sort({ timestamp: 1 })
      .limit(100);
    
    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Unread Counts
app.get('/api/unread', authMiddleware, async (req, res) => {
  try {
    const unreadMessages = await UnreadMessage.find({ user: req.userId });
    res.json(unreadMessages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mark Channel as Read
app.post('/api/unread/mark-read', authMiddleware, async (req, res) => {
  try {
    const { serverId, channel } = req.body;
    
    await UnreadMessage.findOneAndDelete({
      user: req.userId,
      server: serverId,
      channel: channel
    });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Socket.IO for Real-time Communication
const users = new Map();
const onlineUsers = new Set();

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error'));
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    socket.userId = decoded.userId;
    next();
  } catch (err) {
    next(new Error('Authentication error'));
  }
});

io.on('connection', async (socket) => {
  console.log('User connected:', socket.userId);
  users.set(socket.userId, socket.id);
  onlineUsers.add(socket.userId);

  await User.findByIdAndUpdate(socket.userId, { status: 'online' });

  const userServers = await Server.find({ 'members.user': socket.userId });
  userServers.forEach(server => {
    io.to(server._id.toString()).emit('user-status-change', {
      userId: socket.userId,
      status: 'online'
    });
  });

  socket.on('join-server', (serverId) => {
    socket.join(serverId);
  });

  socket.on('join-dm', (conversationId) => {
    socket.join(`dm-${conversationId}`);
  });

  socket.on('send-message', async (data) => {
    try {
      const message = new Message({
        content: data.content,
        author: socket.userId,
        server: data.serverId,
        channel: data.channel
      });
      await message.save();
      
      const populatedMessage = await Message.findById(message._id)
        .populate('author', 'username avatar');
      
      io.to(data.serverId).emit('new-message', populatedMessage);

      // Update unread counts
      const server = await Server.findById(data.serverId);
      for (const member of server.members) {
        if (member.user.toString() !== socket.userId) {
          const unread = await UnreadMessage.findOne({
            user: member.user,
            server: data.serverId,
            channel: data.channel
          });

          if (unread) {
            unread.count += 1;
            unread.lastMessageId = message._id;
            unread.updatedAt = new Date();
            await unread.save();
          } else {
            await UnreadMessage.create({
              user: member.user,
              server: data.serverId,
              channel: data.channel,
              count: 1,
              lastMessageId: message._id
            });
          }
        }
      }
    } catch (error) {
      console.error('Message error:', error);
    }
  });

  socket.on('send-dm', async (data) => {
    try {
      const conversation = await DMConversation.findById(data.conversationId);
      
      const message = new Message({
        content: data.content,
        author: socket.userId,
        isDM: true,
        dmParticipants: conversation.participants,
        channel: 'dm',
        timestamp: new Date()
      });
      await message.save();
      
      conversation.lastMessage = message._id;
      conversation.updatedAt = new Date();
      await conversation.save();
      
      const populatedMessage = await Message.findById(message._id)
        .populate('author', 'username avatar');
      
      io.to(`dm-${data.conversationId}`).emit('new-dm-message', populatedMessage);
    } catch (error) {
      console.error('DM error:', error);
    }
  });

  socket.on('typing', (data) => {
    socket.to(data.serverId).emit('user-typing', {
      userId: socket.userId,
      channel: data.channel
    });
  });

  socket.on('edit-message', async (data) => {
    try {
      const message = await Message.findById(data.messageId);
      if (message && message.author.toString() === socket.userId) {
        message.content = data.content;
        message.edited = true;
        message.editedAt = new Date();
        await message.save();
        
        const populatedMessage = await Message.findById(message._id)
          .populate('author', 'username avatar')
          .populate('reactions.users', 'username');
        
        if (data.serverId) {
          io.to(data.serverId).emit('message-edited', populatedMessage);
        } else if (data.conversationId) {
          io.to(`dm-${data.conversationId}`).emit('message-edited', populatedMessage);
        }
      }
    } catch (error) {
      console.error('Edit message error:', error);
    }
  });

  socket.on('delete-message', async (data) => {
    try {
      const message = await Message.findById(data.messageId);
      if (message && message.author.toString() === socket.userId) {
        await Message.findByIdAndDelete(data.messageId);
        
        if (data.serverId) {
          io.to(data.serverId).emit('message-deleted', { messageId: data.messageId });
        } else if (data.conversationId) {
          io.to(`dm-${data.conversationId}`).emit('message-deleted', { messageId: data.messageId });
        }
      }
    } catch (error) {
      console.error('Delete message error:', error);
    }
  });

  socket.on('add-reaction', async (data) => {
    try {
      const message = await Message.findById(data.messageId);
      if (!message) return;
      
      const existingReaction = message.reactions.find(r => r.emoji === data.emoji);
      
      if (existingReaction) {
        if (existingReaction.users.includes(socket.userId)) {
          existingReaction.users = existingReaction.users.filter(u => u.toString() !== socket.userId);
          if (existingReaction.users.length === 0) {
            message.reactions = message.reactions.filter(r => r.emoji !== data.emoji);
          }
        } else {
          existingReaction.users.push(socket.userId);
        }
      } else {
        message.reactions.push({ emoji: data.emoji, users: [socket.userId] });
      }
      
      await message.save();
      
      const populatedMessage = await Message.findById(message._id)
        .populate('author', 'username avatar')
        .populate('reactions.users', 'username');
      
      if (data.serverId) {
        io.to(data.serverId).emit('reaction-added', populatedMessage);
      } else if (data.conversationId) {
        io.to(`dm-${data.conversationId}`).emit('reaction-added', populatedMessage);
      }
    } catch (error) {
      console.error('Reaction error:', error);
    }
  });

  socket.on('voice-offer', (data) => {
    const targetSocketId = users.get(data.to);
    if (targetSocketId) {
      io.to(targetSocketId).emit('voice-offer', {
        from: socket.userId,
        offer: data.offer
      });
    }
  });

  socket.on('voice-answer', (data) => {
    const targetSocketId = users.get(data.to);
    if (targetSocketId) {
      io.to(targetSocketId).emit('voice-answer', {
        from: socket.userId,
        answer: data.answer
      });
    }
  });

  socket.on('ice-candidate', (data) => {
    const targetSocketId = users.get(data.to);
    if (targetSocketId) {
      io.to(targetSocketId).emit('ice-candidate', {
        from: socket.userId,
        candidate: data.candidate
      });
    }
  });

  socket.on('disconnect', async () => {
    users.delete(socket.userId);
    onlineUsers.delete(socket.userId);
    
    await User.findByIdAndUpdate(socket.userId, { 
      status: 'offline',
      lastSeen: new Date()
    });
    
    const userServers = await Server.find({ 'members.user': socket.userId });
    userServers.forEach(server => {
      io.to(server._id.toString()).emit('user-status-change', {
        userId: socket.userId,
        status: 'offline'
      });
    });
    
    console.log('User disconnected:', socket.userId);
  });

  socket.on('join-voice-channel', async (data) => {
    const { channelName } = data;
    socket.join(`voice-${channelName}`);
    
    const user = await User.findById(socket.userId).select('username');
    
    socket.to(`voice-${channelName}`).emit('voice-user-joined', {
      userId: socket.userId,
      username: user.username
    });
  });

  socket.on('leave-voice-channel', (data) => {
    const { channelName } = data;
    socket.leave(`voice-${channelName}`);
    
    socket.to(`voice-${channelName}`).emit('voice-user-left', {
      userId: socket.userId
    });
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));