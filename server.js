require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);

const io = socketIo(server, {
  cors: { origin: '*', methods: ['GET', 'POST', 'DELETE'] },
});

// ─── Middleware ───────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: false }));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

if (!fs.existsSync('./uploads'))         fs.mkdirSync('./uploads',         { recursive: true });
if (!fs.existsSync('./uploads/avatars')) fs.mkdirSync('./uploads/avatars', { recursive: true });
if (!fs.existsSync('./uploads/media'))   fs.mkdirSync('./uploads/media',   { recursive: true });

// ─── MongoDB Connection ───────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI;
mongoose
  .connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch((err) => console.error('❌ MongoDB Error:', err));

// ─── Test Route ───────────────────────────────────────────────────
app.get('/api/test1', (req, res) => {
  res.json({ message: 'Backend + MongoDB working 🚀 shiva' });
});

// ─── Schemas ──────────────────────────────────────────────────────
const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true, trim: true },
    email:    { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true, minlength: 6 },
    avatar:   { type: String, default: '' },
    status:   { type: String, default: 'Hey there! I am using ChatApp.' },
    isOnline: { type: Boolean, default: false },
    lastSeen: { type: Date, default: Date.now },
    contacts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  },
  { timestamps: true }
);

const messageSchema = new mongoose.Schema(
  {
    conversationId: { type: String, required: true, index: true },
    sender:         { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiver:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type:           { type: String, enum: ['text', 'image', 'video', 'audio', 'file'], default: 'text' },
    content:        { type: String, default: '' },
    mediaUrl:       { type: String, default: '' },
    fileName:       { type: String, default: '' },
    fileSize:       { type: Number, default: 0 },
    isRead:         { type: Boolean, default: false },
    isDelivered:    { type: Boolean, default: false },
    isDeleted:      { type: Boolean, default: false },
    reactions:      [{ emoji: String, userId: mongoose.Schema.Types.ObjectId }],
    replyTo:        { type: mongoose.Schema.Types.ObjectId, ref: 'Message', default: null },
  },
  { timestamps: true }
);

const User    = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

// ─── Multer Config ────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, req.path.includes('avatar') ? './uploads/avatars' : './uploads/media');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(file.originalname));
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp|mp4|mp3|wav|pdf|doc|docx|zip/;
    allowed.test(path.extname(file.originalname).toLowerCase()) ? cb(null, true) : cb(new Error('File type not allowed'));
  },
});

// ─── Auth Middleware ──────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key_change_in_production';

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.userId = jwt.verify(token, JWT_SECRET).userId;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const getConversationId = (id1, id2) => [id1.toString(), id2.toString()].sort().join('_');

// ─── Auth Routes ──────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (await User.findOne({ $or: [{ email }, { username }] })) return res.status(400).json({ error: 'User already exists' });
    const user  = await User.create({ username, email, password: await bcrypt.hash(password, 12) });
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { _id: user._id, username: user.username, email: user.email, avatar: user.avatar, status: user.status } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    await User.findByIdAndUpdate(user._id, { isOnline: true });
    res.json({ token, user: { _id: user._id, username: user.username, email: user.email, avatar: user.avatar, status: user.status, isOnline: true } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── User Routes ──────────────────────────────────────────────────
app.get('/api/users/me', authMiddleware, async (req, res) => {
  res.json(await User.findById(req.userId).select('-password'));
});

app.get('/api/users/search', authMiddleware, async (req, res) => {
  const { q } = req.query;
  res.json(await User.find({
    _id: { $ne: req.userId },
    $or: [{ username: { $regex: q, $options: 'i' } }, { email: { $regex: q, $options: 'i' } }],
  }).select('-password').limit(20));
});

app.get('/api/users/contacts', authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId).populate('contacts', '-password');
  res.json(user.contacts);
});

app.post('/api/users/add-contact', authMiddleware, async (req, res) => {
  await User.findByIdAndUpdate(req.userId, { $addToSet: { contacts: req.body.contactId } });
  res.json(await User.findById(req.body.contactId).select('-password'));
});

app.put('/api/users/status', authMiddleware, async (req, res) => {
  await User.findByIdAndUpdate(req.userId, { status: req.body.status });
  res.json({ message: 'Status updated' });
});

app.post('/api/users/avatar', authMiddleware, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const avatarUrl = `/uploads/avatars/${req.file.filename}`;
  await User.findByIdAndUpdate(req.userId, { avatar: avatarUrl });
  res.json({ avatarUrl });
});

// ─── Message Routes ───────────────────────────────────────────────
// ⚠️  ORDER MATTERS: specific paths must come BEFORE /:param routes

// 1. Get conversations list
app.get('/api/messages/conversations/list', authMiddleware, async (req, res) => {
  try {
    const messages = await Message.aggregate([
      {
        $match: {
          $or: [{ sender: new mongoose.Types.ObjectId(req.userId) }, { receiver: new mongoose.Types.ObjectId(req.userId) }],
          isDeleted: false,
        },
      },
      { $sort: { createdAt: -1 } },
      {
        $group: {
          _id: '$conversationId',
          lastMessage: { $first: '$$ROOT' },
          unreadCount: {
            $sum: {
              $cond: [{ $and: [{ $eq: ['$receiver', new mongoose.Types.ObjectId(req.userId)] }, { $eq: ['$isRead', false] }] }, 1, 0],
            },
          },
        },
      },
    ]);

    const populated = await Message.populate(messages.map((m) => m.lastMessage), [
      { path: 'sender',   select: 'username avatar isOnline lastSeen' },
      { path: 'receiver', select: 'username avatar isOnline lastSeen' },
    ]);

    res.json(messages.map((m, i) => ({ conversationId: m._id, lastMessage: populated[i], unreadCount: m.unreadCount })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// 2. Upload media
app.post('/api/messages/media', authMiddleware, upload.single('media'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ mediaUrl: `/uploads/media/${req.file.filename}`, fileName: req.file.originalname, fileSize: req.file.size });
});

// 3. ✅ Clear chat — soft delete all messages (keep conversation visible)
app.delete('/api/messages/conversation/:otherUserId', authMiddleware, async (req, res) => {
  try {
    const conversationId = getConversationId(req.userId, req.params.otherUserId);
    await Message.updateMany({ conversationId }, { isDeleted: true });
    res.json({ message: 'Chat cleared successfully ✅' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// 4. ✅ Delete conversation — hard delete ALL messages permanently
app.delete('/api/messages/conversation/:otherUserId/hard', authMiddleware, async (req, res) => {
  try {
    const conversationId = getConversationId(req.userId, req.params.otherUserId);
    await Message.deleteMany({ conversationId });
    res.json({ message: 'Conversation deleted permanently ✅' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// 5. ✅ Delete single message — soft delete (only sender can delete)
app.delete('/api/messages/:messageId', authMiddleware, async (req, res) => {
  try {
    await Message.findOneAndUpdate({ _id: req.params.messageId, sender: req.userId }, { isDeleted: true });
    res.json({ message: 'Message deleted ✅' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// 6. Get messages for a conversation (must be LAST among message routes)
app.get('/api/messages/:userId', authMiddleware, async (req, res) => {
  try {
    const conversationId = getConversationId(req.userId, req.params.userId);
    const messages = await Message.find({ conversationId, isDeleted: false })
      .populate('sender',   'username avatar')
      .populate('receiver', 'username avatar')
      .populate('replyTo')
      .sort({ createdAt: 1 });
    await Message.updateMany({ conversationId, receiver: req.userId, isRead: false }, { isRead: true });
    res.json(messages);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── Socket.IO ────────────────────────────────────────────────────
const onlineUsers = new Map();

io.on('connection', (socket) => {
  console.log('🔌 Socket connected:', socket.id);

  socket.on('user:online', async (userId) => {
    onlineUsers.set(userId, socket.id);
    socket.userId = userId;
    await User.findByIdAndUpdate(userId, { isOnline: true, lastSeen: new Date() });
    io.emit('user:status', { userId, isOnline: true });
  });

  socket.on('message:send', async (data) => {
    try {
      const { senderId, receiverId, type, content, mediaUrl, fileName, fileSize, replyTo } = data;
      const conversationId = getConversationId(senderId, receiverId);

      const message = await Message.create({
        conversationId, sender: senderId, receiver: receiverId,
        type: type || 'text', content, mediaUrl, fileName, fileSize, replyTo,
        isDelivered: onlineUsers.has(receiverId),
      });

      const populated = await message.populate([
        { path: 'sender',   select: 'username avatar' },
        { path: 'receiver', select: 'username avatar' },
        { path: 'replyTo' },
      ]);

      const receiverSocket = onlineUsers.get(receiverId);
      if (receiverSocket) io.to(receiverSocket).emit('message:receive', populated);
      socket.emit('message:sent', populated);
    } catch (err) {
      socket.emit('error', { message: err.message });
    }
  });

  socket.on('message:read', async ({ conversationId, userId }) => {
    await Message.updateMany({ conversationId, receiver: userId, isRead: false }, { isRead: true });
    io.emit('message:read:ack', { conversationId });
  });

  socket.on('typing:start', ({ senderId, receiverId }) => {
    const s = onlineUsers.get(receiverId);
    if (s) io.to(s).emit('typing:start', { senderId });
  });

  socket.on('typing:stop', ({ senderId, receiverId }) => {
    const s = onlineUsers.get(receiverId);
    if (s) io.to(s).emit('typing:stop', { senderId });
  });

  socket.on('message:reaction', async ({ messageId, emoji, userId }) => {
    const message = await Message.findByIdAndUpdate(
      messageId, { $addToSet: { reactions: { emoji, userId } } }, { new: true }
    );
    io.emit('message:reaction:update', { messageId, reactions: message.reactions });
  });

  socket.on('disconnect', async () => {
    if (socket.userId) {
      onlineUsers.delete(socket.userId);
      await User.findByIdAndUpdate(socket.userId, { isOnline: false, lastSeen: new Date() });
      io.emit('user:status', { userId: socket.userId, isOnline: false, lastSeen: new Date() });
    }
  });
});

// ─── Start Server ─────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));