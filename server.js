'use strict';
const express  = require('express');
const mongoose = require('mongoose');
const cors     = require('cors');
const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');

// Load .env FIRST before anything else
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI || process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'rhs_default_secret_change_me';

// Debug: print env vars on startup (remove after fix)
console.log('=== ENV CHECK ===');
console.log('PORT:', PORT);
console.log('MONGO_URI exists:', !!MONGO_URI);
console.log('MONGO_URI prefix:', MONGO_URI ? MONGO_URI.substring(0, 30) + '...' : 'MISSING!');
console.log('JWT_SECRET exists:', !!JWT_SECRET);
console.log('=================');

if (!MONGO_URI) {
    console.error('❌ FATAL: MONGO_URI environment variable is not set!');
    console.error('Please set MONGO_URI in Render Environment settings.');
    process.exit(1);
}

// CORS - allow all origins
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','PATCH','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json({ limit: '10mb' }));

// Connect MongoDB
mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 15000 })
    .then(() => console.log('✅ MongoDB Atlas connected!'))
    .catch(err => {
        console.error('❌ MongoDB error:', err.message);
        process.exit(1);
    });

// Generic data store
const ItemSchema = new mongoose.Schema({
    schoolId:   { type: String, required: true, index: true },
    collection: { type: String, required: true, index: true },
    itemId:     { type: String, required: true },
    data:       mongoose.Schema.Types.Mixed,
    createdAt:  { type: Date, default: Date.now },
    updatedAt:  { type: Date, default: Date.now }
});
const Item = mongoose.model('Item', ItemSchema);

// User schema
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    fullName: String,
    role:     { type: String, default: 'teacher' },
    status:   { type: String, default: 'active' },
    schoolId: { type: String, default: 'rhs' },
    lastLogin: Date,
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const SCHOOL = 'rhs';

// ── HEALTH ──
app.get('/', (req, res) => res.json({ status: 'ok', message: 'RHS PRMS API running', db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' }));
app.get('/api/health', (req, res) => res.json({ status: 'ok', message: 'RHS PRMS Backend running', db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected', time: new Date().toISOString() }));

// ── AUTH ──
app.post('/api/auth/initialize', async (req, res) => {
    try {
        let count = await User.countDocuments({ schoolId: SCHOOL });
        if (count === 0) {
            await User.insertMany([
                { username: 'admin',   password: await bcrypt.hash('admin123',10),   fullName: 'AHM RHS',        role: 'admin',   schoolId: SCHOOL },
                { username: 'teacher', password: await bcrypt.hash('teacher123',10), fullName: 'Sample Teacher', role: 'teacher', schoolId: SCHOOL },
                { username: 'office',  password: await bcrypt.hash('office123',10),  fullName: 'Office Staff',   role: 'office',  schoolId: SCHOOL },
            ]);
            count = 3;
        }
        res.json({ success: true, message: 'Initialized', users: count });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body || {};
        if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

        // Auto-create admin if no users
        if (await User.countDocuments({ schoolId: SCHOOL }) === 0) {
            await User.create({ username: 'admin', password: await bcrypt.hash('admin123',10), fullName: 'AHM RHS', role: 'admin', schoolId: SCHOOL });
        }

        const user = await User.findOne({ username: username.toLowerCase().trim(), schoolId: SCHOOL });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        if (user.status !== 'active') return res.status(403).json({ error: 'Account inactive' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

        user.lastLogin = new Date();
        await user.save();

        const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token, user: { id: user._id, username: user.username, fullName: user.fullName, role: user.role } });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── AUTH MIDDLEWARE ──
function auth(req, res, next) {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token' });
    try { req.user = jwt.verify(token, JWT_SECRET); next(); }
    catch(e) { res.status(401).json({ error: 'Invalid token' }); }
}

// ── USERS ──
app.get('/api/users', auth, async (req, res) => {
    try {
        const users = await User.find({ schoolId: SCHOOL }).select('-password');
        res.json(users);
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/users', auth, async (req, res) => {
    try {
        const { username, password, fullName, role } = req.body;
        const hashed = await bcrypt.hash(password || 'password123', 10);
        const user = await User.create({ username: username.toLowerCase(), password: hashed, fullName, role, schoolId: SCHOOL });
        res.json({ success: true, user: { id: user._id, username: user.username, role: user.role } });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/users/:id', auth, async (req, res) => {
    try {
        const updates = { ...req.body };
        if (updates.password) updates.password = await bcrypt.hash(updates.password, 10);
        const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-password');
        res.json(user);
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/:id', auth, async (req, res) => {
    try { await User.findByIdAndDelete(req.params.id); res.json({ success: true }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});

// ── GENERIC CRUD for all collections ──
const COLLECTIONS = ['teachers','subjects','classes','periods','routines','provisionals',
    'leaves','leaveRequests','exams','exam-timetables','halls','students','attendance',
    'settings','seatingPlans','invigilatorRosters','marksData','notifications',
    'loginHistory','uploadHistory','substitutes','substituteRecords','fridayPeriods',
    'smsLog','emailLog','chats','messages','groups','events','holidays','notices'];

async function getAll(collection) {
    const docs = await Item.find({ schoolId: SCHOOL, collection }).sort({ createdAt: 1 });
    return docs.map(d => ({ ...d.data, _mid: d._id }));
}

async function upsertItem(collection, item) {
    const itemId = String(item.id || item._id || Date.now() + Math.random());
    item.id = item.id || itemId;
    await Item.findOneAndUpdate(
        { schoolId: SCHOOL, collection, itemId },
        { schoolId: SCHOOL, collection, itemId, data: item, updatedAt: new Date() },
        { upsert: true, new: true }
    );
    return item;
}

async function replaceAll(collection, items) {
    await Item.deleteMany({ schoolId: SCHOOL, collection });
    if (!items.length) return;
    const docs = items.map((item, i) => {
        const itemId = String(item.id || item._id || Date.now() + i);
        item.id = item.id || itemId;
        return { schoolId: SCHOOL, collection, itemId, data: item, updatedAt: new Date() };
    });
    await Item.insertMany(docs);
}

COLLECTIONS.forEach(col => {
    const path = `/api/${col}`;

    // GET all
    app.get(path, auth, async (req, res) => {
        try { res.json(await getAll(col)); }
        catch(e) { res.status(500).json({ error: e.message }); }
    });

    // POST single
    app.post(path, auth, async (req, res) => {
        try {
            const item = await upsertItem(col, req.body);
            res.status(201).json({ success: true, item });
        } catch(e) { res.status(500).json({ error: e.message }); }
    });

    // POST bulk replace
    app.post(`${path}/bulk`, auth, async (req, res) => {
        try {
            const items = req.body.data || req.body;
            if (!Array.isArray(items)) return res.status(400).json({ error: 'Expected array in {data:[...]}' });
            await replaceAll(col, items);
            res.json({ success: true, count: items.length });
        } catch(e) { res.status(500).json({ error: e.message }); }
    });

    // PUT single
    app.put(`${path}/:id`, auth, async (req, res) => {
        try {
            const item = await upsertItem(col, { ...req.body, id: req.params.id });
            res.json({ success: true, item });
        } catch(e) { res.status(500).json({ error: e.message }); }
    });

    // PUT bulk (settings)
    app.put(path, auth, async (req, res) => {
        try {
            const item = await upsertItem(col, { ...req.body, id: col });
            res.json({ success: true, item });
        } catch(e) { res.status(500).json({ error: e.message }); }
    });

    // DELETE single
    app.delete(`${path}/:id`, auth, async (req, res) => {
        try {
            await Item.deleteOne({ schoolId: SCHOOL, collection: col, itemId: req.params.id });
            res.json({ success: true });
        } catch(e) { res.status(500).json({ error: e.message }); }
    });

    // GET single
    app.get(`${path}/:id`, auth, async (req, res) => {
        try {
            const doc = await Item.findOne({ schoolId: SCHOOL, collection: col, itemId: req.params.id });
            if (!doc) return res.status(404).json({ error: 'Not found' });
            res.json(doc.data);
        } catch(e) { res.status(500).json({ error: e.message }); }
    });
});

// 404
app.use((req, res) => res.status(404).json({ error: `Route ${req.method} ${req.url} not found` }));

app.listen(PORT, () => {
    console.log(`🚀 RHS PRMS Backend running on port ${PORT}`);
    console.log(`🏥 Health check: http://localhost:${PORT}/api/health`);
});

module.exports = app;
