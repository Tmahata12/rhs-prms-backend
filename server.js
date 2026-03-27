const express   = require('express');
const mongoose  = require('mongoose');
const cors      = require('cors');
const jwt       = require('jsonwebtoken');
const bcrypt    = require('bcryptjs');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 5000;

// ─── CORS ────────────────────────────────────────────────────────────────────
app.use(cors({
    origin: '*',          // GitHub Pages, Render frontend, local file
    methods: ['GET','POST','PUT','DELETE','PATCH','OPTIONS'],
    allowedHeaders: ['Content-Type','Authorization'],
    credentials: false
}));
app.use(express.json({ limit: '10mb' }));

// ─── MONGODB ──────────────────────────────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI;

mongoose.connect(MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000,
})
.then(() => console.log('✅ MongoDB Atlas connected'))
.catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
});

// ─── GENERIC COLLECTION SCHEMA ───────────────────────────────────────────────
// One flexible schema for all data collections
function makeModel(collectionName) {
    const schema = new mongoose.Schema({
        schoolId:  { type: String, default: 'rhs_default' },
        data:      { type: mongoose.Schema.Types.Mixed, required: true },
        createdAt: { type: Date, default: Date.now },
        updatedAt: { type: Date, default: Date.now }
    }, { collection: collectionName, strict: false });

    schema.pre('save', function(next) {
        this.updatedAt = new Date();
        next();
    });

    try { return mongoose.model(collectionName); }
    catch(e) { return mongoose.model(collectionName, schema); }
}

// ─── USER SCHEMA ─────────────────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
    username:  { type: String, required: true, unique: true, lowercase: true, trim: true },
    password:  { type: String, required: true },
    fullName:  { type: String, default: '' },
    role:      { type: String, enum: ['admin','teacher','office','staff'], default: 'teacher' },
    email:     { type: String, default: '' },
    phone:     { type: String, default: '' },
    status:    { type: String, enum: ['active','inactive'], default: 'active' },
    schoolId:  { type: String, default: 'rhs_default' },
    lastLogin: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ─── JWT HELPERS ─────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'rhs_prms_secret_2025_change_this';

function signToken(user) {
    return jwt.sign(
        { id: user._id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
}

function authMiddleware(req, res, next) {
    const header = req.headers.authorization || '';
    const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'No token provided' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch(e) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// ─── COLLECTION HELPER ───────────────────────────────────────────────────────
const CollectionItem = mongoose.models.CollectionItem ||
    mongoose.model('CollectionItem', new mongoose.Schema({
        schoolId:   { type: String, required: true, index: true },
        collection: { type: String, required: true, index: true },
        itemId:     { type: String, required: true },
        data:       { type: mongoose.Schema.Types.Mixed, required: true },
        createdAt:  { type: Date, default: Date.now },
        updatedAt:  { type: Date, default: Date.now }
    }, { strict: false }));

const DEFAULT_SCHOOL = 'rhs_default';

// Get all items from a collection
async function getItems(schoolId, collection) {
    const docs = await CollectionItem.find({ schoolId, collection }).sort({ createdAt: 1 });
    return docs.map(d => ({ ...d.data, _mongoId: d._id }));
}

// Save bulk items (replace all)
async function setItems(schoolId, collection, items) {
    await CollectionItem.deleteMany({ schoolId, collection });
    if (!Array.isArray(items) || !items.length) return;
    const docs = items.map(item => ({
        schoolId,
        collection,
        itemId: String(item.id || item._id || Date.now() + Math.random()),
        data:   item,
        updatedAt: new Date()
    }));
    await CollectionItem.insertMany(docs);
}

// ─── HEALTH ──────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        message: 'RHS PRMS Backend is running',
        db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        time: new Date().toISOString(),
        version: '1.0.0'
    });
});

app.get('/', (req, res) => {
    res.json({ message: 'RHS PRMS API', status: 'running', version: '1.0.0' });
});

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

// Initialize default users
app.post('/api/auth/initialize', async (req, res) => {
    try {
        const count = await User.countDocuments({ schoolId: DEFAULT_SCHOOL });
        if (count === 0) {
            const defaults = [
                { username: 'admin',   password: await bcrypt.hash('admin123',   10), fullName: 'AHM RHS',       role: 'admin',   status: 'active' },
                { username: 'teacher', password: await bcrypt.hash('teacher123', 10), fullName: 'Sample Teacher', role: 'teacher', status: 'active' },
                { username: 'office',  password: await bcrypt.hash('office123',  10), fullName: 'Office Staff',   role: 'office',  status: 'active' },
            ];
            await User.insertMany(defaults.map(u => ({ ...u, schoolId: DEFAULT_SCHOOL })));
            res.json({ message: 'Default users created', count: defaults.length });
        } else {
            res.json({ message: 'Already initialized', count });
        }
    } catch(e) {
        res.status(500).json({ error: e.message });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password)
            return res.status(400).json({ error: 'Username and password required' });

        // Auto-initialize if no users
        const count = await User.countDocuments({ schoolId: DEFAULT_SCHOOL });
        if (count === 0) {
            await User.create({
                username: 'admin',
                password: await bcrypt.hash('admin123', 10),
                fullName: 'AHM RHS',
                role: 'admin',
                status: 'active',
                schoolId: DEFAULT_SCHOOL
            });
        }

        const user = await User.findOne({
            username: username.toLowerCase(),
            schoolId: DEFAULT_SCHOOL
        });

        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        if (user.status !== 'active') return res.status(403).json({ error: 'Account inactive' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

        user.lastLogin = new Date();
        await user.save();

        const token = signToken(user);
        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                username: user.username,
                fullName: user.fullName,
                role: user.role,
                email: user.email
            }
        });
    } catch(e) {
        res.status(500).json({ error: e.message });
    }
});

// Register new user (admin only)
app.post('/api/auth/register', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'admin')
            return res.status(403).json({ error: 'Admin only' });

        const { username, password, fullName, role, email, phone } = req.body;
        if (!username || !password)
            return res.status(400).json({ error: 'Username and password required' });

        const exists = await User.findOne({ username: username.toLowerCase(), schoolId: DEFAULT_SCHOOL });
        if (exists) return res.status(400).json({ error: 'Username already exists' });

        const hashed = await bcrypt.hash(password, 10);
        const user   = await User.create({
            username: username.toLowerCase(),
            password: hashed,
            fullName: fullName || username,
            role:     role || 'teacher',
            email:    email || '',
            phone:    phone || '',
            status:   'active',
            schoolId: DEFAULT_SCHOOL
        });

        res.status(201).json({ success: true, user: { id: user._id, username: user.username, role: user.role } });
    } catch(e) {
        res.status(500).json({ error: e.message });
    }
});

// Get all users (admin only)
app.get('/api/users', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
        const users = await User.find({ schoolId: DEFAULT_SCHOOL }).select('-password');
        res.json(users);
    } catch(e) {
        res.status(500).json({ error: e.message });
    }
});

// Update user
app.put('/api/users/:id', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
        const { password, ...updates } = req.body;
        if (password) updates.password = await bcrypt.hash(password, 10);
        const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-password');
        res.json(user);
    } catch(e) {
        res.status(500).json({ error: e.message });
    }
});

// Delete user
app.delete('/api/users/:id', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
        await User.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch(e) {
        res.status(500).json({ error: e.message });
    }
});

// ─── GENERIC CRUD ROUTES ─────────────────────────────────────────────────────
// All data collections use the same pattern

const COLLECTIONS = [
    'teachers', 'subjects', 'classes', 'periods', 'routines',
    'provisionals', 'leaves', 'exams', 'exam-timetables',
    'halls', 'students', 'attendance', 'seatingPlans',
    'invigilatorRosters', 'marksData', 'notifications',
    'loginHistory', 'uploadHistory', 'settings',
    'substitutes', 'substituteRecords', 'leaveRequests',
    'fridayPeriods', 'smsLog', 'emailLog', 'chats', 'messages',
    'groups', 'events', 'holidays', 'notices', 'backups'
];

COLLECTIONS.forEach(col => {
    const path = `/api/${col}`;

    // GET all
    app.get(path, authMiddleware, async (req, res) => {
        try {
            const items = await getItems(DEFAULT_SCHOOL, col);
            res.json(items);
        } catch(e) { res.status(500).json({ error: e.message }); }
    });

    // GET single by id
    app.get(`${path}/:id`, authMiddleware, async (req, res) => {
        try {
            const items = await getItems(DEFAULT_SCHOOL, col);
            const item  = items.find(i => String(i.id || i._id) === req.params.id);
            if (!item) return res.status(404).json({ error: 'Not found' });
            res.json(item);
        } catch(e) { res.status(500).json({ error: e.message }); }
    });

    // POST single item
    app.post(path, authMiddleware, async (req, res) => {
        try {
            const item = req.body;
            if (!item.id) item.id = Date.now().toString() + Math.floor(Math.random()*1000);
            item.updatedAt = new Date().toISOString();

            const existing = await CollectionItem.findOne({
                schoolId: DEFAULT_SCHOOL, collection: col,
                itemId: String(item.id)
            });

            if (existing) {
                existing.data = item;
                existing.updatedAt = new Date();
                await existing.save();
                res.json({ success: true, item, action: 'updated' });
            } else {
                await CollectionItem.create({
                    schoolId: DEFAULT_SCHOOL, collection: col,
                    itemId: String(item.id), data: item
                });
                res.status(201).json({ success: true, item, action: 'created' });
            }
        } catch(e) { res.status(500).json({ error: e.message }); }
    });

    // POST bulk replace
    app.post(`${path}/bulk`, authMiddleware, async (req, res) => {
        try {
            const items = req.body.data || req.body;
            if (!Array.isArray(items)) return res.status(400).json({ error: 'Expected array' });
            await setItems(DEFAULT_SCHOOL, col, items);
            res.json({ success: true, count: items.length });
        } catch(e) { res.status(500).json({ error: e.message }); }
    });

    // PUT update single
    app.put(`${path}/:id`, authMiddleware, async (req, res) => {
        try {
            const item = { ...req.body, id: req.params.id, updatedAt: new Date().toISOString() };
            await CollectionItem.findOneAndUpdate(
                { schoolId: DEFAULT_SCHOOL, collection: col, itemId: req.params.id },
                { data: item, updatedAt: new Date() },
                { upsert: true, new: true }
            );
            res.json({ success: true, item });
        } catch(e) { res.status(500).json({ error: e.message }); }
    });

    // PUT bulk (settings uses this)
    app.put(path, authMiddleware, async (req, res) => {
        try {
            const item = { ...req.body, id: col, updatedAt: new Date().toISOString() };
            await CollectionItem.findOneAndUpdate(
                { schoolId: DEFAULT_SCHOOL, collection: col, itemId: col },
                { data: item, updatedAt: new Date() },
                { upsert: true, new: true }
            );
            res.json({ success: true, item });
        } catch(e) { res.status(500).json({ error: e.message }); }
    });

    // DELETE single
    app.delete(`${path}/:id`, authMiddleware, async (req, res) => {
        try {
            await CollectionItem.deleteOne({
                schoolId: DEFAULT_SCHOOL, collection: col, itemId: req.params.id
            });
            res.json({ success: true });
        } catch(e) { res.status(500).json({ error: e.message }); }
    });
});

// Settings GET without auth (for public school info display)
app.get('/api/settings/public', async (req, res) => {
    try {
        const items = await getItems(DEFAULT_SCHOOL, 'settings');
        const settings = items[0] || {};
        res.json({ schoolName: settings.schoolName, schoolCode: settings.schoolCode });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─── ERROR HANDLER ───────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: `Route ${req.method} ${req.url} not found` }));
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
});

// ─── START ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`🚀 RHS PRMS Backend running on port ${PORT}`);
    console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
});

module.exports = app;
