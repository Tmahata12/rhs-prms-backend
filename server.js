// ==================== RHS PRMS BACKEND SERVER ====================
// Node.js + Express + MongoDB backend for RHS PRMS

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'rhs-prms-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// MongoDB Connection
const MONGO_URL = 'mongodb+srv://tmahata0100_db_user:sjI4p9mBZucFQ7kY@cluster0.jbqjbsg.mongodb.net/rhs_prms?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {
    console.log('✅ Connected to MongoDB successfully!');
    console.log('📊 Database: rhs_prms');
})
.catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
});

// ==================== MONGOOSE SCHEMAS ====================

// User Schema
const userSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    fullName: { type: String, required: true },
    role: { type: String, enum: ['admin', 'teacher', 'office'], required: true },
    email: String,
    phone: String,
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    lastLogin: Date,
    createdAt: { type: Date, default: Date.now }
});

// Teacher Schema
const teacherSchema = new mongoose.Schema({
    teacherId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    email: String,
    phone: String,
    subjects: [String],
    qualification: String,
    experience: Number,
    joiningDate: Date,
    address: String,
    createdAt: { type: Date, default: Date.now }
});

// Subject Schema
const subjectSchema = new mongoose.Schema({
    subjectId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    code: String,
    type: String,
    createdAt: { type: Date, default: Date.now }
});

// Class Schema
const classSchema = new mongoose.Schema({
    classId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    section: String,
    classTeacher: String,
    strength: Number,
    createdAt: { type: Date, default: Date.now }
});

// Period Schema
const periodSchema = new mongoose.Schema({
    periodId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    startTime: String,
    endTime: String,
    duration: Number,
    order: Number,
    createdAt: { type: Date, default: Date.now }
});

// Routine Schema
const routineSchema = new mongoose.Schema({
    routineId: { type: String, required: true, unique: true },
    class: { type: String, required: true },
    day: { type: String, required: true },
    period: { type: String, required: true },
    subject: { type: String, required: true },
    teacher: { type: String, required: true },
    room: String,
    generatedBy: String,
    createdAt: { type: Date, default: Date.now }
});

// Provisional Routine Schema
const provisionalSchema = new mongoose.Schema({
    provisionalId: { type: String, required: true, unique: true },
    date: { type: Date, required: true },
    class: { type: String, required: true },
    period: { type: String, required: true },
    day: String,
    originalTeacher: { type: String, required: true },
    substituteTeacher: { type: String, required: true },
    subject: String,
    reason: String,
    assignedBy: String,
    createdAt: { type: Date, default: Date.now }
});

// Settings Schema
const settingsSchema = new mongoose.Schema({
    schoolName: String,
    schoolCode: String,
    academicYear: String,
    sessionStart: Date,
    sessionEnd: Date,
    workingDays: [String],
    periodsPerDay: Number,
    periodDuration: Number,
    breakDuration: Number,
    schoolStartTime: String,
    lunchBreak: String,
    schoolEndTime: String,
    autoBackup: Boolean,
    backupInterval: String,
    theme: String,
    notifications: Boolean,
    updatedAt: { type: Date, default: Date.now }
});

// Create Models
const User = mongoose.model('User', userSchema);
const Teacher = mongoose.model('Teacher', teacherSchema);
const Subject = mongoose.model('Subject', subjectSchema);
const Class = mongoose.model('Class', classSchema);
const Period = mongoose.model('Period', periodSchema);
const Routine = mongoose.model('Routine', routineSchema);
const Provisional = mongoose.model('Provisional', provisionalSchema);
const Settings = mongoose.model('Settings', settingsSchema);

// ==================== MIDDLEWARE ====================

// Authentication Middleware
const authenticate = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Admin-only Middleware
const adminOnly = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// ==================== ROUTES ====================

// Health Check
app.get('/', (req, res) => {
    res.json({
        status: 'running',
        message: '🎓 RHS PRMS Backend Server',
        version: '1.0.0',
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// ==================== AUTH ROUTES ====================

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password, role } = req.body;
        
        const user = await User.findOne({ username });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        if (user.role !== role) {
            return res.status(401).json({ error: 'Invalid role' });
        }
        
        if (user.status !== 'active') {
            return res.status(401).json({ error: 'Account is inactive' });
        }
        
        // Update last login
        user.lastLogin = new Date();
        await user.save();
        
        // Generate token
        const token = jwt.sign(
            { userId: user.userId, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '8h' }
        );
        
        res.json({
            success: true,
            token,
            user: {
                userId: user.userId,
                username: user.username,
                fullName: user.fullName,
                role: user.role,
                email: user.email
            }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Initialize Default Admin
app.post('/api/auth/initialize', async (req, res) => {
    try {
        const adminExists = await User.findOne({ role: 'admin' });
        
        if (adminExists) {
            return res.json({ message: 'Admin already exists' });
        }
        
        const hashedPassword = await bcrypt.hash('admin123', 10);
        
        const defaultUsers = [
            {
                userId: 'user_admin_001',
                username: 'admin',
                password: hashedPassword,
                fullName: 'AHM RHS',
                role: 'admin',
                email: 'admin@rhs.school',
                phone: '9876543210',
                status: 'active'
            },
            {
                userId: 'user_teacher_001',
                username: 'teacher',
                password: await bcrypt.hash('teacher123', 10),
                fullName: 'Sample Teacher',
                role: 'teacher',
                email: 'teacher@rhs.school',
                phone: '9876543211',
                status: 'active'
            },
            {
                userId: 'user_office_001',
                username: 'office',
                password: await bcrypt.hash('office123', 10),
                fullName: 'Office Staff',
                role: 'office',
                email: 'office@rhs.school',
                phone: '9876543212',
                status: 'active'
            }
        ];
        
        await User.insertMany(defaultUsers);
        
        res.json({ success: true, message: 'Default users created' });
        
    } catch (error) {
        console.error('Initialize error:', error);
        res.status(500).json({ error: 'Initialization failed' });
    }
});

// ==================== USER ROUTES ====================

// Get all users (Admin only)
app.get('/api/users', authenticate, adminOnly, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Create user (Admin only)
app.post('/api/users', authenticate, adminOnly, async (req, res) => {
    try {
        const { username, password, fullName, role, email, phone } = req.body;
        
        const exists = await User.findOne({ username });
        if (exists) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const user = new User({
            userId: 'user_' + Date.now(),
            username,
            password: hashedPassword,
            fullName,
            role,
            email,
            phone,
            status: 'active'
        });
        
        await user.save();
        
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.status(201).json(userResponse);
        
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

// Update user (Admin only)
app.put('/api/users/:userId', authenticate, adminOnly, async (req, res) => {
    try {
        const { fullName, role, email, phone, status } = req.body;
        
        const user = await User.findOne({ userId: req.params.userId });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        user.fullName = fullName || user.fullName;
        user.role = role || user.role;
        user.email = email || user.email;
        user.phone = phone || user.phone;
        user.status = status || user.status;
        
        await user.save();
        
        const userResponse = user.toObject();
        delete userResponse.password;
        
        res.json(userResponse);
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// Delete user (Admin only)
app.delete('/api/users/:userId', authenticate, adminOnly, async (req, res) => {
    try {
        const user = await User.findOne({ userId: req.params.userId });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (user.username === 'admin') {
            return res.status(400).json({ error: 'Cannot delete admin user' });
        }
        
        await User.deleteOne({ userId: req.params.userId });
        
        res.json({ success: true, message: 'User deleted' });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// ==================== TEACHER ROUTES ====================

app.get('/api/teachers', authenticate, async (req, res) => {
    try {
        const teachers = await Teacher.find();
        res.json(teachers);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch teachers' });
    }
});

app.post('/api/teachers', authenticate, async (req, res) => {
    try {
        const teacher = new Teacher({
            teacherId: 'teacher_' + Date.now(),
            ...req.body
        });
        await teacher.save();
        res.status(201).json(teacher);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create teacher' });
    }
});

app.put('/api/teachers/:teacherId', authenticate, async (req, res) => {
    try {
        const teacher = await Teacher.findOneAndUpdate(
            { teacherId: req.params.teacherId },
            req.body,
            { new: true }
        );
        res.json(teacher);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update teacher' });
    }
});

app.delete('/api/teachers/:teacherId', authenticate, async (req, res) => {
    try {
        await Teacher.deleteOne({ teacherId: req.params.teacherId });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete teacher' });
    }
});

// ==================== SUBJECT ROUTES ====================

app.get('/api/subjects', authenticate, async (req, res) => {
    try {
        const subjects = await Subject.find();
        res.json(subjects);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch subjects' });
    }
});

app.post('/api/subjects', authenticate, async (req, res) => {
    try {
        const subject = new Subject({
            subjectId: 'subject_' + Date.now(),
            ...req.body
        });
        await subject.save();
        res.status(201).json(subject);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create subject' });
    }
});

// ==================== CLASS ROUTES ====================

app.get('/api/classes', authenticate, async (req, res) => {
    try {
        const classes = await Class.find();
        res.json(classes);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch classes' });
    }
});

app.post('/api/classes', authenticate, async (req, res) => {
    try {
        const classData = new Class({
            classId: 'class_' + Date.now(),
            ...req.body
        });
        await classData.save();
        res.status(201).json(classData);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create class' });
    }
});

// ==================== PERIOD ROUTES ====================

app.get('/api/periods', authenticate, async (req, res) => {
    try {
        const periods = await Period.find().sort({ order: 1 });
        res.json(periods);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch periods' });
    }
});

app.post('/api/periods', authenticate, async (req, res) => {
    try {
        const period = new Period({
            periodId: 'period_' + Date.now(),
            ...req.body
        });
        await period.save();
        res.status(201).json(period);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create period' });
    }
});

// ==================== ROUTINE ROUTES ====================

app.get('/api/routines', authenticate, async (req, res) => {
    try {
        const routines = await Routine.find();
        res.json(routines);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch routines' });
    }
});

app.post('/api/routines', authenticate, async (req, res) => {
    try {
        const routine = new Routine({
            routineId: 'routine_' + Date.now(),
            ...req.body
        });
        await routine.save();
        res.status(201).json(routine);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create routine' });
    }
});

app.post('/api/routines/bulk', authenticate, async (req, res) => {
    try {
        const routines = req.body.map(r => ({
            routineId: r.id || 'routine_' + Date.now() + '_' + Math.random(),
            ...r
        }));
        await Routine.insertMany(routines);
        res.status(201).json({ success: true, count: routines.length });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create routines' });
    }
});

app.delete('/api/routines/:routineId', authenticate, async (req, res) => {
    try {
        await Routine.deleteOne({ routineId: req.params.routineId });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete routine' });
    }
});

// ==================== PROVISIONAL ROUTES ====================

app.get('/api/provisionals', authenticate, async (req, res) => {
    try {
        const provisionals = await Provisional.find();
        res.json(provisionals);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch provisionals' });
    }
});

app.post('/api/provisionals', authenticate, async (req, res) => {
    try {
        const provisional = new Provisional({
            provisionalId: 'prov_' + Date.now(),
            ...req.body
        });
        await provisional.save();
        res.status(201).json(provisional);
    } catch (error) {
        res.status(500).json({ error: 'Failed to create provisional' });
    }
});

// ==================== SETTINGS ROUTES ====================

app.get('/api/settings', authenticate, async (req, res) => {
    try {
        let settings = await Settings.findOne();
        
        if (!settings) {
            settings = new Settings({
                schoolName: 'Ramnagar High School (H.S.)',
                schoolCode: '19090310603',
                academicYear: '2025-26',
                workingDays: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'],
                periodsPerDay: 7,
                periodDuration: 45,
                breakDuration: 10,
                schoolStartTime: '10:00',
                lunchBreak: '13:00-13:45',
                schoolEndTime: '16:00',
                autoBackup: true,
                backupInterval: 'daily',
                theme: 'light',
                notifications: true
            });
            await settings.save();
        }
        
        res.json(settings);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

app.put('/api/settings', authenticate, adminOnly, async (req, res) => {
    try {
        let settings = await Settings.findOne();
        
        if (!settings) {
            settings = new Settings(req.body);
        } else {
            Object.assign(settings, req.body);
            settings.updatedAt = new Date();
        }
        
        await settings.save();
        res.json(settings);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

// ==================== GENERIC CRUD ROUTES ====================

// Generic GET for any collection
app.get('/api/data/:collection', authenticate, async (req, res) => {
    try {
        const collection = req.params.collection;
        const Model = mongoose.model(collection.charAt(0).toUpperCase() + collection.slice(1, -1));
        const data = await Model.find();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch data' });
    }
});

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
    console.log('');
    console.log('╔══════════════════════════════════════════════╗');
    console.log('║  🎓 RHS PRMS Backend Server Running         ║');
    console.log('╠══════════════════════════════════════════════╣');
    console.log(`║  📡 Port: ${PORT}                              ║`);
    console.log(`║  🗄️  Database: MongoDB Atlas                 ║`);
    console.log('║  ✅ Status: Active                           ║');
    console.log('╚══════════════════════════════════════════════╝');
    console.log('');
});
