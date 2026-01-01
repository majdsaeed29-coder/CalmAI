const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');
require('dotenv').config();

// إعداد Express
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // يخدم الملفات من نفس المجلد

// قاعدة البيانات SQLite
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: './database/calmai.db',
    logging: false
});

// تعريف Models
const User = sequelize.define('User', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    username: {
        type: DataTypes.STRING,
        unique: true
    },
    email: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    first_name: DataTypes.STRING,
    last_name: DataTypes.STRING,
    gender: DataTypes.STRING,
    birth_year: DataTypes.INTEGER,
    user_id: {
        type: DataTypes.STRING,
        unique: true,
        defaultValue: () => `CAI-${Date.now().toString().slice(-6)}`
    },
    subscription_type: {
        type: DataTypes.STRING,
        defaultValue: 'free'
    },
    is_active: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
    },
    is_verified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    }
});

const Admin = sequelize.define('Admin', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    username: DataTypes.STRING,
    password: DataTypes.STRING,
    email: DataTypes.STRING
});

const ChatSession = sequelize.define('ChatSession', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    user_id: DataTypes.INTEGER,
    messages: {
        type: DataTypes.TEXT,
        get() {
            const raw = this.getDataValue('messages');
            return raw ? JSON.parse(raw) : [];
        },
        set(value) {
            this.setDataValue('messages', JSON.stringify(value));
        }
    }
});

// ربط الجداول
User.hasMany(ChatSession, { foreignKey: 'user_id' });
ChatSession.belongsTo(User, { foreignKey: 'user_id' });

// تهيئة قاعدة البيانات
async function initDatabase() {
    try {
        await sequelize.authenticate();
        await sequelize.sync({ force: false }); // لا تحذف البيانات الموجود
        
        // إنشاء أدمن إذا لم يكن موجود
        const adminCount = await Admin.count();
        if (adminCount === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await Admin.create({
                username: 'admin',
                password: hashedPassword,
                email: 'admin@calmai.com'
            });
            console.log('✅ Admin user created');
        }
        
        console.log('✅ Database connected & synced');
    } catch (error) {
        console.error('❌ Database error:', error);
    }
}

// ========== Routes ==========

// إرسال ملفات HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// ========== API Routes ==========

// تسجيل جديد
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, password, first_name, last_name, username, birth_year, gender } = req.body;
        
        // التحقق من البيانات
        if (!email || !password || !first_name) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing required fields' 
            });
        }
        
        // التحقق من البريد المكرر
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email already exists' 
            });
        }
        
        // تشفير كلمة المرور
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // إنشاء المستخدم
        const user = await User.create({
            email,
            password: hashedPassword,
            first_name,
            last_name: last_name || '',
            username: username || `${first_name.toLowerCase()}_${(last_name || 'user').toLowerCase()}`,
            birth_year: birth_year || 1990,
            gender: gender || 'male',
            user_id: `CAI-${Date.now().toString().slice(-6)}`,
            subscription_type: 'free'
        });
        
        // توليد التوكن
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET || 'calmai-secret-key-2024',
            { expiresIn: '7d' }
        );
        
        // نجاح التسجيل
        res.json({
            success: true,
            message: 'User registered successfully',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
                user_id: user.user_id
            },
            token: token
        });
        
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Server error during registration' 
        });
    }
});

// تسجيل دخول
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email and password required' 
            });
        }
        
        // البحث عن المستخدم
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid credentials' 
            });
        }
        
        // التحقق من كلمة المرور
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid credentials' 
            });
        }
        
        // التحقق من حالة الحساب
        if (!user.is_active) {
            return res.status(403).json({ 
                success: false, 
                error: 'Account is inactive' 
            });
        }
        
        // توليد التوكن
        const token = jwt.sign(
            { 
                userId: user.id, 
                email: user.email,
                subscription: user.subscription_type 
            },
            process.env.JWT_SECRET || 'calmai-secret-key-2024',
            { expiresIn: '7d' }
        );
        
        // تحديث آخر دخول
        await user.update({ last_login: new Date() });
        
        // إرسال النتيجة
        res.json({
            success: true,
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
                user_id: user.user_id,
                subscription_type: user.subscription_type
            },
            token: token
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Server error during login' 
        });
    }
});

// تسجيل دخول الأدمن
app.post('/api/auth/admin-login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const admin = await Admin.findOne({ where: { username } });
        if (!admin) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid credentials' 
            });
        }
        
        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid credentials' 
            });
        }
        
        const token = jwt.sign(
            { adminId: admin.id, username: admin.username },
            process.env.ADMIN_JWT_SECRET || 'calmai-admin-secret-2024',
            { expiresIn: '7d' }
        );
        
        res.json({
            success: true,
            message: 'Admin login successful',
            admin: {
                id: admin.id,
                username: admin.username,
                email: admin.email
            },
            token: token
        });
        
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Server error' 
        });
    }
});

// التحقق من التوكن
app.post('/api/auth/verify-token', (req, res) => {
    try {
        const token = req.body.token || req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.json({ valid: false, error: 'No token provided' });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'calmai-secret-key-2024');
        res.json({ valid: true, user: decoded });
        
    } catch (error) {
        res.json({ valid: false, error: 'Invalid token' });
    }
});

// AI Chat
app.post('/api/ai/chat', async (req, res) => {
    try {
        const { message, user_id } = req.body;
        
        // رد بسيط من AI (في الواقع تستخدم OpenAI API)
        const aiResponse = `Thank you for your message: "${message}". I'm here to support you. How are you feeling today?`;
        
        // حفظ المحادثة
        let session = await ChatSession.findOne({ where: { user_id } });
        if (!session) {
            session = await ChatSession.create({
                user_id,
                messages: []
            });
        }
        
        const messages = session.messages;
        messages.push({ role: 'user', content: message });
        messages.push({ role: 'assistant', content: aiResponse });
        
        await session.update({ messages });
        
        res.json({
            success: true,
            response: aiResponse,
            session_id: session.id
        });
        
    } catch (error) {
        console.error('Chat error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'AI service error' 
        });
    }
});

// جلب الإحصائيات
app.get('/api/stats', async (req, res) => {
    try {
        const totalUsers = await User.count();
        const activeUsers = await User.count({ where: { is_active: true } });
        const premiumUsers = await User.count({ where: { subscription_type: 'premium' } });
        
        res.json({
            success: true,
            stats: {
                total_users: totalUsers,
                active_users: activeUsers,
                premium_users: premiumUsers,
                total_chats: await ChatSession.count()
            }
        });
        
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to get stats' 
        });
    }
});

// الحصول على المستخدمين (للداشبورد)
app.get('/api/admin/users', async (req, res) => {
    try {
        const users = await User.findAll({
            attributes: ['id', 'username', 'email', 'first_name', 'last_name', 
                        'user_id', 'subscription_type', 'is_active', 'createdAt'],
            order: [['createdAt', 'DESC']],
            limit: 100
        });
        
        res.json({
            success: true,
            users: users,
            count: users.length
        });
        
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to get users' 
        });
    }
});

// إضافة محتوى جديد
app.post('/api/admin/content', async (req, res) => {
    try {
        const { type, title_en, title_ar, description_en, description_ar, url } = req.body;
        
        // هنا تضيف Content model إذا تحتاج
        res.json({
            success: true,
            message: 'Content added successfully'
        });
        
    } catch (error) {
        console.error('Add content error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to add content' 
        });
    }
});

// ========== تشغيل السيرفر ==========
async function startServer() {
    try {
        // تهيئة قاعدة البيانات
        await initDatabase();
        
        // تشغيل السيرفر
        app.listen(PORT, () => {
            console.log(`✅ Server running at: http://localhost:${PORT}`);
            console.log(`📁 HTML files served from: ${__dirname}`);
            console.log(`🔐 JWT Secret: ${process.env.JWT_SECRET ? 'Set' : 'Using default'}`);
        });
        
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

startServer();

// إغلاق نظيف
process.on('SIGTERM', () => {
    console.log('Shutting down...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('Shutting down...');
    process.exit(0);
});
