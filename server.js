const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

// ============== إعداد التطبيق ==============
const app = express();
const PORT = process.env.PORT || 3000;

// ============== إعداد الأمان ==============
app.use(helmet());

// CORS - يسمح للنطاقات التالية فقط
const allowedOrigins = ['http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// Rate Limiting - لمنع الهجمات
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 100, // 100 طلب كحد أقصى
  message: {
    success: false,
    message: 'Too many requests, please try again later.'
  }
});
app.use('/api/', limiter);

// Body Parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ============== قاعدة البيانات ==============
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/calmai';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// ============== النماذج (Models) ==============

// 1. نموذج المستخدم
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    minlength: 3
  },
  gender: {
    type: String,
    enum: ['male', 'female', 'other'],
    default: 'male'
  },
  birthYear: {
    type: Number,
    required: true,
    min: 1900,
    max: new Date().getFullYear() - 13
  },
  country: {
    type: String,
    default: 'SA'
  },
  plan: {
    type: String,
    enum: ['free', 'pro', 'enterprise'],
    default: 'free'
  },
  messagesUsed: {
    type: Number,
    default: 0
  },
  adsWatched: {
    type: Number,
    default: 0
  },
  totalMessages: {
    type: Number,
    default: 0
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  isBanned: {
    type: Boolean,
    default: false
  },
  language: {
    type: String,
    enum: ['ar', 'en'],
    default: 'ar'
  },
  lastLogin: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// تشفير كلمة المرور قبل الحفظ
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// مقارنة كلمة المرور
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// التحقق إذا كان يمكن إرسال رسالة
userSchema.methods.canSendMessage = function() {
  if (this.plan === 'free') {
    return this.messagesUsed < 20;
  }
  return true;
};

const User = mongoose.model('User', userSchema);

// 2. نموذج الجلسات
const sessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  token: {
    type: String,
    required: true,
    unique: true
  },
  deviceInfo: {
    userAgent: String,
    ip: String
  },
  expiresAt: {
    type: Date,
    required: true
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastActivity: {
    type: Date,
    default: Date.now
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Session = mongoose.model('Session', sessionSchema);

// 3. نموذج الإعلانات
const adSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: String,
  imageUrl: {
    type: String,
    required: true
  },
  link: {
    type: String,
    required: true
  },
  targetCountries: [String],
  targetPlans: [String],
  impressions: {
    type: Number,
    default: 0
  },
  clicks: {
    type: Number,
    default: 0
  },
  isActive: {
    type: Boolean,
    default: true
  },
  priority: {
    type: Number,
    default: 1,
    min: 1,
    max: 10
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Ad = mongoose.model('Ad', adSchema);

// 4. نموذج المحتوى
const contentSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: ['music', 'exercise', 'game']
  },
  title: {
    type: String,
    required: true
  },
  description: String,
  url: String,
  duration: Number,
  category: String,
  language: {
    type: String,
    enum: ['ar', 'en', 'both'],
    default: 'both'
  },
  isPremium: {
    type: Boolean,
    default: false
  },
  requiredPlan: {
    type: String,
    enum: ['free', 'pro', 'enterprise', 'all'],
    default: 'all'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  views: {
    type: Number,
    default: 0
  },
  likes: {
    type: Number,
    default: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Content = mongoose.model('Content', contentSchema);

// 5. نموذج النشاطات
const activitySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    required: true,
    enum: ['login', 'logout', 'signup', 'message_sent', 'ad_clicked', 'ad_watched', 'content_viewed']
  },
  targetType: String,
  targetId: mongoose.Schema.Types.ObjectId,
  data: mongoose.Schema.Types.Mixed,
  ip: String,
  userAgent: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Activity = mongoose.model('Activity', activitySchema);

// ============== الـ Middlewares ==============

// مصادقة المستخدم
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.'
      });
    }
    
    const token = authHeader.split(' ')[1];
    
    // التحقق من التوكن
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    
    // التحقق من الجلسة
    const session = await Session.findOne({
      token,
      userId: decoded.userId,
      isActive: true,
      expiresAt: { $gt: new Date() }
    });
    
    if (!session) {
      return res.status(401).json({
        success: false,
        message: 'Session expired or invalid.'
      });
    }
    
    // تحديث آخر نشاط
    session.lastActivity = new Date();
    await session.save();
    
    // جلب المستخدم
    const user = await User.findById(decoded.userId);
    
    if (!user || user.isBanned || !user.isActive) {
      return res.status(403).json({
        success: false,
        message: 'Account is not active or banned.'
      });
    }
    
    // إضافة المستخدم للطلب
    req.user = user;
    req.session = session;
    req.token = token;
    
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token.'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expired. Please login again.'
      });
    }
    
    return res.status(500).json({
      success: false,
      message: 'Authentication error.'
    });
  }
};

// مصادقة الأدمن
const adminMiddleware = async (req, res, next) => {
  // تحقق إذا كان المستخدم أدمن (هنا نتحقق من الإيميل)
  const adminEmails = ['admin@calmai.com', 'test@calmai.com'];
  
  if (!adminEmails.includes(req.user.email)) {
    return res.status(403).json({
      success: false,
      message: 'Access denied. Admin privileges required.'
    });
  }
  
  next();
};

// معالج الأخطاء
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);
  
  let statusCode = 500;
  let message = 'Internal Server Error';
  
  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = 'Validation Error';
  } else if (err.name === 'CastError') {
    statusCode = 400;
    message = 'Invalid ID format';
  } else if (err.code === 11000) {
    statusCode = 409;
    message = 'Duplicate field value entered';
  }
  
  res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV === 'development' && { error: err.message })
  });
};

// ============== الدوال المساعدة ==============

// توليد توكن
const generateToken = (userId, email, plan) => {
  return jwt.sign(
    { userId, email, plan },
    process.env.JWT_SECRET || 'your-secret-key',
    { expiresIn: '7d' }
  );
};

// رد API موحد
const apiResponse = (success, message, data = null) => {
  return {
    success,
    message,
    data,
    timestamp: new Date().toISOString()
  };
};

// توليد كود تحقق
const generateVerificationCode = () => {
  const digits = '0123456789';
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += digits[Math.floor(Math.random() * 10)];
  }
  return code;
};

// ============== المسارات (Routes) ==============

// 1. مسارات المصادقة
app.post('/api/auth/signup', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('firstName').notEmpty().trim(),
  body('lastName').notEmpty().trim(),
  body('username').isLength({ min: 3 }),
  body('birthYear').isInt({ min: 1900, max: new Date().getFullYear() - 13 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(apiResponse(false, 'Validation failed', { errors: errors.array() }));
    }
    
    const { email, password, firstName, lastName, username, birthYear, gender, country, language } = req.body;
    
    // التحقق من وجود المستخدم
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      const field = existingUser.email === email ? 'email' : 'username';
      return res.status(409).json(apiResponse(false, `${field} already exists`));
    }
    
    // إنشاء المستخدم
    const user = new User({
      email,
      password,
      firstName,
      lastName,
      username,
      birthYear,
      gender: gender || 'male',
      country: country || 'SA',
      language: language || 'ar'
    });
    
    await user.save();
    
    // إنشاء توكن
    const token = generateToken(user._id, user.email, user.plan);
    
    // إنشاء جلسة
    const session = new Session({
      userId: user._id,
      token,
      deviceInfo: {
        userAgent: req.headers['user-agent'],
        ip: req.ip
      },
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 أيام
    });
    
    await session.save();
    
    // تسجيل النشاط
    const activity = new Activity({
      userId: user._id,
      type: 'signup',
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    await activity.save();
    
    res.status(201).json(apiResponse(true, 'Account created successfully', {
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.username,
        plan: user.plan
      }
    }));
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json(apiResponse(false, 'Error creating account'));
  }
});

app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(apiResponse(false, 'Validation failed'));
    }
    
    const { email, password } = req.body;
    
    // البحث عن المستخدم
    const user = await User.findOne({ email }).select('+password');
    
    if (!user) {
      return res.status(401).json(apiResponse(false, 'Invalid email or password'));
    }
    
    // التحقق من حالة الحساب
    if (user.isBanned) {
      return res.status(403).json(apiResponse(false, 'Account is banned'));
    }
    
    if (!user.isActive) {
      return res.status(403).json(apiResponse(false, 'Account is deactivated'));
    }
    
    // التحقق من كلمة المرور
    const isPasswordValid = await user.comparePassword(password);
    
    if (!isPasswordValid) {
      return res.status(401).json(apiResponse(false, 'Invalid email or password'));
    }
    
    // إنشاء توكن جديد
    const token = generateToken(user._id, user.email, user.plan);
    
    // إنشاء جلسة جديدة
    const session = new Session({
      userId: user._id,
      token,
      deviceInfo: {
        userAgent: req.headers['user-agent'],
        ip: req.ip
      },
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 أيام
    });
    
    await session.save();
    
    // تحديث آخر تسجيل دخول
    user.lastLogin = new Date();
    await user.save();
    
    // تسجيل النشاط
    const activity = new Activity({
      userId: user._id,
      type: 'login',
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    await activity.save();
    
    res.json(apiResponse(true, 'Login successful', {
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.username,
        plan: user.plan,
        language: user.language,
        messagesUsed: user.messagesUsed,
        adsWatched: user.adsWatched
      }
    }));
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json(apiResponse(false, 'Error logging in'));
  }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  try {
    // إلغاء تنشيط الجلسة
    req.session.isActive = false;
    await req.session.save();
    
    // تسجيل النشاط
    const activity = new Activity({
      userId: req.user._id,
      type: 'logout',
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    await activity.save();
    
    res.json(apiResponse(true, 'Logged out successfully'));
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json(apiResponse(false, 'Error logging out'));
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    res.json(apiResponse(true, 'User data retrieved', {
      user: {
        id: req.user._id,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        username: req.user.username,
        gender: req.user.gender,
        birthYear: req.user.birthYear,
        country: req.user.country,
        plan: req.user.plan,
        language: req.user.language,
        messagesUsed: req.user.messagesUsed,
        adsWatched: req.user.adsWatched,
        totalMessages: req.user.totalMessages,
        isVerified: req.user.isVerified,
        createdAt: req.user.createdAt,
        lastLogin: req.user.lastLogin
      }
    }));
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json(apiResponse(false, 'Error getting user data'));
  }
});

// 2. مسارات المستخدم
app.get('/api/users/profile', authMiddleware, async (req, res) => {
  try {
    res.json(apiResponse(true, 'Profile retrieved', {
      user: req.user
    }));
  } catch (error) {
    res.status(500).json(apiResponse(false, 'Error getting profile'));
  }
});

app.get('/api/users/stats', authMiddleware, async (req, res) => {
  try {
    const stats = {
      messagesUsed: req.user.messagesUsed,
      adsWatched: req.user.adsWatched,
      totalMessages: req.user.totalMessages,
      messagesLimit: req.user.plan === 'free' ? 20 : 'Unlimited',
      adsNeededForUpgrade: Math.max(0, 50 - req.user.adsWatched),
      daysActive: Math.floor((new Date() - req.user.createdAt) / (1000 * 60 * 60 * 24))
    };
    
    res.json(apiResponse(true, 'Stats retrieved', { stats }));
  } catch (error) {
    res.status(500).json(apiResponse(false, 'Error getting stats'));
  }
});

app.get('/api/users/can-send-message', authMiddleware, async (req, res) => {
  try {
    const canSend = req.user.canSendMessage();
    
    res.json(apiResponse(true, 'Message limit checked', {
      canSend,
      messagesUsed: req.user.messagesUsed,
      messagesLimit: req.user.plan === 'free' ? 20 : 'Unlimited',
      remaining: req.user.plan === 'free' ? Math.max(0, 20 - req.user.messagesUsed) : 'Unlimited'
    }));
  } catch (error) {
    res.status(500).json(apiResponse(false, 'Error checking message limit'));
  }
});

app.post('/api/users/increment-message', authMiddleware, async (req, res) => {
  try {
    req.user.messagesUsed += 1;
    req.user.totalMessages += 1;
    await req.user.save();
    
    // تسجيل النشاط
    const activity = new Activity({
      userId: req.user._id,
      type: 'message_sent',
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    await activity.save();
    
    res.json(apiResponse(true, 'Message count incremented', {
      messagesUsed: req.user.messagesUsed
    }));
  } catch (error) {
    res.status(500).json(apiResponse(false, 'Error incrementing message count'));
  }
});

app.post('/api/users/watch-ad', authMiddleware, async (req, res) => {
  try {
    req.user.adsWatched += 1;
    await req.user.save();
    
    // تسجيل النشاط
    const activity = new Activity({
      userId: req.user._id,
      type: 'ad_watched',
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    await activity.save();
    
    res.json(apiResponse(true, 'Ad watched', {
      adsWatched: req.user.adsWatched,
      adsNeededForUpgrade: Math.max(0, 50 - req.user.adsWatched)
    }));
  } catch (error) {
    res.status(500).json(apiResponse(false, 'Error recording ad watch'));
  }
});

// 3. مسارات الإعلانات
app.get('/api/ads', authMiddleware, async (req, res) => {
  try {
    // الحصول على إعلانات تناسب المستخدم
    const ads = await Ad.find({
      isActive: true,
      $or: [
        { targetCountries: { $size: 0 } },
        { targetCountries: req.user.country }
      ],
      $or: [
        { targetPlans: { $size: 0 } },
        { targetPlans: req.user.plan }
      ]
    })
    .sort({ priority: -1, createdAt: -1 })
    .limit(10);
    
    // زيادة عدد المشاهدات
    ads.forEach(ad => {
      ad.impressions += 1;
      ad.save();
    });
    
    res.json(apiResponse(true, 'Ads retrieved', { ads }));
  } catch (error) {
    console.error('Get ads error:', error);
    res.status(500).json(apiResponse(false, 'Error getting ads'));
  }
});

app.post('/api/ads/:id/click', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    
    const ad = await Ad.findById(id);
    
    if (!ad) {
      return res.status(404).json(apiResponse(false, 'Ad not found'));
    }
    
    if (!ad.isActive) {
      return res.status(400).json(apiResponse(false, 'Ad is not active'));
    }
    
    // زيادة النقرات
    ad.clicks += 1;
    await ad.save();
    
    // زيادة عدد إعلانات المستخدم
    req.user.adsWatched += 1;
    await req.user.save();
    
    // تسجيل النشاط
    const activity = new Activity({
      userId: req.user._id,
      type: 'ad_clicked',
      targetType: 'ad',
      targetId: ad._id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      data: {
        adTitle: ad.title,
        adLink: ad.link
      }
    });
    
    await activity.save();
    
    res.json(apiResponse(true, 'Ad click recorded', {
      redirectUrl: ad.link,
      adId: ad._id
    }));
  } catch (error) {
    console.error('Click ad error:', error);
    res.status(500).json(apiResponse(false, 'Error recording ad click'));
  }
});

// 4. مسارات المحتوى
app.get('/api/content', authMiddleware, async (req, res) => {
  try {
    const { type, category, language = req.user.language } = req.query;
    
    let query = { isActive: true };
    
    if (type) query.type = type;
    if (category) query.category = category;
    
    // فلترة اللغة
    query.$or = [
      { language: 'both' },
      { language: language }
    ];
    
    // التحقق من صلاحية المحتوى حسب الخطة
    if (req.user.plan === 'free') {
      query.isPremium = false;
      query.requiredPlan = { $in: ['free', 'all'] };
    } else if (req.user.plan === 'pro') {
      query.requiredPlan = { $in: ['free', 'pro', 'all'] };
    }
    
    const content = await Content.find(query)
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json(apiResponse(true, 'Content retrieved', { content }));
  } catch (error) {
    console.error('Get content error:', error);
    res.status(500).json(apiResponse(false, 'Error getting content'));
  }
});

app.get('/api/content/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    
    const content = await Content.findById(id);
    
    if (!content) {
      return res.status(404).json(apiResponse(false, 'Content not found'));
    }
    
    if (!content.isActive) {
      return res.status(404).json(apiResponse(false, 'Content is not available'));
    }
    
    // التحقق من صلاحية المحتوى
    if (content.requiredPlan !== 'all') {
      if (req.user.plan === 'free' && content.requiredPlan !== 'free') {
        return res.status(403).json(apiResponse(false, 'Upgrade your plan to access this content'));
      }
      if (req.user.plan === 'pro' && content.requiredPlan === 'enterprise') {
        return res.status(403).json(apiResponse(false, 'Enterprise plan required'));
      }
    }
    
    // زيادة المشاهدات
    content.views += 1;
    await content.save();
    
    // تسجيل النشاط
    const activity = new Activity({
      userId: req.user._id,
      type: 'content_viewed',
      targetType: 'content',
      targetId: content._id,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      data: {
        contentType: content.type,
        title: content.title
      }
    });
    
    await activity.save();
    
    res.json(apiResponse(true, 'Content retrieved', { content }));
  } catch (error) {
    console.error('Get content by id error:', error);
    res.status(500).json(apiResponse(false, 'Error getting content'));
  }
});

app.post('/api/content/:id/like', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    
    const content = await Content.findById(id);
    
    if (!content) {
      return res.status(404).json(apiResponse(false, 'Content not found'));
    }
    
    content.likes += 1;
    await content.save();
    
    res.json(apiResponse(true, 'Content liked', {
      likes: content.likes
    }));
  } catch (error) {
    console.error('Like content error:', error);
    res.status(500).json(apiResponse(false, 'Error liking content'));
  }
});

// 5. مسارات الأدمن
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { page = 1, limit = 20, plan, search } = req.query;
    
    let query = {};
    
    if (plan) query.plan = plan;
    
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { username: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ];
    }
    
    const users = await User.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .select('-password');
    
    const total = await User.countDocuments(query);
    
    res.json(apiResponse(true, 'Users retrieved', {
      users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    }));
  } catch (error) {
    console.error('Get admin users error:', error);
    res.status(500).json(apiResponse(false, 'Error getting users'));
  }
});

app.get('/api/admin/ads', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const ads = await Ad.find().sort({ createdAt: -1 });
    res.json(apiResponse(true, 'Ads retrieved', { ads }));
  } catch (error) {
    console.error('Get admin ads error:', error);
    res.status(500).json(apiResponse(false, 'Error getting ads'));
  }
});

app.post('/api/admin/ads', authMiddleware, adminMiddleware, [
  body('title').notEmpty(),
  body('imageUrl').notEmpty(),
  body('link').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(apiResponse(false, 'Validation failed'));
    }
    
    const adData = req.body;
    adData.advertiserId = req.user._id;
    adData.advertiserName = req.user.username;
    
    const ad = new Ad(adData);
    await ad.save();
    
    res.status(201).json(apiResponse(true, 'Ad created', { ad }));
  } catch (error) {
    console.error('Create ad error:', error);
    res.status(500).json(apiResponse(false, 'Error creating ad'));
  }
});

app.get('/api/admin/content', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const content = await Content.find().sort({ createdAt: -1 });
    res.json(apiResponse(true, 'Content retrieved', { content }));
  } catch (error) {
    console.error('Get admin content error:', error);
    res.status(500).json(apiResponse(false, 'Error getting content'));
  }
});

app.post('/api/admin/content', authMiddleware, adminMiddleware, [
  body('type').isIn(['music', 'exercise', 'game']),
  body('title').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(apiResponse(false, 'Validation failed'));
    }
    
    const content = new Content(req.body);
    await content.save();
    
    res.status(201).json(apiResponse(true, 'Content created', { content }));
  } catch (error) {
    console.error('Create content error:', error);
    res.status(500).json(apiResponse(false, 'Error creating content'));
  }
});

// 6. مسارات الإحصائيات
app.get('/api/metrics/basic', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ 
      lastLogin: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } 
    });
    const totalAds = await Ad.countDocuments({ isActive: true });
    const totalContent = await Content.countDocuments({ isActive: true });
    
    res.json(apiResponse(true, 'Basic metrics retrieved', {
      metrics: {
        totalUsers,
        activeUsers,
        totalAds,
        totalContent
      }
    }));
  } catch (error) {
    console.error('Get metrics error:', error);
    res.status(500).json(apiResponse(false, 'Error getting metrics'));
  }
});

// 7. مسارات الخدمة
app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// 8. تهيئة البيانات الأولية
app.post('/api/init', async (req, res) => {
  try {
    // إنشاء أدمن افتراضي
    const adminUser = await User.findOne({ email: 'admin@calmai.com' });
    
    if (!adminUser) {
      const admin = new User({
        email: 'admin@calmai.com',
        password: 'Admin123!',
        firstName: 'Admin',
        lastName: 'User',
        username: 'admin',
        birthYear: 1990,
        gender: 'male',
        country: 'SA',
        plan: 'enterprise',
        language: 'ar'
      });
      
      await admin.save();
      console.log('✅ Admin user created');
    }
    
    // إنشاء إعلانات تجريبية
    const adCount = await Ad.countDocuments();
    
    if (adCount === 0) {
      const sampleAds = [
        {
          title: 'عروض خاصة على الاشتراكات',
          description: 'احصل على خصم 50% على الاشتراك السنوي',
          imageUrl: 'https://via.placeholder.com/300x200/5d8aa8/ffffff?text=CalmAI+Ad',
          link: 'https://calmai.com/pricing',
          targetCountries: ['SA', 'AE', 'EG'],
          targetPlans: ['free'],
          priority: 5
        },
        {
          title: 'جلسات تأمل مجانية',
          description: 'انضم إلى جلسات التأمل المجانية الأسبوعية',
          imageUrl: 'https://via.placeholder.com/300x200/7bcfa9/ffffff?text=Meditation',
          link: 'https://calmai.com/meditation',
          targetCountries: [],
          targetPlans: [],
          priority: 3
        }
      ];
      
      await Ad.insertMany(sampleAds);
      console.log('✅ Sample ads created');
    }
    
    // إنشاء محتوى تجريبي
    const contentCount = await Content.countDocuments();
    
    if (contentCount === 0) {
      const sampleContent = [
        {
          type: 'music',
          title: 'موسيقى هادئة للاسترخاء',
          description: 'موسيقى هادئة تساعد على الاسترخاء والتأمل',
          category: 'relaxation',
          language: 'both',
          duration: 30,
          requiredPlan: 'free'
        },
        {
          type: 'exercise',
          title: 'تمرين التنفس العميق',
          description: 'تمرين بسيط للتنفس العميق لتخفيف التوتر',
          category: 'breathing',
          language: 'both',
          duration: 10,
          requiredPlan: 'free'
        },
        {
          type: 'game',
          title: 'لعبة التنفس الهادئ',
          description: 'لعبة تفاعلية لتعليم التنفس الصحيح',
          category: 'breathing',
          language: 'both',
          duration: 15,
          requiredPlan: 'free'
        },
        {
          type: 'music',
          title: 'موسيقى النوم العميق',
          description: 'موسيقى مخصصة للنوم العميق والهادئ',
          category: 'sleep',
          language: 'both',
          duration: 60,
          requiredPlan: 'pro',
          isPremium: true
        }
      ];
      
      await Content.insertMany(sampleContent);
      console.log('✅ Sample content created');
    }
    
    res.json(apiResponse(true, 'Initialization completed', {
      adminCreated: !adminUser,
      adsCreated: adCount === 0,
      contentCreated: contentCount === 0
    }));
  } catch (error) {
    console.error('Init error:', error);
    res.status(500).json(apiResponse(false, 'Error during initialization'));
  }
});

// ============== معالج الأخطاء ==============
app.use(errorHandler);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// ============== بدء السيرفر ==============
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
  console.log(`📁 API Base URL: http://localhost:${PORT}/api`);
  console.log(`👤 Admin email: admin@calmai.com`);
  console.log(`🔑 Admin password: Admin123!`);
});
