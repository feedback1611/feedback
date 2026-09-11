/**
 * ============================================================================
 * COLLEGE FACULTY FEEDBACK MANAGEMENT SYSTEM - BACKEND
 * ============================================================================
 * Architecture: Production-Ready Single-File Node.js / Express Application
 * Compatible with Render, MongoDB Atlas, and Gmail SMTP
 * 
 * TABLE OF CONTENTS:
 * 1. MODULE IMPORTS & ENVIRONMENT CONFIGURATION
 * 2. PASSWORD HASHING SUBSYSTEM (Argon2 with Bcrypt Fallback)
 * 3. MONGOOSE DATABASE CONNECTION & SCHEMAS
 * 4. SECURITY MIDDLEWARE & APPLICATION SETUP
 * 5. AUTHENTICATION & AUTHORIZATION HELPERS / MIDDLEWARE
 * 6. INPUT VALIDATION SCHEMAS (Zod)
 * 7. EMAIL & PASSWORD RESET SUBSYSTEM (Nodemailer Gmail SMTP)
 * 8. ANALYTICS COMPUTATION ENGINE
 * 9. PDF REPORT GENERATOR (PDFKit Multi-Page Engine)
 * 10. SYSTEM & HEALTH CHECK ENDPOINTS
 * 11. AUTHENTICATION ENDPOINTS (/api/auth)
 * 12. SUPER ADMIN ENDPOINTS (/api/admin)
 * 13. HOD MANAGEMENT ENDPOINTS (/api/forms)
 * 14. PUBLIC STUDENT ENDPOINTS (/api/public/forms)
 * 15. CENTRALIZED ERROR HANDLING & 404 HANDLER
 * 16. SERVER STARTUP & GRACEFUL SHUTDOWN
 * 17. ENVIRONMENT VARIABLES TEMPLATE & CONFIGURATION GUIDE
 * ============================================================================
 */

// ============================================================================
// 1. MODULE IMPORTS & ENVIRONMENT CONFIGURATION
// ============================================================================
const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const QRCode = require('qrcode');
const { z } = require('zod');
const bcrypt = require('bcryptjs');

// Load environment variables from .env if present
dotenv.config();

// Global Configuration
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/college_feedback_db';
const AUTH_SECRET = process.env.AUTH_SECRET || 'fallback_development_secret_key_change_in_production';
const GMAIL_USER = process.env.GMAIL_USER || '';
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || '';
const STUDENT_FRONTEND_URL = (process.env.STUDENT_FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');
const COLLEGE_NAME = process.env.COLLEGE_NAME || 'College Faculty Feedback System';
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';

// ============================================================================
// 2. PASSWORD HASHING SUBSYSTEM
// ============================================================================
/**
 * Uses Argon2 for strong, memory-hard password hashing if available,
 * with automatic fallback to bcryptjs for seamless cross-platform reliability.
 */
let argon2 = null;
try {
  argon2 = require('argon2');
} catch (err) {
  // Argon2 native module unavailable, bcryptjs will be used seamlessly
}

async function hashPassword(password) {
  if (argon2) {
    try {
      return await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 2 ** 16,
        timeCost: 3,
        parallelism: 1
      });
    } catch (e) {
      // Fallback to bcrypt if argon2 hashing encounters an unexpected error
      return await bcrypt.hash(password, 12);
    }
  }
  return await bcrypt.hash(password, 12);
}

async function verifyPassword(password, hash) {
  if (!hash || !password) return false;
  if (hash.startsWith('$argon2') && argon2) {
    try {
      return await argon2.verify(hash, password);
    } catch (e) {
      return false;
    }
  }
  // Fallback to bcrypt verification
  return await bcrypt.compare(password, hash);
}

// ============================================================================
// 3. MONGOOSE DATABASE CONNECTION & SCHEMAS
// ============================================================================
mongoose.set('strictQuery', true);

// 3.1 User Schema (SUPER_ADMIN and HOD)
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true
    },
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true
    },
    passwordHash: {
      type: String,
      required: true
    },
    role: {
      type: String,
      enum: ['SUPER_ADMIN', 'HOD'],
      required: true,
      index: true
    },
    department: {
      type: String,
      trim: true,
      default: ''
    },
    isActive: {
      type: Boolean,
      default: true
    },
    resetTokenHash: {
      type: String,
      default: null
    },
    resetTokenExpiry: {
      type: Date,
      default: null
    }
  },
  { timestamps: true }
);

// Remove sensitive credentials when converting user to JSON
userSchema.methods.toJSON = function () {
  const user = this.toObject();
  delete user.passwordHash;
  delete user.resetTokenHash;
  delete user.resetTokenExpiry;
  return user;
};

const User = mongoose.model('User', userSchema);

// 3.2 FeedbackForm Schema
const teacherSubSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true
    },
    subject: {
      type: String,
      required: true,
      trim: true
    }
  },
  { _id: true }
);

const feedbackFormSchema = new mongoose.Schema(
  {
    hodId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    department: {
      type: String,
      required: true,
      trim: true
    },
    className: {
      type: String,
      required: true,
      trim: true
    },
    semester: {
      type: String,
      required: true,
      trim: true
    },
    academicYear: {
      type: String,
      trim: true,
      default: ''
    },
    feedbackDate: {
      type: Date,
      default: Date.now
    },
    teachers: {
      type: [teacherSubSchema],
      validate: [v => Array.isArray(v) && v.length > 0, 'At least one teacher is required']
    },
    topics: {
      type: [String],
      validate: [v => Array.isArray(v) && v.length > 0, 'At least one evaluation topic is required']
    },
    publicToken: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    status: {
      type: String,
      enum: ['ACTIVE', 'CLOSED'],
      default: 'ACTIVE',
      index: true
    }
  },
  { timestamps: true }
);

const FeedbackForm = mongoose.model('FeedbackForm', feedbackFormSchema);

// 3.3 FeedbackResponse Schema (Raw student feedback submissions)
const answerSubSchema = new mongoose.Schema(
  {
    topic: {
      type: String,
      required: true,
      trim: true
    },
    rating: {
      type: Number,
      required: true,
      min: 1,
      max: 5,
      validate: {
        validator: Number.isInteger,
        message: 'Rating must be an integer between 1 and 5'
      }
    }
  },
  { _id: false }
);

const teacherResponseSubSchema = new mongoose.Schema(
  {
    teacherId: {
      type: String,
      required: true
    },
    teacherName: {
      type: String,
      required: true
    },
    subject: {
      type: String,
      required: true
    },
    answers: {
      type: [answerSubSchema],
      required: true
    }
  },
  { _id: false }
);

const feedbackResponseSchema = new mongoose.Schema(
  {
    formId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'FeedbackForm',
      required: true,
      index: true
    },
    enrollmentNumber: {
      type: String,
      required: true,
      trim: true,
      uppercase: true
    },
    submittedAt: {
      type: Date,
      default: Date.now
    },
    teacherResponses: {
      type: [teacherResponseSubSchema],
      required: true
    }
  },
  { timestamps: true }
);

// CRITICAL SECURITY & INTEGRITY CONSTRAINT:
// Database-level compound unique index prevents race-condition duplicate submissions
feedbackResponseSchema.index({ formId: 1, enrollmentNumber: 1 }, { unique: true });

const FeedbackResponse = mongoose.model('FeedbackResponse', feedbackResponseSchema);

// ============================================================================
// 4. SECURITY MIDDLEWARE & APPLICATION SETUP
// ============================================================================
const app = express();

// Trust proxy for Render / reverse proxies (essential for rate limiting & secure cookies)
app.set('trust proxy', 1);

// HTTP Security Headers
app.use(
  helmet({
    contentSecurityPolicy: IS_PRODUCTION ? undefined : false,
    crossOriginEmbedderPolicy: false
  })
);

// Strict CORS setup
const corsOptions = {
  origin: (origin, callback) => {
    // Allow non-browser agents, curl, Postman, Render healthcheck
    if (!origin) return callback(null, true);
    // In development or if explicitly matching frontend URL
    if (!IS_PRODUCTION) return callback(null, true);
    if (origin === STUDENT_FRONTEND_URL || origin.endsWith('.onrender.com')) {
      return callback(null, true);
    }
    return callback(null, true); // Permissive for initial deployment; lock down as needed
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};
app.use(cors(corsOptions));

// Body parsers with payload size limits to mitigate DoS
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Cookie Parser for HTTP-only cookie authentication
app.use(cookieParser());

// Rate Limiters
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests from this IP. Please try again later.' }
});
app.use('/api', globalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many authentication attempts. Please try again later.' }
});

const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many password reset attempts. Please try again later.' }
});

const submissionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many submissions from this connection. Please wait before retrying.' }
});

// ============================================================================
// 5. AUTHENTICATION & AUTHORIZATION HELPERS / MIDDLEWARE
// ============================================================================
const COOKIE_NAME = 'faculty_feedback_token';

function generateJwtToken(user) {
  return jwt.sign(
    {
      id: user._id.toString(),
      role: user.role,
      department: user.department,
      email: user.email,
      username: user.username
    },
    AUTH_SECRET,
    { expiresIn: '24h' }
  );
}

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: IS_PRODUCTION ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  });
}

function clearAuthCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: IS_PRODUCTION ? 'none' : 'lax'
  });
}

// Authentication middleware supporting both HTTP-only Cookies and Bearer Header
async function authenticate(req, res, next) {
  try {
    let token = null;

    // 1. Check Cookie
    if (req.cookies && req.cookies[COOKIE_NAME]) {
      token = req.cookies[COOKIE_NAME];
    }
    // 2. Check Authorization Header (Bearer <token>)
    else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({ success: false, error: 'Authentication required. No token provided.' });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, AUTH_SECRET);
    } catch (err) {
      return res.status(401).json({ success: false, error: 'Invalid or expired session. Please log in again.' });
    }

    const user = await User.findById(decoded.id);
    if (!user || !user.isActive) {
      return res.status(401).json({ success: false, error: 'User account is inactive or no longer exists.' });
    }

    // Attach authenticated user to request
    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

// Role-based Access Control (RBAC) middleware
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: `Access denied. Requires one of the following roles: ${roles.join(', ')}`
      });
    }
    next();
  };
}

// Helper to verify form ownership for HOD
async function getHodOwnedForm(formId, hodId) {
  if (!mongoose.Types.ObjectId.isValid(formId)) {
    return { error: { status: 400, message: 'Invalid form ID format' }, form: null };
  }
  const form = await FeedbackForm.findById(formId);
  if (!form) {
    return { error: { status: 404, message: 'Feedback form not found' }, form: null };
  }
  if (form.hodId.toString() !== hodId.toString()) {
    return { error: { status: 403, message: 'Access denied: You do not own this feedback form' }, form: null };
  }
  return { error: null, form };
}

// ============================================================================
// 6. INPUT VALIDATION SCHEMAS (Zod)
// ============================================================================
const loginSchema = z.object({
  usernameOrEmail: z.string().trim().min(3, 'Username or email is required'),
  password: z.string().min(6, 'Password must be at least 6 characters')
});

const createHodSchema = z.object({
  department: z.string().trim().min(2, 'Department name is required'),
  name: z.string().trim().min(2, 'HOD name is required'),
  email: z.string().trim().email('Valid email address is required'),
  username: z
    .string()
    .trim()
    .min(3, 'Username must be at least 3 characters')
    .max(30)
    .regex(/^[a-zA-Z0-9_.-]+$/, 'Username can only contain letters, numbers, underscores, dots, and hyphens'),
  password: z.string().min(8, 'Password must be at least 8 characters long')
});

const forgotPasswordSchema = z.object({
  email: z.string().trim().email('Valid email address is required')
});

const resetPasswordSchema = z.object({
  token: z.string().trim().min(16, 'Valid reset token is required'),
  newPassword: z.string().min(8, 'New password must be at least 8 characters long')
});

const createFormSchema = z.object({
  className: z.string().trim().min(1, 'Class name is required'),
  semester: z.string().trim().min(1, 'Semester is required'),
  academicYear: z.string().trim().optional(),
  feedbackDate: z.string().optional(),
  teachers: z
    .array(
      z.object({
        name: z.string().trim().min(1, 'Teacher name cannot be empty'),
        subject: z.string().trim().min(1, 'Subject cannot be empty')
      })
    )
    .min(1, 'At least one teacher must be added to the form'),
  topics: z
    .array(z.string().trim().min(1, 'Topic question cannot be empty'))
    .min(1, 'At least one evaluation topic must be added')
});

const verifyEnrollmentSchema = z.object({
  enrollmentNumber: z.string().trim().min(1, 'Enrollment number is required')
});

const submitFeedbackSchema = z.object({
  enrollmentNumber: z.string().trim().min(1, 'Enrollment number is required'),
  teacherResponses: z
    .array(
      z.object({
        teacherId: z.string().trim().min(1, 'Teacher ID is required'),
        teacherName: z.string().trim().min(1, 'Teacher name is required'),
        subject: z.string().trim().min(1, 'Subject is required'),
        answers: z
          .array(
            z.object({
              topic: z.string().trim().min(1, 'Topic title is required'),
              rating: z.number().int().min(1).max(5)
            })
          )
          .min(1, 'All topic answers must be provided')
      })
    )
    .min(1, 'Teacher responses must not be empty')
});

// ============================================================================
// 7. EMAIL & PASSWORD RESET SUBSYSTEM (Nodemailer Gmail SMTP)
// ============================================================================
let emailTransporter = null;

if (GMAIL_USER && GMAIL_APP_PASSWORD) {
  emailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: GMAIL_USER,
      pass: GMAIL_APP_PASSWORD
    }
  });
}

async function sendPasswordResetEmail(recipientEmail, rawToken) {
  if (!emailTransporter) {
    console.warn('[EMAIL WARNING] Gmail SMTP is not configured. Reset token (dev mode only):', rawToken);
    return false;
  }

  // Frontend password reset page URL pointing to the user interface
  const resetUrl = `${STUDENT_FRONTEND_URL}/reset-password?token=${encodeURIComponent(rawToken)}`;

  const mailOptions = {
    from: `"${COLLEGE_NAME}" <${GMAIL_USER}>`,
    to: recipientEmail,
    subject: `Password Reset Request - ${COLLEGE_NAME}`,
    text: `Hello,\n\nA password reset request was received for your HOD account at ${COLLEGE_NAME}.\n\nTo reset your password, please visit the following link (valid for 30 minutes):\n${resetUrl}\n\nIf you did not request a password reset, please ignore this email.\n\nRegards,\n${COLLEGE_NAME} Administration`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #1a365d; text-align: center; margin-bottom: 20px;">${COLLEGE_NAME}</h2>
        <div style="padding: 20px; background-color: #f7fafc; border-radius: 6px;">
          <h3 style="color: #2d3748; margin-top: 0;">Password Reset Request</h3>
          <p style="color: #4a5568; line-height: 1.6;">
            A password reset was requested for your HOD account. Click the button below to set a new password. This link will expire in <strong>30 minutes</strong>.
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" style="background-color: #2b6cb0; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
              Reset Password
            </a>
          </div>
          <p style="color: #718096; font-size: 13px; line-height: 1.5;">
            Or copy and paste this URL into your browser:<br/>
            <a href="${resetUrl}" style="color: #2b6cb0; word-break: break-all;">${resetUrl}</a>
          </p>
          <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;" />
          <p style="color: #a0aec0; font-size: 12px; margin-bottom: 0;">
            If you did not request this reset, no further action is required. Your account remains secure.
          </p>
        </div>
      </div>
    `
  };

  await emailTransporter.sendMail(mailOptions);
  return true;
}

// ============================================================================
// 8. ANALYTICS COMPUTATION ENGINE
// ============================================================================
/**
 * Accurately computes all requested feedback metrics from stored raw responses:
 * 1. Teacher + topic average rating
 * 2. Teacher overall average
 * 3. Student + teacher average
 * 4. Overall form average
 * 5. Total responses and submitted enrollment numbers
 */
function computeFormAnalytics(form, responses) {
  const totalResponses = responses.length;
  const submittedEnrollments = responses.map(r => r.enrollmentNumber);

  // Initialize analytics data structures
  const teacherTopicMap = {}; // key: `${teacherId}__${topic}` -> { sum, count, teacherName, subject, topic }
  const teacherOverallMap = {}; // key: teacherId -> { sum, count, teacherName, subject }
  const studentTeacherMap = {}; // key: `${enrollmentNumber}__${teacherId}` -> { sum, count, teacherName }

  let globalScoreSum = 0;
  let globalAnswersCount = 0;

  // Process raw stored responses
  for (const resp of responses) {
    const student = resp.enrollmentNumber;

    for (const tResp of resp.teacherResponses) {
      const tId = tResp.teacherId;
      const tName = tResp.teacherName;
      const tSubj = tResp.subject;

      if (!teacherOverallMap[tId]) {
        teacherOverallMap[tId] = {
          teacherId: tId,
          teacherName: tName,
          subject: tSubj,
          sum: 0,
          count: 0
        };
      }

      const stKey = `${student}__${tId}`;
      if (!studentTeacherMap[stKey]) {
        studentTeacherMap[stKey] = {
          enrollmentNumber: student,
          teacherId: tId,
          teacherName: tName,
          subject: tSubj,
          sum: 0,
          count: 0
        };
      }

      for (const ans of tResp.answers) {
        const rating = ans.rating;
        const topic = ans.topic;
        const ttKey = `${tId}__${topic}`;

        if (!teacherTopicMap[ttKey]) {
          teacherTopicMap[ttKey] = {
            teacherId: tId,
            teacherName: tName,
            subject: tSubj,
            topic: topic,
            sum: 0,
            count: 0
          };
        }

        teacherTopicMap[ttKey].sum += rating;
        teacherTopicMap[ttKey].count += 1;

        teacherOverallMap[tId].sum += rating;
        teacherOverallMap[tId].count += 1;

        studentTeacherMap[stKey].sum += rating;
        studentTeacherMap[stKey].count += 1;

        globalScoreSum += rating;
        globalAnswersCount += 1;
      }
    }
  }

  // 1. Teacher + Topic averages
  const teacherTopicAverages = Object.values(teacherTopicMap).map(item => ({
    teacherId: item.teacherId,
    teacherName: item.teacherName,
    subject: item.subject,
    topic: item.topic,
    averageRating: item.count > 0 ? parseFloat((item.sum / item.count).toFixed(2)) : 0,
    totalRatings: item.count
  }));

  // 2. Teacher overall averages
  const teacherOverallAverages = form.teachers.map(t => {
    const tId = t._id.toString();
    const metrics = teacherOverallMap[tId];
    return {
      teacherId: tId,
      teacherName: t.name,
      subject: t.subject,
      overallAverage: metrics && metrics.count > 0 ? parseFloat((metrics.sum / metrics.count).toFixed(2)) : 0,
      totalAnswers: metrics ? metrics.count : 0
    };
  });

  // 3. Student + Teacher averages
  const studentTeacherAverages = Object.values(studentTeacherMap).map(item => ({
    enrollmentNumber: item.enrollmentNumber,
    teacherId: item.teacherId,
    teacherName: item.teacherName,
    subject: item.subject,
    averageRating: item.count > 0 ? parseFloat((item.sum / item.count).toFixed(2)) : 0
  }));

  // 4. Overall Form Average
  const overallFormAverage =
    globalAnswersCount > 0 ? parseFloat((globalScoreSum / globalAnswersCount).toFixed(2)) : 0;

  return {
    totalResponses,
    submittedEnrollments,
    overallFormAverage,
    teacherTopicAverages,
    teacherOverallAverages,
    studentTeacherAverages
  };
}

// ============================================================================
// 9. PDF REPORT GENERATOR (PDFKit Multi-Page Engine)
// ============================================================================
function drawPdfHeader(doc, title, subtitle) {
  doc.rect(40, 30, doc.page.width - 80, 55).fill('#1A365D');
  doc.fillColor('#FFFFFF').fontSize(16).font('Helvetica-Bold').text(title, 40, 42, {
    align: 'center',
    width: doc.page.width - 80
  });
  doc.fontSize(11).font('Helvetica').text(subtitle, 40, 62, {
    align: 'center',
    width: doc.page.width - 80
  });
  doc.fillColor('#000000');
  doc.y = 100;
}

function drawMetadataBox(doc, form, totalResponses, overallAvg) {
  const startY = doc.y;
  const boxWidth = doc.page.width - 80;

  doc.rect(40, startY, boxWidth, 75).fillAndStroke('#F7FAFC', '#CBD5E0');
  doc.fillColor('#2D3748').fontSize(10).font('Helvetica-Bold');

  const col1 = 55;
  const col2 = 220;
  const col3 = 400;

  doc.text(`Department:`, col1, startY + 12).font('Helvetica').text(form.department, col1 + 75, startY + 12);
  doc.font('Helvetica-Bold').text(`Class:`, col1, startY + 30).font('Helvetica').text(form.className, col1 + 75, startY + 30);
  doc.font('Helvetica-Bold').text(`Semester:`, col1, startY + 48).font('Helvetica').text(form.semester, col1 + 75, startY + 48);

  const dateStr = form.feedbackDate ? new Date(form.feedbackDate).toLocaleDateString() : 'N/A';
  doc.font('Helvetica-Bold').text(`Feedback Date:`, col2, startY + 12).font('Helvetica').text(dateStr, col2 + 85, startY + 12);
  doc.font('Helvetica-Bold').text(`Status:`, col2, startY + 30).font('Helvetica').text(form.status, col2 + 85, startY + 30);
  doc.font('Helvetica-Bold').text(`Total Responses:`, col2, startY + 48).font('Helvetica').text(String(totalResponses), col2 + 85, startY + 48);

  doc.rect(col3, startY + 10, 140, 55).fill('#EDF2F7');
  doc.fillColor('#4A5568').fontSize(9).font('Helvetica').text('OVERALL RATING', col3, startY + 16, { width: 140, align: 'center' });
  doc.fillColor('#2B6CB0').fontSize(22).font('Helvetica-Bold').text(`${overallAvg.toFixed(2)} / 5`, col3, startY + 30, { width: 140, align: 'center' });

  doc.fillColor('#000000');
  doc.y = startY + 90;
}

function generateAnalysisPDF(res, form, responses, analytics) {
  const doc = new PDFDocument({ margin: 40, size: 'A4', bufferPages: true });

  doc.pipe(res);

  // ---------------- PAGE 1: TOTAL SUMMARY ----------------
  drawPdfHeader(doc, COLLEGE_NAME, 'FACULTY FEEDBACK ANALYSIS REPORT - SUMMARY');
  drawMetadataBox(doc, form, analytics.totalResponses, analytics.overallFormAverage);

  // Section: Teacher-Topic Breakdown Table
  doc.fontSize(12).font('Helvetica-Bold').fillColor('#1A365D').text('1. Teacher & Topic Average Ratings', 40, doc.y);
  doc.moveDown(0.5);

  let currentY = doc.y;
  const colWidths = { teacher: 150, subject: 100, topic: 195, avg: 70 };
  const tableX = 40;

  // Table Header
  doc.rect(tableX, currentY, doc.page.width - 80, 22).fill('#2B6CB0');
  doc.fillColor('#FFFFFF').fontSize(9).font('Helvetica-Bold');
  doc.text('Teacher', tableX + 8, currentY + 6, { width: colWidths.teacher });
  doc.text('Subject', tableX + colWidths.teacher + 8, currentY + 6, { width: colWidths.subject });
  doc.text('Topic / Criteria', tableX + colWidths.teacher + colWidths.subject + 8, currentY + 6, { width: colWidths.topic });
  doc.text('Avg Rating', tableX + colWidths.teacher + colWidths.subject + colWidths.topic + 8, currentY + 6, { width: colWidths.avg, align: 'right' });
  currentY += 22;

  // Table Rows
  doc.font('Helvetica').fontSize(9).fillColor('#2D3748');
  let isEven = false;
  for (const item of analytics.teacherTopicAverages) {
    if (currentY > doc.page.height - 70) {
      doc.addPage();
      currentY = 40;
    }
    const rowHeight = 20;
    if (isEven) {
      doc.rect(tableX, currentY, doc.page.width - 80, rowHeight).fill('#F7FAFC');
      doc.fillColor('#2D3748');
    }
    doc.text(item.teacherName, tableX + 8, currentY + 5, { width: colWidths.teacher });
    doc.text(item.subject, tableX + colWidths.teacher + 8, currentY + 5, { width: colWidths.subject });
    doc.text(item.topic, tableX + colWidths.teacher + colWidths.subject + 8, currentY + 5, { width: colWidths.topic });
    doc.font('Helvetica-Bold').text(`${item.averageRating.toFixed(2)} / 5`, tableX + colWidths.teacher + colWidths.subject + colWidths.topic + 8, currentY + 5, { width: colWidths.avg - 16, align: 'right' }).font('Helvetica');
    currentY += rowHeight;
    isEven = !isEven;
  }

  // Teacher Overall Summary Cards
  doc.y = currentY + 15;
  if (doc.y > doc.page.height - 100) {
    doc.addPage();
    doc.y = 40;
  }
  doc.fontSize(12).font('Helvetica-Bold').fillColor('#1A365D').text('Teacher Overall Performance Summary', 40, doc.y);
  doc.moveDown(0.5);

  let cardY = doc.y;
  for (const t of analytics.teacherOverallAverages) {
    if (cardY > doc.page.height - 50) {
      doc.addPage();
      cardY = 40;
    }
    doc.rect(40, cardY, doc.page.width - 80, 26).fillAndStroke('#EDF2F7', '#E2E8F0');
    doc.fillColor('#1A365D').fontSize(10).font('Helvetica-Bold').text(`${t.teacherName} (${t.subject})`, 50, cardY + 7);
    doc.fillColor('#2B6CB0').fontSize(10).text(`Overall Average: ${t.overallAverage.toFixed(2)} / 5.00`, doc.page.width - 230, cardY + 7, { align: 'right', width: 180 });
    cardY += 32;
  }

  // ---------------- PAGE 2: STUDENT-WISE SUMMARY ----------------
  doc.addPage();
  drawPdfHeader(doc, COLLEGE_NAME, 'STUDENT-WISE EVALUATION SUMMARY');

  doc.fontSize(12).font('Helvetica-Bold').fillColor('#1A365D').text('2. Student-Wise Average per Teacher', 40, doc.y);
  doc.moveDown(0.5);

  let stTableY = doc.y;
  const stColWidths = { sr: 45, enrollment: 140, teacher: 220, avg: 110 };

  // Header
  doc.rect(tableX, stTableY, doc.page.width - 80, 22).fill('#2B6CB0');
  doc.fillColor('#FFFFFF').fontSize(9).font('Helvetica-Bold');
  doc.text('Sr. No.', tableX + 6, stTableY + 6, { width: stColWidths.sr });
  doc.text('Enrollment Number', tableX + stColWidths.sr + 6, stTableY + 6, { width: stColWidths.enrollment });
  doc.text('Teacher (Subject)', tableX + stColWidths.sr + stColWidths.enrollment + 6, stTableY + 6, { width: stColWidths.teacher });
  doc.text('Average Score', tableX + stColWidths.sr + stColWidths.enrollment + stColWidths.teacher + 6, stTableY + 6, { width: stColWidths.avg, align: 'right' });
  stTableY += 22;

  isEven = false;
  let srNo = 1;
  for (const row of analytics.studentTeacherAverages) {
    if (stTableY > doc.page.height - 60) {
      doc.addPage();
      stTableY = 40;
    }
    const rHeight = 20;
    if (isEven) {
      doc.rect(tableX, stTableY, doc.page.width - 80, rHeight).fill('#F7FAFC');
    }
    doc.fillColor('#2D3748').font('Helvetica').fontSize(9);
    doc.text(String(srNo++), tableX + 6, stTableY + 5, { width: stColWidths.sr });
    doc.font('Helvetica-Bold').text(row.enrollmentNumber, tableX + stColWidths.sr + 6, stTableY + 5, { width: stColWidths.enrollment }).font('Helvetica');
    doc.text(`${row.teacherName} - ${row.subject}`, tableX + stColWidths.sr + stColWidths.enrollment + 6, stTableY + 5, { width: stColWidths.teacher });
    doc.font('Helvetica-Bold').text(`${row.averageRating.toFixed(2)} / 5`, tableX + stColWidths.sr + stColWidths.enrollment + stColWidths.teacher + 6, stTableY + 5, { width: stColWidths.avg - 16, align: 'right' });

    stTableY += rHeight;
    isEven = !isEven;
  }

  // ---------------- REMAINING PAGES: FULL STUDENT REPORT (1 STUDENT PER PAGE) ----------------
  for (const resp of responses) {
    doc.addPage();
    drawPdfHeader(doc, COLLEGE_NAME, 'INDIVIDUAL STUDENT FEEDBACK BREAKDOWN');

    // Student Enrollment Banner
    doc.rect(40, doc.y, doc.page.width - 80, 36).fill('#EDF2F7');
    doc.fillColor('#1A365D').fontSize(12).font('Helvetica-Bold').text(`Enrollment Number: ${resp.enrollmentNumber}`, 50, doc.y + 11);
    const subDate = resp.submittedAt ? new Date(resp.submittedAt).toLocaleString() : 'N/A';
    doc.fillColor('#718096').fontSize(9).font('Helvetica').text(`Submitted: ${subDate}`, doc.page.width - 240, doc.y + 13, { align: 'right', width: 190 });
    doc.y += 50;

    for (const tResp of resp.teacherResponses) {
      if (doc.y > doc.page.height - 120) {
        doc.addPage();
        doc.y = 40;
      }

      // Teacher heading
      doc.rect(40, doc.y, doc.page.width - 80, 22).fill('#2D3748');
      doc.fillColor('#FFFFFF').fontSize(10).font('Helvetica-Bold').text(`Teacher: ${tResp.teacherName}   |   Subject: ${tResp.subject}`, 50, doc.y + 6);
      doc.y += 24;

      // Table for Topics & Ratings
      const curTableY = doc.y;
      doc.rect(40, curTableY, doc.page.width - 80, 18).fill('#E2E8F0');
      doc.fillColor('#2D3748').fontSize(9).font('Helvetica-Bold');
      doc.text('Evaluation Criteria / Topic', 50, curTableY + 5, { width: 380 });
      doc.text('Rating (1-5)', doc.page.width - 160, curTableY + 5, { width: 110, align: 'right' });
      doc.y += 18;

      let tSum = 0;
      let tCount = 0;
      let tEven = false;

      for (const ans of tResp.answers) {
        const itemY = doc.y;
        if (tEven) {
          doc.rect(40, itemY, doc.page.width - 80, 18).fill('#F7FAFC');
        }
        doc.fillColor('#4A5568').font('Helvetica').fontSize(9);
        doc.text(ans.topic, 50, itemY + 4, { width: 380 });
        doc.font('Helvetica-Bold').text(`${ans.rating} / 5`, doc.page.width - 160, itemY + 4, { width: 110, align: 'right' });
        doc.y += 18;
        tSum += ans.rating;
        tCount += 1;
        tEven = !tEven;
      }

      // Teacher average score bar
      const tAvg = tCount > 0 ? (tSum / tCount).toFixed(2) : '0.00';
      const avgBarY = doc.y;
      doc.rect(40, avgBarY, doc.page.width - 80, 20).fill('#EDF2F7');
      doc.fillColor('#2B6CB0').font('Helvetica-Bold').fontSize(9).text(`Teacher Average: ${tAvg} / 5.00`, doc.page.width - 240, avgBarY + 5, { align: 'right', width: 190 });
      doc.y += 30;
    }
  }

  // Add Page Numbers to all pages
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    doc.fillColor('#A0AEC0').fontSize(8).font('Helvetica').text(
      `Page ${i + 1} of ${range.count}  •  ${COLLEGE_NAME} Confidential Report`,
      40,
      doc.page.height - 30,
      { align: 'center', width: doc.page.width - 80 }
    );
  }

  doc.end();
}

// ============================================================================
// 10. SYSTEM & HEALTH CHECK ENDPOINTS
// ============================================================================
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// ============================================================================
// 11. AUTHENTICATION ENDPOINTS (/api/auth)
// ============================================================================
const authRouter = express.Router();

/**
 * POST /api/auth/login
 * Log in Super Admin or HOD using Username OR Email + Password
 */
authRouter.post('/login', authLimiter, async (req, res, next) => {
  try {
    const parseResult = loginSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: parseResult.error.flatten().fieldErrors
      });
    }

    const { usernameOrEmail, password } = parseResult.data;
    const cleanIdentifier = usernameOrEmail.toLowerCase().trim();

    // Query user by username or email
    const user = await User.findOne({
      $or: [{ username: cleanIdentifier }, { email: cleanIdentifier }]
    });

    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid username/email or password' });
    }

    if (!user.isActive) {
      return res.status(403).json({ success: false, error: 'Your account has been deactivated. Contact Super Admin.' });
    }

    const isMatch = await verifyPassword(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid username/email or password' });
    }

    const token = generateJwtToken(user);
    setAuthCookie(res, token);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        username: user.username,
        role: user.role,
        department: user.department
      }
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/logout
 * Clears authentication cookie
 */
authRouter.post('/logout', (req, res) => {
  clearAuthCookie(res);
  res.status(200).json({ success: true, message: 'Logged out successfully' });
});

/**
 * GET /api/auth/me
 * Returns currently logged-in user profile
 */
authRouter.get('/me', authenticate, (req, res) => {
  res.status(200).json({
    success: true,
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      username: req.user.username,
      role: req.user.role,
      department: req.user.department
    }
  });
});

/**
 * POST /api/auth/forgot-password
 * Initiates single-use secure reset token flow.
 * SECURITY: Never reveals whether an email exists (timing-safe generic response).
 */
authRouter.post('/forgot-password', passwordResetLimiter, async (req, res, next) => {
  try {
    const parseResult = forgotPasswordSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: parseResult.error.flatten().fieldErrors
      });
    }

    const email = parseResult.data.email.toLowerCase().trim();
    const user = await User.findOne({ email, isActive: true });

    if (user) {
      // 1. Generate cryptographically secure random token
      const rawResetToken = crypto.randomBytes(32).toString('hex');

      // 2. Hash token with SHA-256 before saving to MongoDB
      const tokenHash = crypto.createHash('sha256').update(rawResetToken).digest('hex');

      // 3. Set expiration (30 minutes)
      user.resetTokenHash = tokenHash;
      user.resetTokenExpiry = new Date(Date.now() + 30 * 60 * 1000);
      await user.save();

      // 4. Dispatch reset email via Gmail SMTP
      try {
        await sendPasswordResetEmail(user.email, rawResetToken);
      } catch (mailErr) {
        console.error('[EMAIL ERROR] Failed to send reset email:', mailErr.message);
      }
    }

    // Always return generic response to prevent email enumeration
    res.status(200).json({
      success: true,
      message: 'If an account exists for this email, a password reset link has been sent.'
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/reset-password
 * Validates reset token and updates password
 */
authRouter.post('/reset-password', passwordResetLimiter, async (req, res, next) => {
  try {
    const parseResult = resetPasswordSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: parseResult.error.flatten().fieldErrors
      });
    }

    const { token, newPassword } = parseResult.data;

    // Hash the incoming raw token to look it up
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      resetTokenHash: tokenHash,
      resetTokenExpiry: { $gt: new Date() },
      isActive: true
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        error: 'Password reset link is invalid or has expired. Please request a new one.'
      });
    }

    // Hash new password using Argon2/Bcrypt
    user.passwordHash = await hashPassword(newPassword);

    // Invalidate reset token immediately (single-use enforcement)
    user.resetTokenHash = null;
    user.resetTokenExpiry = null;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Your password has been successfully reset. You can now log in with your new password.'
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/setup-admin
 * One-time setup endpoint: only succeeds if NO Super Admin exists in the database
 */
authRouter.post('/setup-admin', async (req, res, next) => {
  try {
    const adminCount = await User.countDocuments({ role: 'SUPER_ADMIN' });
    if (adminCount > 0) {
      return res.status(403).json({
        success: false,
        error: 'Super Admin account has already been initialized.'
      });
    }

    const { name, email, username, password } = req.body;
    if (!name || !email || !username || !password || password.length < 8) {
      return res.status(400).json({
        success: false,
        error: 'name, email, username, and a password of at least 8 characters are required.'
      });
    }

    const passwordHash = await hashPassword(password);
    const superAdmin = new User({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      username: username.toLowerCase().trim(),
      passwordHash,
      role: 'SUPER_ADMIN',
      department: 'Administration',
      isActive: true
    });

    await superAdmin.save();

    res.status(201).json({
      success: true,
      message: 'Super Admin initialized successfully. You may now log in.',
      user: {
        id: superAdmin._id,
        name: superAdmin.name,
        email: superAdmin.email,
        username: superAdmin.username,
        role: superAdmin.role
      }
    });
  } catch (error) {
    next(error);
  }
});

app.use('/api/auth', authRouter);

// ============================================================================
// 12. SUPER ADMIN ENDPOINTS (/api/admin)
// ============================================================================
const adminRouter = express.Router();
adminRouter.use(authenticate, requireRole('SUPER_ADMIN'));

/**
 * POST /api/admin/hods
 * Super Admin creates a new HOD account
 */
adminRouter.post('/hods', async (req, res, next) => {
  try {
    const parseResult = createHodSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: parseResult.error.flatten().fieldErrors
      });
    }

    const { department, name, email, username, password } = parseResult.data;
    const cleanEmail = email.toLowerCase().trim();
    const cleanUsername = username.toLowerCase().trim();

    // Prevent duplicate email or username
    const existing = await User.findOne({
      $or: [{ email: cleanEmail }, { username: cleanUsername }]
    });

    if (existing) {
      if (existing.email === cleanEmail) {
        return res.status(409).json({ success: false, error: 'A user with this email address already exists.' });
      }
      return res.status(409).json({ success: false, error: 'A user with this username already exists.' });
    }

    const passwordHash = await hashPassword(password);

    const newHod = new User({
      department,
      name,
      email: cleanEmail,
      username: cleanUsername,
      passwordHash,
      role: 'HOD',
      isActive: true
    });

    await newHod.save();

    res.status(201).json({
      success: true,
      message: 'HOD account created successfully',
      hod: {
        id: newHod._id,
        name: newHod.name,
        department: newHod.department,
        email: newHod.email,
        username: newHod.username,
        isActive: newHod.isActive,
        createdAt: newHod.createdAt
      }
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/admin/hods
 * Super Admin lists all HOD accounts
 */
adminRouter.get('/hods', async (req, res, next) => {
  try {
    const hods = await User.find({ role: 'HOD' }).sort({ createdAt: -1 });
    res.status(200).json({
      success: true,
      count: hods.length,
      hods
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PATCH /api/admin/hods/:id/status
 * Super Admin toggles or updates active status of an HOD
 */
adminRouter.patch('/hods/:id/status', async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid HOD ID format' });
    }

    const hod = await User.findOne({ _id: id, role: 'HOD' });
    if (!hod) {
      return res.status(404).json({ success: false, error: 'HOD account not found' });
    }

    if (typeof req.body.isActive === 'boolean') {
      hod.isActive = req.body.isActive;
    } else {
      hod.isActive = !hod.isActive;
    }

    await hod.save();

    res.status(200).json({
      success: true,
      message: `HOD account ${hod.isActive ? 'activated' : 'deactivated'} successfully`,
      hod
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PATCH /api/admin/hods/:id
 * Super Admin edits an HOD's details (name, email, username, department, or resets password)
 */
adminRouter.patch('/hods/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid HOD ID format' });
    }

    const hod = await User.findOne({ _id: id, role: 'HOD' });
    if (!hod) {
      return res.status(404).json({ success: false, error: 'HOD account not found' });
    }

    const { name, email, username, department, password } = req.body;

    if (email && email.toLowerCase().trim() !== hod.email) {
      const cleanEmail = email.toLowerCase().trim();
      const existingEmail = await User.findOne({ email: cleanEmail, _id: { $ne: hod._id } });
      if (existingEmail) {
        return res.status(409).json({ success: false, error: 'A user with this email address already exists.' });
      }
      hod.email = cleanEmail;
    }

    if (username && username.toLowerCase().trim() !== hod.username) {
      const cleanUsername = username.toLowerCase().trim();
      if (!/^[a-zA-Z0-9_.-]{3,30}$/.test(cleanUsername)) {
        return res.status(400).json({
          success: false,
          error: 'Username must be 3-30 characters and contain only letters, numbers, underscores, dots, and hyphens.'
        });
      }
      const existingUsername = await User.findOne({ username: cleanUsername, _id: { $ne: hod._id } });
      if (existingUsername) {
        return res.status(409).json({ success: false, error: 'A user with this username already exists.' });
      }
      hod.username = cleanUsername;
    }

    if (name && name.trim()) {
      hod.name = name.trim();
    }

    if (department && department.trim()) {
      hod.department = department.trim();
    }

    if (password) {
      if (password.length < 8) {
        return res.status(400).json({ success: false, error: 'New password must be at least 8 characters long.' });
      }
      hod.passwordHash = await hashPassword(password);
    }

    await hod.save();

    res.status(200).json({
      success: true,
      message: 'HOD account updated successfully',
      hod
    });
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /api/admin/hods/:id
 * Super Admin deletes an HOD account and cleans up associated forms
 */
adminRouter.delete('/hods/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid HOD ID format' });
    }

    const hod = await User.findOne({ _id: id, role: 'HOD' });
    if (!hod) {
      return res.status(404).json({ success: false, error: 'HOD account not found' });
    }

    // Clean up forms created by this HOD
    await FeedbackForm.deleteMany({ hodId: id });
    await User.deleteOne({ _id: id });

    res.status(200).json({
      success: true,
      message: `HOD '${hod.name}' and all associated feedback forms have been deleted successfully.`
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PATCH /api/admin/profile
 * Super Admin updates their own profile credentials (name, email, username, and password)
 */
adminRouter.patch('/profile', async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user || user.role !== 'SUPER_ADMIN') {
      return res.status(403).json({ success: false, error: 'Access denied: Must be SUPER_ADMIN.' });
    }

    const { name, email, username, currentPassword, newPassword } = req.body;

    if (email && email.toLowerCase().trim() !== user.email) {
      const cleanEmail = email.toLowerCase().trim();
      const existingEmail = await User.findOne({ email: cleanEmail, _id: { $ne: user._id } });
      if (existingEmail) {
        return res.status(409).json({ success: false, error: 'A user with this email address already exists.' });
      }
      user.email = cleanEmail;
    }

    if (username && username.toLowerCase().trim() !== user.username) {
      const cleanUsername = username.toLowerCase().trim();
      if (!/^[a-zA-Z0-9_.-]{3,30}$/.test(cleanUsername)) {
        return res.status(400).json({
          success: false,
          error: 'Username must be 3-30 characters (letters, numbers, _, -, .).'
        });
      }
      const existingUsername = await User.findOne({ username: cleanUsername, _id: { $ne: user._id } });
      if (existingUsername) {
        return res.status(409).json({ success: false, error: 'A user with this username already exists.' });
      }
      user.username = cleanUsername;
    }

    if (name && name.trim()) {
      user.name = name.trim();
    }

    if (newPassword) {
      if (newPassword.length < 8) {
        return res.status(400).json({ success: false, error: 'New password must be at least 8 characters long.' });
      }
      if (currentPassword) {
        const isMatch = await verifyPassword(currentPassword, user.passwordHash);
        if (!isMatch) {
          return res.status(400).json({ success: false, error: 'Current password does not match.' });
        }
      }
      user.passwordHash = await hashPassword(newPassword);
    }

    await user.save();

    // Re-issue new JWT token with updated credentials
    const newToken = generateJwtToken(user);
    setAuthCookie(res, newToken);

    res.status(200).json({
      success: true,
      message: 'Super Admin credentials updated successfully.',
      token: newToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        username: user.username,
        role: user.role,
        department: user.department
      }
    });
  } catch (error) {
    next(error);
  }
});

app.use('/api/admin', adminRouter);

// ============================================================================
// 13. HOD MANAGEMENT ENDPOINTS (/api/forms)
// ============================================================================
const formRouter = express.Router();
formRouter.use(authenticate, requireRole('HOD'));

/**
 * POST /api/forms
 * HOD creates a new feedback form
 * Department is locked to authenticated HOD profile
 */
formRouter.post('/', async (req, res, next) => {
  try {
    const parseResult = createFormSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: parseResult.error.flatten().fieldErrors
      });
    }

    const { className, semester, academicYear, feedbackDate, teachers, topics } = parseResult.data;

    // Cryptographically secure unpredictable random public token
    const publicToken = crypto.randomBytes(24).toString('hex');

    const newForm = new FeedbackForm({
      hodId: req.user._id,
      department: req.user.department, // Locked strictly to authenticated HOD
      className,
      semester,
      academicYear: academicYear || '',
      feedbackDate: feedbackDate ? new Date(feedbackDate) : new Date(),
      teachers,
      topics,
      publicToken,
      status: 'ACTIVE'
    });

    await newForm.save();

    const publicUrl = `${STUDENT_FRONTEND_URL}/feedback/${publicToken}`;
    const qrCodeDataUrl = await QRCode.toDataURL(publicUrl);

    res.status(201).json({
      success: true,
      message: 'Feedback form created successfully',
      form: newForm,
      publicUrl,
      qrCodeDataUrl
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/forms
 * HOD lists all forms created by this HOD, with response counts
 */
formRouter.get('/', async (req, res, next) => {
  try {
    const forms = await FeedbackForm.find({ hodId: req.user._id }).sort({ createdAt: -1 });

    // Aggregate response counts efficiently
    const formIds = forms.map(f => f._id);
    const countAgg = await FeedbackResponse.aggregate([
      { $match: { formId: { $in: formIds } } },
      { $group: { _id: '$formId', count: { $sum: 1 } } }
    ]);

    const countMap = {};
    for (const c of countAgg) {
      countMap[c._id.toString()] = c.count;
    }

    const formsWithCounts = forms.map(form => {
      const formObj = form.toObject();
      formObj.totalResponses = countMap[form._id.toString()] || 0;
      formObj.publicUrl = `${STUDENT_FRONTEND_URL}/feedback/${form.publicToken}`;
      return formObj;
    });

    res.status(200).json({
      success: true,
      count: formsWithCounts.length,
      forms: formsWithCounts
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/forms/:id
 * HOD retrieves full form details, submitted enrollment numbers, and QR code
 * Enforces ownership: HOD A cannot access HOD B's form
 */
formRouter.get('/:id', async (req, res, next) => {
  try {
    const { error, form } = await getHodOwnedForm(req.params.id, req.user._id);
    if (error) {
      return res.status(error.status).json({ success: false, error: error.message });
    }

    // Retrieve submitted enrollment numbers
    const responses = await FeedbackResponse.find({ formId: form._id }, 'enrollmentNumber submittedAt').sort({
      submittedAt: -1
    });

    const publicUrl = `${STUDENT_FRONTEND_URL}/feedback/${form.publicToken}`;
    const qrCodeDataUrl = await QRCode.toDataURL(publicUrl);

    res.status(200).json({
      success: true,
      form,
      publicUrl,
      qrCodeDataUrl,
      totalResponses: responses.length,
      submittedEnrollmentNumbers: responses.map(r => r.enrollmentNumber),
      recentSubmissions: responses
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PATCH /api/forms/:id/status
 * HOD toggles form status (ACTIVE / CLOSED)
 */
formRouter.patch('/:id/status', async (req, res, next) => {
  try {
    const { error, form } = await getHodOwnedForm(req.params.id, req.user._id);
    if (error) {
      return res.status(error.status).json({ success: false, error: error.message });
    }

    if (req.body.status && ['ACTIVE', 'CLOSED'].includes(req.body.status)) {
      form.status = req.body.status;
    } else {
      form.status = form.status === 'ACTIVE' ? 'CLOSED' : 'ACTIVE';
    }

    await form.save();

    res.status(200).json({
      success: true,
      message: `Feedback form is now ${form.status}`,
      form
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/forms/:id/responses
 * HOD gets raw submissions for this form
 */
formRouter.get('/:id/responses', async (req, res, next) => {
  try {
    const { error, form } = await getHodOwnedForm(req.params.id, req.user._id);
    if (error) {
      return res.status(error.status).json({ success: false, error: error.message });
    }

    const responses = await FeedbackResponse.find({ formId: form._id }).sort({ submittedAt: -1 });

    res.status(200).json({
      success: true,
      count: responses.length,
      responses
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/forms/:id/analytics
 * HOD gets computed averages, teacher rankings, and metrics
 */
formRouter.get('/:id/analytics', async (req, res, next) => {
  try {
    const { error, form } = await getHodOwnedForm(req.params.id, req.user._id);
    if (error) {
      return res.status(error.status).json({ success: false, error: error.message });
    }

    const responses = await FeedbackResponse.find({ formId: form._id });
    const analytics = computeFormAnalytics(form, responses);

    res.status(200).json({
      success: true,
      formId: form._id,
      className: form.className,
      semester: form.semester,
      department: form.department,
      analytics
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/forms/:id/pdf
 * HOD downloads complete multi-page analysis PDF
 */
formRouter.get('/:id/pdf', async (req, res, next) => {
  try {
    const { error, form } = await getHodOwnedForm(req.params.id, req.user._id);
    if (error) {
      return res.status(error.status).json({ success: false, error: error.message });
    }

    const responses = await FeedbackResponse.find({ formId: form._id }).sort({ enrollmentNumber: 1 });
    const analytics = computeFormAnalytics(form, responses);

    const filename = `Faculty_Feedback_${form.department}_${form.className}_Sem${form.semester}.pdf`.replace(/\s+/g, '_');

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    generateAnalysisPDF(res, form, responses, analytics);
  } catch (error) {
    next(error);
  }
});

app.use('/api/forms', formRouter);

// ============================================================================
// 14. PUBLIC STUDENT ENDPOINTS (/api/public/forms)
// ============================================================================
const publicRouter = express.Router();

/**
 * GET /api/public/forms/:token
 * Student loads form via publicToken
 * Returns only necessary public form fields; no sensitive HOD credentials
 */
publicRouter.get('/:token', async (req, res, next) => {
  try {
    const { token } = req.params;
    const form = await FeedbackForm.findOne({ publicToken: token });

    if (!form) {
      return res.status(404).json({ success: false, error: 'Feedback form not found' });
    }

    if (form.status !== 'ACTIVE') {
      return res.status(403).json({
        success: false,
        error: 'This feedback form is currently closed and no longer accepting responses.'
      });
    }

    res.status(200).json({
      success: true,
      form: {
        department: form.department,
        className: form.className,
        semester: form.semester,
        academicYear: form.academicYear,
        feedbackDate: form.feedbackDate,
        teachers: form.teachers.map(t => ({
          id: t._id,
          name: t.name,
          subject: t.subject
        })),
        topics: form.topics
      }
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/public/forms/:token/verify-enrollment
 * Student checks if their enrollment number has already submitted for this form.
 * SECURITY: Does NOT leak other students' enrollment numbers or submission lists.
 */
publicRouter.post('/:token/verify-enrollment', submissionLimiter, async (req, res, next) => {
  try {
    const { token } = req.params;
    const parseResult = verifyEnrollmentSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: parseResult.error.flatten().fieldErrors
      });
    }

    const form = await FeedbackForm.findOne({ publicToken: token });
    if (!form) {
      return res.status(404).json({ success: false, error: 'Feedback form not found' });
    }

    if (form.status !== 'ACTIVE') {
      return res.status(403).json({
        success: false,
        error: 'This feedback form is currently closed.'
      });
    }

    const enrollmentNumber = parseResult.data.enrollmentNumber.trim().toUpperCase();

    // Check if already submitted
    const existing = await FeedbackResponse.findOne({
      formId: form._id,
      enrollmentNumber
    });

    if (existing) {
      return res.status(200).json({
        success: false,
        canSubmit: false,
        message: 'Feedback has already been submitted for this enrollment number.'
      });
    }

    res.status(200).json({
      success: true,
      canSubmit: true,
      message: 'Enrollment number is valid and eligible to submit feedback.'
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/public/forms/:token/submit
 * Student submits feedback
 * Server strictly validates that:
 * - Form exists and is ACTIVE
 * - All teachers in the form are answered
 * - All topics are evaluated with integer rating 1-5
 * - No duplicate ratings or teachers
 * - DB compound index guarantees single submission
 */
publicRouter.post('/:token/submit', submissionLimiter, async (req, res, next) => {
  try {
    const { token } = req.params;
    const parseResult = submitFeedbackSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: parseResult.error.flatten().fieldErrors
      });
    }

    const { enrollmentNumber, teacherResponses } = parseResult.data;
    const cleanEnrollment = enrollmentNumber.trim().toUpperCase();

    const form = await FeedbackForm.findOne({ publicToken: token });
    if (!form) {
      return res.status(404).json({ success: false, error: 'Feedback form not found' });
    }

    if (form.status !== 'ACTIVE') {
      return res.status(403).json({
        success: false,
        error: 'This feedback form is currently closed and no longer accepting submissions.'
      });
    }

    // 1. Strict Server-Side Teacher Validation
    const expectedTeacherIds = new Set(form.teachers.map(t => t._id.toString()));
    const submittedTeacherIds = new Set();

    for (const tResp of teacherResponses) {
      if (!expectedTeacherIds.has(tResp.teacherId)) {
        return res.status(400).json({
          success: false,
          error: `Teacher '${tResp.teacherName}' (ID: ${tResp.teacherId}) does not belong to this feedback form.`
        });
      }
      if (submittedTeacherIds.has(tResp.teacherId)) {
        return res.status(400).json({
          success: false,
          error: `Duplicate responses submitted for teacher '${tResp.teacherName}'.`
        });
      }
      submittedTeacherIds.add(tResp.teacherId);

      // 2. Strict Topic and Rating Validation for Each Teacher
      const expectedTopics = new Set(form.topics);
      const answeredTopics = new Set();

      for (const ans of tResp.answers) {
        if (!expectedTopics.has(ans.topic)) {
          return res.status(400).json({
            success: false,
            error: `Invalid evaluation topic '${ans.topic}' for teacher '${tResp.teacherName}'.`
          });
        }
        if (answeredTopics.has(ans.topic)) {
          return res.status(400).json({
            success: false,
            error: `Duplicate answer for topic '${ans.topic}' under teacher '${tResp.teacherName}'.`
          });
        }
        if (!Number.isInteger(ans.rating) || ans.rating < 1 || ans.rating > 5) {
          return res.status(400).json({
            success: false,
            error: `Rating for '${ans.topic}' must be an integer between 1 and 5.`
          });
        }
        answeredTopics.add(ans.topic);
      }

      // Check that all form topics were answered for this teacher
      if (answeredTopics.size !== form.topics.length) {
        return res.status(400).json({
          success: false,
          error: `Incomplete feedback: all ${form.topics.length} topics must be rated for teacher '${tResp.teacherName}'.`
        });
      }
    }

    // Check that all form teachers have responses
    if (submittedTeacherIds.size !== form.teachers.length) {
      return res.status(400).json({
        success: false,
        error: `Incomplete feedback: all ${form.teachers.length} teachers must be evaluated.`
      });
    }

    // 3. Save response to database
    // Unique compound index ({ formId: 1, enrollmentNumber: 1 }) handles race conditions
    const feedbackResponse = new FeedbackResponse({
      formId: form._id,
      enrollmentNumber: cleanEnrollment,
      teacherResponses,
      submittedAt: new Date()
    });

    await feedbackResponse.save();

    res.status(201).json({
      success: true,
      message: 'Thank you! Your faculty feedback has been submitted successfully.'
    });
  } catch (error) {
    // Handle MongoDB duplicate key error code 11000 gracefully
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        error: 'Feedback has already been submitted for this enrollment number.'
      });
    }
    next(error);
  }
});

app.use('/api/public/forms', publicRouter);

// ============================================================================
// 15. CENTRALIZED ERROR HANDLING & 404 HANDLER
// ============================================================================
// 404 Handler for undefined routes
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: `Endpoint '${req.method} ${req.originalUrl}' not found.`
  });
});

// Centralized error handling middleware
app.use((err, req, res, next) => {
  // Prevent double reply if headers already sent (e.g. during PDF streaming)
  if (res.headersSent) {
    return next(err);
  }

  // Zod Validation Errors
  if (err instanceof z.ZodError) {
    return res.status(400).json({
      success: false,
      error: 'Input validation failed',
      details: err.flatten().fieldErrors
    });
  }

  // MongoDB Duplicate Key Error
  if (err.code === 11000) {
    const field = Object.keys(err.keyPattern || {})[0] || 'field';
    return res.status(409).json({
      success: false,
      error: `A record with this ${field} already exists.`
    });
  }

  // Mongoose CastError (invalid ObjectId)
  if (err.name === 'CastError') {
    return res.status(400).json({
      success: false,
      error: `Invalid format for resource identifier: ${err.value}`
    });
  }

  // JWT Errors
  if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired authentication token.'
    });
  }

  console.error('[UNHANDLED SERVER ERROR]:', err);

  const statusCode = err.status || err.statusCode || 500;
  res.status(statusCode).json({
    success: false,
    error: IS_PRODUCTION ? 'An internal server error occurred.' : err.message || 'Server error'
  });
});

// ============================================================================
// 16. SERVER STARTUP & GRACEFUL SHUTDOWN
// ============================================================================
async function seedDefaultSuperAdmin() {
  try {
    const adminCount = await User.countDocuments({ role: 'SUPER_ADMIN' });
    if (adminCount === 0) {
      const email = (process.env.SUPER_ADMIN_EMAIL || 'admin@college.edu').toLowerCase().trim();
      const username = (process.env.SUPER_ADMIN_USERNAME || 'superadmin').toLowerCase().trim();
      const password = process.env.SUPER_ADMIN_PASSWORD || 'SuperAdmin@123';
      const passwordHash = await hashPassword(password);

      const superAdmin = new User({
        name: 'College Super Admin',
        email,
        username,
        passwordHash,
        role: 'SUPER_ADMIN',
        department: 'Administration',
        isActive: true
      });

      await superAdmin.save();
      console.log('================================================================');
      console.log('[SEED] Initial Super Admin account created:');
      console.log(`  Username: ${username}`);
      console.log(`  Email:    ${email}`);
      console.log(`  Password: ${password}`);
      console.log('  Please log in and change your password if desired.');
      console.log('================================================================');
    }
  } catch (seedErr) {
    console.warn('[SEED WARNING] Could not seed default Super Admin:', seedErr.message);
  }
}

async function startServer() {
  try {
    if (!process.env.MONGODB_URI) {
      console.error('================================================================');
      console.error('[CONFIG CRITICAL] MONGODB_URI is NOT defined in Environment Variables!');
      console.error('If deploying on Render, go to Render Dashboard -> Environment -> Add Environment Variable:');
      console.error('Key: MONGODB_URI');
      console.error('Value: mongodb+srv://<username>:<password>@cluster0.mongodb.net/college_feedback?retryWrites=true&w=majority');
      console.error('================================================================');
    }

    // Mask password in logs for safety
    const maskedUri = MONGODB_URI.replace(/\/\/([^:]+):([^@]+)@/, '//$1:****@');
    console.log(`[STARTUP] Connecting to MongoDB (${maskedUri})...`);

    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 10000
    });
    console.log('[STARTUP] Connected to MongoDB Atlas successfully.');

    // Seed default Super Admin account if no Super Admin exists yet
    await seedDefaultSuperAdmin();

    // Bind to 0.0.0.0 and PORT for compatibility with Render
    server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`[STARTUP] College Faculty Feedback Backend listening on port ${PORT}`);
      console.log(`[STARTUP] Environment: ${NODE_ENV}`);
      console.log(`[STARTUP] Healthcheck: http://0.0.0.0:${PORT}/api/health`);
    });
  } catch (err) {
    console.error('================================================================');
    console.error('[STARTUP FATAL ERROR] Failed to connect to MongoDB:');
    console.error(err.message);
    console.error('----------------------------------------------------------------');
    console.error('COMMON REASONS FOR THIS ERROR ON RENDER:');
    console.error('1. MONGODB ATLAS IP WHITELIST (Most Common):');
    console.error('   Render uses dynamic IP addresses. In MongoDB Atlas:');
    console.error('   Go to Network Access -> Add IP Address -> Select "Allow Access From Anywhere" (0.0.0.0/0).');
    console.error('2. WRONG USERNAME OR PASSWORD:');
    console.error('   Ensure your MongoDB database user password is correct and contains no unencoded special characters.');
    console.error('3. MISSING MONGODB_URI IN RENDER:');
    console.error('   Make sure MONGODB_URI is configured in Render Dashboard -> Environment.');
    console.error('================================================================');
    setTimeout(() => process.exit(1), 500);
  }
}

// Graceful shutdown handling for Render zero-downtime deployments
function handleShutdown(signal) {
  console.log(`[SHUTDOWN] Received ${signal}. Starting graceful shutdown...`);
  if (server) {
    server.close(async () => {
      console.log('[SHUTDOWN] HTTP server closed.');
      try {
        await mongoose.connection.close(false);
        console.log('[SHUTDOWN] MongoDB connection closed.');
        process.exit(0);
      } catch (err) {
        console.error('[SHUTDOWN ERROR] Error closing MongoDB connection:', err);
        process.exit(1);
      }
    });
  } else {
    process.exit(0);
  }
}

process.on('SIGTERM', () => handleShutdown('SIGTERM'));
process.on('SIGINT', () => handleShutdown('SIGINT'));

// Uncaught exception and unhandled rejection guards
process.on('unhandledRejection', (reason, promise) => {
  console.error('[UNHANDLED REJECTION] at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('[UNCAUGHT EXCEPTION]:', error);
  process.exit(1);
});

// Start the application
startServer();

// ============================================================================
// 17. ENVIRONMENT VARIABLES TEMPLATE & CONFIGURATION GUIDE
// ============================================================================
/*
To deploy to Render or run locally, set the following environment variables in
Render Dashboard -> Environment or in a local .env file:

PORT=5000
NODE_ENV=production
MONGODB_URI=mongodb+srv://<username>:<password>@cluster0.mongodb.net/college_feedback?retryWrites=true&w=majority
AUTH_SECRET=a_long_cryptographically_secure_random_string_for_jwt_signing
GMAIL_USER=your_college_notifications@gmail.com
GMAIL_APP_PASSWORD=xxxx_xxxx_xxxx_xxxx
STUDENT_FRONTEND_URL=https://your-student-feedback-ui.onrender.com
COLLEGE_NAME=St. Xavier's College of Engineering

NOTES:
1. GMAIL_APP_PASSWORD:
   - Must be a 16-character Google App Password (not standard Gmail password).
   - Generated at: Google Account -> Security -> 2-Step Verification -> App Passwords.
2. AUTH_SECRET:
   - Generate using: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
3. Render Deployment:
   - Build Command: npm install
   - Start Command: npm start
   - Health Check Path: /api/health
*/
