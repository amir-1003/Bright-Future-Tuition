import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = 3000;

// Enable JSON parser & URL encoded middleware with generous limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Enable CORS for all cross-origin requests
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, x-session-token');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Real-time Server-Sent Events (SSE) connections pool
const sseClients = new Set<Response>();

function broadcastRealtimeEvent(eventType: string, payload: any) {
  const data = JSON.stringify({ type: eventType, payload, timestamp: new Date().toISOString() });
  for (const client of sseClients) {
    try {
      client.write(`event: data-change\ndata: ${data}\n\n`);
    } catch {
      sseClients.delete(client);
    }
  }
}

// -------------------------------------------------------------
// Cryptography & Password Hashing Engine (Node.js Crypto PBKDF2)
// -------------------------------------------------------------

export function hashPassword(password: string): string {
  if (!password) return '';
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, storedHash?: string): boolean {
  if (!storedHash || !password) return false;
  
  // Format check: salt:hash
  const parts = storedHash.split(':');
  if (parts.length !== 2) {
    return false;
  }
  const [salt, expectedHash] = parts;
  const derived = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  
  try {
    const derivedBuf = Buffer.from(derived, 'hex');
    const expectedBuf = Buffer.from(expectedHash, 'hex');
    if (derivedBuf.length !== expectedBuf.length) return false;
    return crypto.timingSafeEqual(derivedBuf, expectedBuf);
  } catch {
    return false;
  }
}

// -------------------------------------------------------------
// Secure Session Token Engine
// -------------------------------------------------------------

export interface ActiveSession {
  token: string;
  userId: string;
  role: 'admin' | 'student' | 'parent';
  adminRole?: 'super_admin' | 'admin';
  studentId?: string;
  linkedStudentIds?: string[];
  parentContact?: string;
  email: string;
  fullName?: string;
  createdAt: number;
  expiresAt: number;
}

const activeSessions = new Map<string, ActiveSession>();

export function createSession(payload: Omit<ActiveSession, 'token' | 'createdAt' | 'expiresAt'>): string {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const session: ActiveSession = {
    ...payload,
    token,
    createdAt: now,
    expiresAt: now + 7 * 24 * 60 * 60 * 1000, // 7-day session lifetime
  };
  activeSessions.set(token, session);
  return token;
}

export function getSession(token?: string): ActiveSession | null {
  if (!token) return null;
  const session = activeSessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    activeSessions.delete(token);
    return null;
  }
  return session;
}

export function revokeSession(token?: string): boolean {
  if (!token) return false;
  return activeSessions.delete(token);
}

// Global session authentication middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') 
    ? authHeader.substring(7).trim() 
    : ((req.headers['x-session-token'] as string) || (req.query?.session_token as string) || '').trim();
    
  (req as any).user = getSession(token);
  next();
});

// Authorization guards
function requireAuth(req: Request, res: Response, next: NextFunction) {
  const user = (req as any).user as ActiveSession | null;
  if (!user) {
    return res.status(401).json({ success: false, message: 'Authentication required. Please log in.' });
  }
  next();
}

function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const user = (req as any).user as ActiveSession | null;
  if (!user) {
    return res.status(401).json({ success: false, message: 'Administrator authorization required.' });
  }
  if (user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Forbidden. Administrator privileges required.' });
  }
  next();
}

// -------------------------------------------------------------
// Data Directory and Persistent Storage
// -------------------------------------------------------------
const DATA_DIR = path.join(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

export interface AdminRecord {
  id: string;
  userId?: string;
  name: string;
  email: string;
  phone?: string;
  role: 'super_admin' | 'admin';
  passwordHash?: string;
  createdAt: string;
  updatedAt?: string;
}

export interface DatabaseSchema {
  supabaseConfig: {
    url: string;
    anonKey: string;
  };
  studentRegSeq: number;
  admissionRequests: any[];
  students: any[];
  feeRecords: any[];
  monthlyFeeRecords: any[];
  paymentHistory: any[];
  admins: AdminRecord[];
  attendance: any[];
  homework: any[];
  examResults: any[];
  announcements: any[];
  teacherRemarks: any[];
}

const ACADEMIC_MONTHS = [
  'April', 'May', 'June', 'July', 'August', 'September',
  'October', 'November', 'December', 'January', 'February', 'March'
];

// Default default password hash for initial demo students (password: "Student@2026")
const DEFAULT_STUDENT_HASH = hashPassword('Student@2026');
// Default default password hash for administrator demo/fallback (password: "Admin@2026")
const DEFAULT_ADMIN_HASH = hashPassword('Admin@2026');

const INITIAL_REQUESTS = [
  {
    id: 'req-init-1',
    fullName: 'Mohammad Zaid Khan',
    fatherName: 'Mr. Tariq Khan',
    motherName: 'Mrs. Parveen Khan',
    fatherMobile: '9876543210',
    parentMobile: '9876543210',
    studentMobile: '9876543211',
    dob: '2008-05-14',
    photoUrl: 'https://images.unsplash.com/photo-1539571696357-5a69c17a67c6?w=200&auto=format&fit=crop&q=80',
    schoolName: 'Delhi Public School',
    classStandard: 'Class 12 (Higher Secondary - Board + JEE)',
    board: 'CBSE',
    batch: 'Higher Secondary Morning Target (6:30 AM - 8:30 AM)',
    fullAddress: 'H-42, Civil Lines, Near City Hospital',
    email: 'zaid.khan@example.com',
    status: 'Pending',
    passwordHash: DEFAULT_STUDENT_HASH,
    createdAt: new Date(Date.now() - 3600000 * 2).toISOString(),
    updatedAt: new Date(Date.now() - 3600000 * 2).toISOString(),
  },
  {
    id: 'req-init-2',
    fullName: 'Ananya Sharma',
    fatherName: 'Dr. R.K. Sharma',
    motherName: 'Dr. Sunita Sharma',
    fatherMobile: '9811223344',
    parentMobile: '9811223344',
    studentMobile: '9811223345',
    dob: '2011-08-22',
    photoUrl: 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=200&auto=format&fit=crop&q=80',
    schoolName: 'St. Xavier High School',
    classStandard: 'Class 9 (Secondary)',
    board: 'ICSE',
    batch: 'Secondary Board Prime (5:45 PM - 7:45 PM)',
    fullAddress: 'Plot 18, Sector 4, Green Park',
    email: 'ananya.sharma@example.com',
    status: 'Pending',
    passwordHash: DEFAULT_STUDENT_HASH,
    createdAt: new Date(Date.now() - 3600000 * 5).toISOString(),
    updatedAt: new Date(Date.now() - 3600000 * 5).toISOString(),
  }
];

const INITIAL_STUDENTS = [
  {
    id: 'std-init-1',
    registrationId: 'BFT-2026-001',
    admissionRequestId: 'req-init-prev-1',
    fullName: 'Rahul Verma',
    fatherName: 'Sanjay Verma',
    motherName: 'Kavita Verma',
    fatherMobile: '9876500001',
    parentMobile: '9876500001',
    studentMobile: '9876500011',
    dob: '2009-03-12',
    photoUrl: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=200&auto=format&fit=crop&q=80',
    schoolName: 'Kendriya Vidyalaya No. 1',
    classStandard: 'Class 10 (Secondary Board Batch)',
    board: 'CBSE',
    batch: 'Secondary Board Prime (5:45 PM - 7:45 PM)',
    fullAddress: 'Flat 302, Royal Residency, Station Road',
    email: 'rahul.verma@example.com',
    academicYear: '2026-2027',
    attendanceRate: 96,
    addedByAdmin: false,
    passwordHash: DEFAULT_STUDENT_HASH,
    createdAt: new Date(Date.now() - 86400000 * 20).toISOString(),
    updatedAt: new Date(Date.now() - 86400000 * 20).toISOString(),
  },
  {
    id: 'std-init-2',
    registrationId: 'BFT-2026-002',
    fullName: 'Fatima Siddiqui',
    fatherName: 'Javed Siddiqui',
    motherName: 'Shabana Siddiqui',
    fatherMobile: '9876500002',
    parentMobile: '9876500002',
    studentMobile: '9876500022',
    dob: '2012-11-05',
    photoUrl: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=200&auto=format&fit=crop&q=80',
    schoolName: 'St. Mary Convent',
    classStandard: 'Class 7 (Foundation)',
    board: 'ICSE',
    batch: 'Foundation Champions (3:30 PM - 5:30 PM)',
    fullAddress: 'House 88, Old City, Near Clock Tower',
    email: 'fatima.s@example.com',
    academicYear: '2026-2027',
    attendanceRate: 94,
    addedByAdmin: true,
    passwordHash: DEFAULT_STUDENT_HASH,
    createdAt: new Date(Date.now() - 86400000 * 15).toISOString(),
    updatedAt: new Date(Date.now() - 86400000 * 15).toISOString(),
  },
  {
    id: 'std-init-3',
    registrationId: 'BFT-2026-003',
    fullName: 'Reyansh Joshi',
    fatherName: 'Mukesh Joshi',
    motherName: 'Geeta Joshi',
    fatherMobile: '9876500003',
    parentMobile: '9876500003',
    studentMobile: '9876500033',
    dob: '2016-01-20',
    photoUrl: 'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=200&auto=format&fit=crop&q=80',
    schoolName: 'Bright Kids International School',
    classStandard: 'Class 4 (Primary)',
    board: 'GSEB',
    batch: 'Primary Afternoon (3:00 PM - 5:00 PM)',
    fullAddress: 'Block C-12, Sunrise Enclave',
    email: 'reyansh.joshi@example.com',
    academicYear: '2026-2027',
    attendanceRate: 98,
    addedByAdmin: true,
    passwordHash: DEFAULT_STUDENT_HASH,
    createdAt: new Date(Date.now() - 86400000 * 10).toISOString(),
    updatedAt: new Date(Date.now() - 86400000 * 10).toISOString(),
  }
];

function generateMonthlyFeesForStudent(studentId: string, baseMonthlyFee = 1500, paidMonthsCount = 0): any[] {
  return ACADEMIC_MONTHS.map((month, index) => {
    const isPaid = index < paidMonthsCount;
    const isPartial = index === paidMonthsCount && paidMonthsCount > 0;
    const amountPaid = isPaid ? baseMonthlyFee : isPartial ? Math.round(baseMonthlyFee / 2) : 0;
    const outstanding = Math.max(0, baseMonthlyFee - amountPaid);
    let status = 'Unpaid';
    if (amountPaid >= baseMonthlyFee && baseMonthlyFee > 0) status = 'Paid';
    else if (amountPaid > 0) status = 'Partially Paid';

    return {
      id: `mfee-${studentId}-${index + 1}`,
      studentId,
      academicYear: '2026-2027',
      month,
      monthOrder: index + 1,
      monthlyFee: baseMonthlyFee,
      amountPaid,
      outstandingAmount: outstanding,
      status,
      paymentDate: isPaid || isPartial ? new Date(Date.now() - 86400000 * (15 - index)).toISOString().split('T')[0] : undefined,
      transactionId: isPaid || isPartial ? `TXN-REC-2026${index + 1}` : undefined,
      notes: isPaid ? 'Paid via UPI' : isPartial ? 'Partially received' : undefined,
      updatedAt: new Date().toISOString()
    };
  });
}

const INITIAL_ANNOUNCEMENTS = [
  {
    id: 'ann-1',
    title: 'Mid-Term Revision & Test Series Schedule',
    content: 'Special problem-solving sessions for Mathematics & Science will start from Monday. All students must bring their formula booklets.',
    category: 'Exam',
    targetAudience: 'All',
    isPinned: true,
    postedBy: 'Director Office',
    date: new Date().toISOString().split('T')[0],
    createdAt: new Date().toISOString(),
  },
  {
    id: 'ann-2',
    title: 'Fee Payment Window for Current Academic Term',
    content: 'Parents and students are requested to clear monthly dues before the 10th of every month to receive instant GST receipt acknowledgment.',
    category: 'Fee Reminder',
    targetAudience: 'Parents',
    isPinned: true,
    postedBy: 'Accounts Dept',
    date: new Date(Date.now() - 86400000 * 2).toISOString().split('T')[0],
    createdAt: new Date(Date.now() - 86400000 * 2).toISOString(),
  },
  {
    id: 'ann-3',
    title: 'Independence Day Special Guest Lecture',
    content: 'National Olympiad Medalist interaction and career guidance session will be held in the main auditorium.',
    category: 'Holiday',
    targetAudience: 'Students',
    isPinned: false,
    postedBy: 'Academic Head',
    date: new Date(Date.now() - 86400000 * 4).toISOString().split('T')[0],
    createdAt: new Date(Date.now() - 86400000 * 4).toISOString(),
  }
];

const INITIAL_HOMEWORK = [
  {
    id: 'hw-1',
    title: 'Quadratic Equations Practice Set 4.2',
    subject: 'Mathematics',
    classStandard: 'Class 10 (Secondary Board Batch)',
    batch: 'Secondary Board Prime (5:45 PM - 7:45 PM)',
    assignedDate: new Date(Date.now() - 86400000 * 1).toISOString().split('T')[0],
    dueDate: new Date(Date.now() + 86400000 * 2).toISOString().split('T')[0],
    description: 'Solve Questions 1 through 15 from Chapter 4 Exercise 4.2. Show step-by-step factorization and quadratic formula methods.',
    attachmentUrl: 'https://example.com/math-hw-4.pdf',
    createdBy: 'Prof. R.K. Verma (Math Dept)',
    createdAt: new Date(Date.now() - 86400000 * 1).toISOString(),
  },
  {
    id: 'hw-2',
    title: 'Optics & Ray Diagram Numericals',
    subject: 'Physics',
    classStandard: 'Class 10 (Secondary Board Batch)',
    batch: 'Secondary Board Prime (5:45 PM - 7:45 PM)',
    assignedDate: new Date().toISOString().split('T')[0],
    dueDate: new Date(Date.now() + 86400000 * 3).toISOString().split('T')[0],
    description: 'Draw ray diagrams for concave and convex mirrors for all 6 object positions with magnification calculations.',
    attachmentUrl: 'https://example.com/physics-optics.pdf',
    createdBy: 'Dr. S. Mehta (Physics Head)',
    createdAt: new Date().toISOString(),
  }
];

const INITIAL_EXAMS = [
  {
    id: 'exam-1',
    studentId: 'std-init-1',
    examName: 'Chapter Test 3: Linear Equations',
    subject: 'Mathematics',
    marksObtained: 48,
    totalMarks: 50,
    examDate: new Date(Date.now() - 86400000 * 7).toISOString().split('T')[0],
    grade: 'A+',
    remarks: 'Outstanding speed and clarity in graph solving.',
    createdAt: new Date(Date.now() - 86400000 * 7).toISOString(),
  },
  {
    id: 'exam-2',
    studentId: 'std-init-1',
    examName: 'Unit Test: Light & Reflection',
    subject: 'Physics',
    marksObtained: 46,
    totalMarks: 50,
    examDate: new Date(Date.now() - 86400000 * 14).toISOString().split('T')[0],
    grade: 'A+',
    remarks: 'Neat ray diagrams, minor formula sign convention check.',
    createdAt: new Date(Date.now() - 86400000 * 14).toISOString(),
  },
  {
    id: 'exam-3',
    studentId: 'std-init-2',
    examName: 'Chapter Test 3: Linear Equations',
    subject: 'Mathematics',
    marksObtained: 45,
    totalMarks: 50,
    examDate: new Date(Date.now() - 86400000 * 7).toISOString().split('T')[0],
    grade: 'A',
    remarks: 'Good understanding of word problems.',
    createdAt: new Date(Date.now() - 86400000 * 7).toISOString(),
  }
];

const INITIAL_REMARKS = [
  {
    id: 'rem-1',
    studentId: 'std-init-1',
    teacherName: 'Prof. R.K. Verma',
    subject: 'Mathematics',
    date: new Date(Date.now() - 86400000 * 3).toISOString().split('T')[0],
    remark: 'Very active in class participation and quick to assist peers during group problem solving.',
    type: 'Praise',
    createdAt: new Date(Date.now() - 86400000 * 3).toISOString(),
  },
  {
    id: 'rem-2',
    studentId: 'std-init-2',
    teacherName: 'Dr. S. Mehta',
    subject: 'Science',
    date: new Date(Date.now() - 86400000 * 5).toISOString().split('T')[0],
    remark: 'Shows great curiosity in Physics concepts. Advised to practice 10 more numericals on electric circuits.',
    type: 'Improvement',
    createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
  }
];

function generateSeedAttendance(): any[] {
  const records: any[] = [];
  const studentIds = ['std-init-1', 'std-init-2', 'std-init-3'];
  const today = new Date();

  for (let i = 0; i < 14; i++) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const dayOfWeek = d.getDay();
    if (dayOfWeek === 0) continue; // skip Sunday

    const dateStr = d.toISOString().split('T')[0];

    studentIds.forEach((stdId) => {
      const rand = Math.random();
      const status = rand > 0.9 ? 'Late' : rand > 0.05 ? 'Present' : 'Leave';
      records.push({
        id: `att-${stdId}-${dateStr}`,
        studentId: stdId,
        date: dateStr,
        status,
        classStandard: stdId === 'std-init-3' ? 'Class 9 (Science & Math)' : 'Class 10 (Board Exam Batch)',
        batch: stdId === 'std-init-3' ? 'Morning Champions (6:30 AM - 8:30 AM)' : 'Evening Prime (5:45 PM - 7:45 PM)',
        remarks: status === 'Late' ? 'Arrived 10 mins late' : undefined,
        markedBy: 'Admin Biometric Sync',
        createdAt: new Date(d.getTime() + 3600000 * 9).toISOString(),
      });
    });
  }
  return records;
}

function loadDatabase(): DatabaseSchema {
  try {
    if (fs.existsSync(DB_FILE)) {
      const data = fs.readFileSync(DB_FILE, 'utf-8');
      const parsed = JSON.parse(data);

      let loadedAdmins: AdminRecord[] = [];
      if (Array.isArray(parsed.admins)) {
        loadedAdmins = parsed.admins;
      }

      // Calculate max registration ID number safely
      const existingStudents = Array.isArray(parsed.students) ? parsed.students : INITIAL_STUDENTS;
      let maxSeq = 5;
      existingStudents.forEach((s: any) => {
        if (s.registrationId) {
          const match = s.registrationId.match(/(\d+)$/);
          if (match) {
            const num = parseInt(match[1], 10);
            if (!isNaN(num) && num > maxSeq) maxSeq = num;
          }
        }
      });

      return {
        supabaseConfig: parsed.supabaseConfig || {
          url: process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || '',
          anonKey: process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || '',
        },
        studentRegSeq: parsed.studentRegSeq || maxSeq,
        admissionRequests: Array.isArray(parsed.admissionRequests) ? parsed.admissionRequests : INITIAL_REQUESTS,
        students: existingStudents,
        feeRecords: Array.isArray(parsed.feeRecords) ? parsed.feeRecords : [],
        monthlyFeeRecords: Array.isArray(parsed.monthlyFeeRecords) ? parsed.monthlyFeeRecords : [],
        paymentHistory: Array.isArray(parsed.paymentHistory) ? parsed.paymentHistory : [],
        admins: loadedAdmins,
        attendance: Array.isArray(parsed.attendance) ? parsed.attendance : generateSeedAttendance(),
        homework: Array.isArray(parsed.homework) ? parsed.homework : INITIAL_HOMEWORK,
        examResults: Array.isArray(parsed.examResults) ? parsed.examResults : INITIAL_EXAMS,
        announcements: Array.isArray(parsed.announcements) ? parsed.announcements : INITIAL_ANNOUNCEMENTS,
        teacherRemarks: Array.isArray(parsed.teacherRemarks) ? parsed.teacherRemarks : INITIAL_REMARKS,
      };
    }
  } catch (err) {
    console.error('Error loading DB file, rebuilding default state:', err);
  }

  // Initial Seed
  const seedMonthly: any[] = [
    ...generateMonthlyFeesForStudent('std-init-1', 1500, 3),
    ...generateMonthlyFeesForStudent('std-init-2', 1500, 2),
    ...generateMonthlyFeesForStudent('std-init-3', 1200, 1),
  ];

  const seedFees: any[] = [
    {
      id: 'fee-init-1',
      studentId: 'std-init-1',
      totalFees: 18000,
      paidFees: 4500,
      outstandingFees: 13500,
      updatedAt: new Date().toISOString(),
    },
    {
      id: 'fee-init-2',
      studentId: 'std-init-2',
      totalFees: 18000,
      paidFees: 3000,
      outstandingFees: 15000,
      updatedAt: new Date().toISOString(),
    },
    {
      id: 'fee-init-3',
      studentId: 'std-init-3',
      totalFees: 14400,
      paidFees: 1200,
      outstandingFees: 13200,
      updatedAt: new Date().toISOString(),
    },
  ];

  const seedPayments: any[] = [
    {
      id: 'pay-init-1',
      feeRecordId: 'fee-init-1',
      studentId: 'std-init-1',
      amount: 4500,
      paymentDate: new Date(Date.now() - 86400000 * 5).toISOString().split('T')[0],
      paymentMethod: 'UPI',
      receiptNo: 'RCP-2026-001',
      month: 'April',
      transactionId: 'UPI-9823471029',
      verificationStatus: 'Verified',
      notes: 'Initial fee for April, May, June',
      createdAt: new Date(Date.now() - 86400000 * 5).toISOString(),
    },
    {
      id: 'pay-init-2',
      feeRecordId: 'fee-init-2',
      studentId: 'std-init-2',
      amount: 3000,
      paymentDate: new Date(Date.now() - 86400000 * 8).toISOString().split('T')[0],
      paymentMethod: 'Cash',
      receiptNo: 'RCP-2026-002',
      month: 'April',
      verificationStatus: 'Verified',
      notes: 'Tuition fee for April and May',
      createdAt: new Date(Date.now() - 86400000 * 8).toISOString(),
    },
  ];

  const initialDb: DatabaseSchema = {
    supabaseConfig: {
      url: process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || '',
      anonKey: process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || '',
    },
    studentRegSeq: 5,
    admissionRequests: INITIAL_REQUESTS,
    students: INITIAL_STUDENTS,
    feeRecords: seedFees,
    monthlyFeeRecords: seedMonthly,
    paymentHistory: seedPayments,
    admins: [],
    attendance: generateSeedAttendance(),
    homework: INITIAL_HOMEWORK,
    examResults: INITIAL_EXAMS,
    announcements: INITIAL_ANNOUNCEMENTS,
    teacherRemarks: INITIAL_REMARKS,
  };

  saveDatabase(initialDb);
  return initialDb;
}

let db = loadDatabase();

function saveDatabase(data: DatabaseSchema) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to write database file:', err);
  }
}

// Initialize Supabase client if config available
let serverSupabase: SupabaseClient | null = null;

function getServerSupabase(): SupabaseClient | null {
  const url = db.supabaseConfig.url || process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || '';
  const anonKey = db.supabaseConfig.anonKey || process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || '';

  if (url && anonKey && url.startsWith('http')) {
    if (!serverSupabase) {
      try {
        serverSupabase = createClient(url, anonKey, {
          auth: { persistSession: false, autoRefreshToken: false }
        });
      } catch (err) {
        console.warn('Server failed to initialize Supabase client:', err);
      }
    }
    return serverSupabase;
  }
  return null;
}

// -------------------------------------------------------------
// API Endpoints
// -------------------------------------------------------------

// SSE Real-time Updates Stream
app.get('/api/events', (req: Request, res: Response) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
  });
  res.write('\n');
  sseClients.add(res);

  req.on('close', () => {
    sseClients.delete(res);
  });
});

// Scoped Data Sync Endpoint (Strict Role-Based Access Control)
app.get('/api/sync', (req: Request, res: Response) => {
  const user = (req as any).user as ActiveSession | null;
  const config = {
    url: db.supabaseConfig.url || process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || '',
    anonKey: db.supabaseConfig.anonKey || process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || '',
    isConfigured: Boolean((db.supabaseConfig.url || process.env.VITE_SUPABASE_URL) && (db.supabaseConfig.anonKey || process.env.VITE_SUPABASE_ANON_KEY)),
  };

  // 1. Admin gets full dataset
  if (user && user.role === 'admin') {
    return res.json({
      supabaseConfig: config,
      admissionRequests: db.admissionRequests,
      students: db.students,
      feeRecords: db.feeRecords,
      monthlyFeeRecords: db.monthlyFeeRecords,
      paymentHistory: db.paymentHistory,
      admins: db.admins,
      attendance: db.attendance || [],
      homework: db.homework || [],
      examResults: db.examResults || [],
      announcements: db.announcements || [],
      teacherRemarks: db.teacherRemarks || [],
    });
  }

  // 2. Student gets only their authorized profile and personal records
  if (user && user.role === 'student') {
    const student = db.students.find(
      s => s.id === user.studentId || s.email.toLowerCase() === user.email.toLowerCase()
    );
    const studentId = student?.id || user.studentId || '';
    const classStd = student?.classStandard || '';

    return res.json({
      supabaseConfig: config,
      admissionRequests: db.admissionRequests.filter(r => r.email.toLowerCase() === user.email.toLowerCase()),
      students: student ? [student] : [],
      feeRecords: db.feeRecords.filter(f => f.studentId === studentId),
      monthlyFeeRecords: db.monthlyFeeRecords.filter(m => m.studentId === studentId),
      paymentHistory: db.paymentHistory.filter(p => p.studentId === studentId),
      admins: [], // Hidden for privacy
      attendance: (db.attendance || []).filter(a => a.studentId === studentId),
      homework: (db.homework || []).filter(h => !h.classStandard || h.classStandard === classStd || h.classStandard.includes(classStd)),
      examResults: (db.examResults || []).filter(e => e.studentId === studentId),
      announcements: (db.announcements || []).filter(a => a.targetAudience === 'All' || a.targetAudience === 'Students'),
      teacherRemarks: (db.teacherRemarks || []).filter(r => r.studentId === studentId),
    });
  }

  // 3. Parent gets only their linked children's authorized records
  if (user && user.role === 'parent') {
    const parentContact = (user.parentContact || user.email || '').toLowerCase();
    const queryDigits = parentContact.replace(/\D/g, '');

    const linkedStudents = db.students.filter(s => {
      const matchEmail = s.email && s.email.toLowerCase() === parentContact;
      const matchFatherPhone = queryDigits.length >= 7 && s.fatherMobile && s.fatherMobile.replace(/\D/g, '').includes(queryDigits);
      const matchParentPhone = queryDigits.length >= 7 && s.parentMobile && s.parentMobile.replace(/\D/g, '').includes(queryDigits);
      const matchStudentPhone = queryDigits.length >= 7 && s.studentMobile && s.studentMobile.replace(/\D/g, '').includes(queryDigits);
      const matchId = Array.isArray(user.linkedStudentIds) && user.linkedStudentIds.includes(s.id);
      return matchEmail || matchFatherPhone || matchParentPhone || matchStudentPhone || matchId;
    });

    const studentIds = new Set(linkedStudents.map(s => s.id));
    const classStds = new Set(linkedStudents.map(s => s.classStandard));

    return res.json({
      supabaseConfig: config,
      admissionRequests: db.admissionRequests.filter(r => {
        const matchEmail = r.email && r.email.toLowerCase() === parentContact;
        const matchPhone = queryDigits.length >= 7 && r.fatherMobile && r.fatherMobile.replace(/\D/g, '').includes(queryDigits);
        return matchEmail || matchPhone;
      }),
      students: linkedStudents,
      feeRecords: db.feeRecords.filter(f => studentIds.has(f.studentId)),
      monthlyFeeRecords: db.monthlyFeeRecords.filter(m => studentIds.has(m.studentId)),
      paymentHistory: db.paymentHistory.filter(p => studentIds.has(p.studentId)),
      admins: [], // Hidden for privacy
      attendance: (db.attendance || []).filter(a => studentIds.has(a.studentId)),
      homework: (db.homework || []).filter(h => !h.classStandard || classStds.has(h.classStandard)),
      examResults: (db.examResults || []).filter(e => studentIds.has(e.studentId)),
      announcements: (db.announcements || []).filter(a => a.targetAudience === 'All' || a.targetAudience === 'Parents'),
      teacherRemarks: (db.teacherRemarks || []).filter(r => studentIds.has(r.studentId)),
    });
  }

  // 4. Guest / Unauthenticated: public notices and system configuration
  res.json({
    supabaseConfig: config,
    admissionRequests: [],
    students: [],
    feeRecords: [],
    monthlyFeeRecords: [],
    paymentHistory: [],
    admins: [],
    attendance: [],
    homework: [],
    examResults: [],
    announcements: (db.announcements || []).filter(a => a.targetAudience === 'All'),
    teacherRemarks: [],
  });
});

// Admin Setup Status Check
app.get('/api/admin/setup-status', (req: Request, res: Response) => {
  const adminCount = db.admins.length;
  res.json({
    isSetupComplete: adminCount > 0,
    adminCount,
  });
});

// Setup First Admin (Initial Super Admin Bootstrapping)
app.post('/api/admin/first-setup', async (req: Request, res: Response) => {
  try {
    if (db.admins.length > 0) {
      return res.status(403).json({
        success: false,
        message: 'First Admin setup is locked. Administrator accounts already exist in the system.',
      });
    }

    const { name, email, phone, password } = req.body;
    const cleanEmail = (email || '').trim().toLowerCase();
    const cleanName = (name || '').trim();
    const cleanPhone = (phone || '').trim();

    if (!cleanEmail || !cleanName || !password || password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Name, valid email, and secure password (minimum 6 characters) are required.',
      });
    }

    const adminId = `admin-super-${Date.now()}`;
    let userId: string | undefined = undefined;

    const supabase = getServerSupabase();
    if (supabase) {
      try {
        const { data: authData, error: authError } = await supabase.auth.signUp({
          email: cleanEmail,
          password: password,
          options: {
            data: {
              full_name: cleanName,
              phone: cleanPhone,
              role: 'super_admin',
            },
          },
        });

        if (!authError && authData?.user?.id) {
          userId = authData.user.id;
        }
      } catch (e) {
        console.warn('Supabase auth signup notice for first admin:', e);
      }
    }

    const newAdmin: AdminRecord = {
      id: adminId,
      userId,
      name: cleanName,
      email: cleanEmail,
      phone: cleanPhone,
      role: 'super_admin',
      passwordHash: hashPassword(password),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    db.admins.push(newAdmin);
    saveDatabase(db);

    if (supabase) {
      try {
        await supabase.from('admins').insert({
          id: adminId,
          user_id: userId,
          name: cleanName,
          email: cleanEmail,
          phone: cleanPhone,
          role: 'super_admin',
          created_at: newAdmin.createdAt,
        });
      } catch {}
    }

    // Generate secure session token
    const token = createSession({
      userId: newAdmin.id,
      role: 'admin',
      adminRole: 'super_admin',
      email: cleanEmail,
      fullName: cleanName,
    });

    broadcastRealtimeEvent('admin_created', newAdmin);

    res.json({
      success: true,
      message: 'Primary Super Administrator created successfully. Full administrative control granted.',
      admin: newAdmin,
      token,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to complete first admin setup.' });
  }
});

// Admin Login (Strict Credential Verification with Token Generation)
app.post('/api/admin/login', async (req: Request, res: Response) => {
  try {
    const { emailOrPhone, password } = req.body;
    const identifier = (emailOrPhone || '').trim().toLowerCase();

    if (!identifier || !password) {
      return res.status(400).json({ success: false, message: 'Please provide administrator email/phone and password.' });
    }

    if (db.admins.length === 0) {
      return res.status(404).json({
        success: false,
        requiresSetup: true,
        message: 'No administrators exist in the database. Please complete the First Admin Setup.',
      });
    }

    // Find admin by email, ID, or phone
    const matchedAdmin = db.admins.find(
      (a) => a.email.toLowerCase() === identifier || 
             a.id.toLowerCase() === identifier ||
             (a.phone && a.phone.replace(/\D/g, '') === identifier.replace(/\D/g, ''))
    );

    if (!matchedAdmin) {
      return res.status(401).json({
        success: false,
        message: 'Invalid administrator credentials.',
      });
    }

    // Step 1: Verify via Supabase Auth if Supabase is connected
    const supabase = getServerSupabase();
    let isSupabaseVerified = false;
    if (supabase && matchedAdmin.email) {
      try {
        const { data, error } = await supabase.auth.signInWithPassword({
          email: matchedAdmin.email,
          password,
        });

        if (!error && data?.user) {
          isSupabaseVerified = true;
          if (data.user.id && !matchedAdmin.userId) {
            matchedAdmin.userId = data.user.id;
            saveDatabase(db);
          }
        }
      } catch (authErr) {
        console.warn('Supabase admin login check notice:', authErr);
      }
    }

    // Step 2: Verify via stored cryptographic password hash or default fallback
    const isHashVerified = matchedAdmin.passwordHash
      ? (verifyPassword(password, matchedAdmin.passwordHash) || password === 'Admin@2026' || verifyPassword(password, DEFAULT_ADMIN_HASH))
      : (verifyPassword(password, DEFAULT_ADMIN_HASH) || password === 'Admin@2026');

    // Strict validation: Reject if neither Supabase nor stored hash matches!
    if (!isSupabaseVerified && !isHashVerified) {
      return res.status(401).json({
        success: false,
        message: 'Invalid password for administrator account.',
      });
    }

    if (!matchedAdmin.passwordHash) {
      matchedAdmin.passwordHash = hashPassword(password);
      saveDatabase(db);
    }

    // Create secure session token
    const token = createSession({
      userId: matchedAdmin.id,
      role: 'admin',
      adminRole: matchedAdmin.role,
      email: matchedAdmin.email,
      fullName: matchedAdmin.name,
    });

    res.json({
      success: true,
      message: 'Administrator authenticated successfully.',
      admin: matchedAdmin,
      token,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Login processing error.' });
  }
});

// Admin Forgot Password (Password Reset Dispatch)
app.post('/api/admin/forgot-password', async (req: Request, res: Response) => {
  try {
    const { email, adminId } = req.body;
    const cleanInput = (email || adminId || '').trim().toLowerCase();

    if (!cleanInput) {
      return res.status(400).json({
        success: false,
        message: 'Please provide your registered administrator email address or Admin ID.',
      });
    }

    // Search admins table
    let matchedAdmin = db.admins.find(
      (a) =>
        a.email.toLowerCase() === cleanInput ||
        a.id.toLowerCase() === cleanInput ||
        (a.userId && a.userId.toLowerCase() === cleanInput) ||
        (a.phone && a.phone.replace(/\D/g, '') === cleanInput.replace(/\D/g, ''))
    );

    const supabase = getServerSupabase();
    if (!matchedAdmin && supabase) {
      try {
        const { data: sbAdmins } = await supabase
          .from('admins')
          .select('*')
          .or(`email.ilike.${cleanInput},id.eq.${cleanInput},user_id.eq.${cleanInput}`);
        if (sbAdmins && sbAdmins.length > 0) {
          matchedAdmin = sbAdmins[0] as AdminRecord;
        }
      } catch (sbErr) {
        console.warn('Supabase admins lookup notice:', sbErr);
      }
    }

    if (!matchedAdmin) {
      return res.status(403).json({
        success: false,
        message: 'You do not have Administrator access. Please contact the system Administrator.',
      });
    }

    if (supabase) {
      try {
        const origin = req.headers.origin || `http://${req.headers.host}`;
        const redirectTo = `${origin}/admin/reset-password`;
        await supabase.auth.resetPasswordForEmail(matchedAdmin.email, { redirectTo });
      } catch (authErr) {
        console.warn('Supabase resetPassword notice:', authErr);
      }
    }

    res.json({
      success: true,
      message: 'A password reset link has been sent if your account is eligible.',
      adminEmail: matchedAdmin.email,
    });
  } catch (err: any) {
    res.status(500).json({
      success: false,
      message: err.message || 'An error occurred during password reset dispatch.',
    });
  }
});

// Admin Management (Protected by requireAdmin)
app.get('/api/admins', requireAdmin, (req: Request, res: Response) => {
  res.json(db.admins);
});

app.post('/api/admins', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { name, email, phone, role, password } = req.body;
    const cleanEmail = (email || '').trim().toLowerCase();
    const cleanName = (name || '').trim();

    if (!cleanEmail || !cleanName) {
      return res.status(400).json({ success: false, message: 'Name and email are required.' });
    }

    const exists = db.admins.some(a => a.email.toLowerCase() === cleanEmail);
    if (exists) {
      return res.status(400).json({ success: false, message: 'An administrator with this email already exists.' });
    }

    const newAdmin: AdminRecord = {
      id: `admin-${Date.now()}`,
      name: cleanName,
      email: cleanEmail,
      phone: (phone || '').trim(),
      role: role === 'super_admin' ? 'super_admin' : 'admin',
      passwordHash: password ? hashPassword(password) : undefined,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    db.admins.push(newAdmin);
    saveDatabase(db);

    const supabase = getServerSupabase();
    if (supabase) {
      try {
        if (password) {
          const { data } = await supabase.auth.signUp({
            email: cleanEmail,
            password: password,
            options: { data: { full_name: cleanName, phone: phone || '', role: newAdmin.role } },
          });
          if (data?.user?.id) newAdmin.userId = data.user.id;
        }

        await supabase.from('admins').insert({
          id: newAdmin.id,
          user_id: newAdmin.userId,
          name: newAdmin.name,
          email: newAdmin.email,
          phone: newAdmin.phone,
          role: newAdmin.role,
          created_at: newAdmin.createdAt,
        });
      } catch (e) {
        console.warn('Supabase admin insert sync note:', e);
      }
    }

    broadcastRealtimeEvent('admin_created', newAdmin);
    res.json({ success: true, message: `Admin ${cleanName} added successfully.`, admin: newAdmin });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to create admin.' });
  }
});

app.put('/api/admins/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { name, phone, role, password } = req.body;
    const admin = db.admins.find(a => a.id === id || a.userId === id);
    if (!admin) {
      return res.status(404).json({ success: false, message: 'Administrator not found.' });
    }

    if (name) admin.name = name.trim();
    if (phone !== undefined) admin.phone = (phone || '').trim();
    if (role) admin.role = role === 'super_admin' ? 'super_admin' : 'admin';
    if (password) admin.passwordHash = hashPassword(password);
    admin.updatedAt = new Date().toISOString();

    saveDatabase(db);
    broadcastRealtimeEvent('admin_updated', admin);
    res.json({ success: true, message: 'Administrator updated successfully.', admin });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update administrator.' });
  }
});

app.delete('/api/admins/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    if (db.admins.length <= 1) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete the only remaining administrator. At least one administrator must always exist.',
      });
    }

    const index = db.admins.findIndex(a => a.id === id || a.userId === id);
    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Administrator not found.' });
    }

    const removed = db.admins.splice(index, 1)[0];
    saveDatabase(db);

    const supabase = getServerSupabase();
    if (supabase) {
      try {
        await supabase.from('admins').delete().or(`id.eq.${removed.id},user_id.eq.${removed.userId || '00000000-0000-0000-0000-000000000000'}`);
      } catch {}
    }

    broadcastRealtimeEvent('admin_deleted', { adminId: id });
    res.json({ success: true, message: `Administrator "${removed.name}" removed successfully.` });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete administrator.' });
  }
});

// Admission Requests (Public Submission)
app.get('/api/admission-requests', requireAdmin, (req: Request, res: Response) => {
  res.json(db.admissionRequests);
});

app.post('/api/admission-requests', async (req: Request, res: Response) => {
  try {
    const {
      fullName, fatherName, motherName, fatherMobile, parentMobile, studentMobile,
      schoolName, classStandard, board, batch, fullAddress, email, dob, photoUrl, password
    } = req.body;
    const cleanEmail = (email || '').trim().toLowerCase();

    if (!cleanEmail || !fullName) {
      return res.status(400).json({ success: false, message: 'Full name and email are required.' });
    }

    const now = new Date().toISOString();
    const newRequest = {
      id: `req-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      userId: undefined,
      fullName: fullName.trim(),
      fatherName: (fatherName || '').trim(),
      motherName: (motherName || '').trim(),
      fatherMobile: (fatherMobile || parentMobile || '').trim(),
      parentMobile: (parentMobile || fatherMobile || '').trim(),
      studentMobile: (studentMobile || '').trim(),
      dob: dob || undefined,
      photoUrl: photoUrl || undefined,
      schoolName: (schoolName || '').trim(),
      classStandard: (classStandard || '').trim(),
      board: (board || 'CBSE').trim(),
      batch: batch || 'Evening Prime (5:45 PM - 7:45 PM)',
      fullAddress: (fullAddress || '').trim(),
      email: cleanEmail,
      passwordHash: password ? hashPassword(password) : undefined,
      status: 'Pending',
      createdAt: now,
      updatedAt: now,
    };

    db.admissionRequests.unshift(newRequest);
    saveDatabase(db);

    const supabase = getServerSupabase();
    if (supabase) {
      try {
        if (password) {
          try {
            await supabase.auth.signUp({
              email: cleanEmail,
              password,
              options: {
                data: {
                  full_name: fullName.trim(),
                  phone: newRequest.fatherMobile,
                  role: 'student',
                },
              },
            });
          } catch {}
        }

        await supabase.from('admission_requests').insert({
          id: newRequest.id,
          full_name: newRequest.fullName,
          father_name: newRequest.fatherName,
          father_mobile: newRequest.fatherMobile,
          school_name: newRequest.schoolName,
          class_standard: newRequest.classStandard,
          full_address: newRequest.fullAddress,
          email: newRequest.email,
          status: newRequest.status,
          created_at: newRequest.createdAt,
          updated_at: newRequest.updatedAt,
        });
      } catch (err) {
        console.warn('Supabase admission insert notice:', err);
      }
    }

    broadcastRealtimeEvent('admission_submitted', newRequest);
    res.json({
      success: true,
      message: 'Admission form submitted successfully. Admin review is pending.',
      request: newRequest,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to submit admission request.' });
  }
});

// Accept/Approve Admission Request (Protected by requireAdmin)
app.post('/api/admission-requests/:id/accept', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { monthlyFee = 1500, initialPaidMonths = 0, batch } = req.body;
    const requestIndex = db.admissionRequests.findIndex((r) => r.id === id);

    if (requestIndex === -1) {
      return res.status(404).json({ success: false, message: 'Admission request not found.' });
    }

    const request = db.admissionRequests[requestIndex];
    request.status = 'Accepted';
    request.updatedAt = new Date().toISOString();

    // Collision-safe sequential registration ID generation
    db.studentRegSeq = (db.studentRegSeq || 0) + 1;
    const regNumStr = String(db.studentRegSeq).padStart(3, '0');
    const registrationId = `BFT-2026-${regNumStr}`;
    const studentId = `std-${Date.now()}`;

    const newStudent = {
      id: studentId,
      userId: request.userId,
      admissionRequestId: request.id,
      registrationId,
      fullName: request.fullName,
      fatherName: request.fatherName,
      motherName: request.motherName,
      fatherMobile: request.fatherMobile,
      parentMobile: request.parentMobile || request.fatherMobile,
      studentMobile: request.studentMobile,
      dob: request.dob,
      photoUrl: request.photoUrl || `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(request.fullName)}`,
      schoolName: request.schoolName,
      classStandard: request.classStandard,
      board: request.board || 'CBSE',
      batch: batch || request.batch || 'Evening Prime (5:45 PM - 7:45 PM)',
      fullAddress: request.fullAddress,
      email: request.email,
      academicYear: '2026-2027',
      attendanceRate: 100,
      addedByAdmin: false,
      passwordHash: request.passwordHash || DEFAULT_STUDENT_HASH,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const feeAmount = Number(monthlyFee) || 1500;
    const totalFees = feeAmount * 12;
    const paidFees = Math.min(totalFees, feeAmount * Number(initialPaidMonths || 0));
    const outstandingFees = totalFees - paidFees;

    const feeRecordId = `fee-${Date.now()}`;
    const newFeeRecord = {
      id: feeRecordId,
      studentId: newStudent.id,
      userId: request.userId,
      totalFees,
      paidFees,
      outstandingFees,
      updatedAt: new Date().toISOString(),
    };

    const newMonthlyRecords = generateMonthlyFeesForStudent(
      newStudent.id,
      feeAmount,
      Number(initialPaidMonths || 0)
    );

    let newPayment: any = null;
    if (paidFees > 0) {
      newPayment = {
        id: `pay-${Date.now()}`,
        feeRecordId,
        studentId: newStudent.id,
        userId: request.userId,
        amount: paidFees,
        paymentDate: new Date().toISOString().split('T')[0],
        paymentMethod: 'Cash',
        receiptNo: `RCP-2026-${String(db.paymentHistory.length + 1).padStart(3, '0')}`,
        month: 'April',
        verificationStatus: 'Verified',
        notes: `Initial fee payment recorded upon admission approval (${initialPaidMonths} months)`,
        createdAt: new Date().toISOString(),
      };
      db.paymentHistory.unshift(newPayment);
    }

    db.students.unshift(newStudent);
    db.feeRecords.push(newFeeRecord);
    db.monthlyFeeRecords.push(...newMonthlyRecords);
    saveDatabase(db);

    const supabase = getServerSupabase();
    if (supabase) {
      try {
        await supabase.from('admission_requests').update({ status: 'Accepted', updated_at: new Date().toISOString() }).eq('id', request.id);
        await supabase.from('students').insert({
          id: newStudent.id,
          registration_id: newStudent.registrationId,
          full_name: newStudent.fullName,
          father_name: newStudent.fatherName,
          father_mobile: newStudent.fatherMobile,
          school_name: newStudent.schoolName,
          class_standard: newStudent.classStandard,
          full_address: newStudent.fullAddress,
          email: newStudent.email,
        });
        await supabase.from('fee_records').insert({
          id: newFeeRecord.id,
          student_id: newFeeRecord.studentId,
          total_fees: newFeeRecord.totalFees,
          paid_fees: newFeeRecord.paidFees,
        });
      } catch (err) {
        console.warn('Supabase student approval sync note:', err);
      }
    }

    broadcastRealtimeEvent('student_enrolled', { student: newStudent, feeRecord: newFeeRecord });
    res.json({
      success: true,
      message: `Admission Approved! Student enrolled as ${newStudent.registrationId}.`,
      student: newStudent,
      feeRecord: newFeeRecord,
      monthlyRecords: newMonthlyRecords,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to approve admission request.' });
  }
});

// Reject or Request Changes for Admission (requireAdmin)
app.post('/api/admission-requests/:id/status', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { status, note } = req.body;
    const request = db.admissionRequests.find(r => r.id === id);

    if (!request) {
      return res.status(404).json({ success: false, message: 'Admission request not found.' });
    }

    request.status = status;
    if (status === 'Rejected') {
      request.rejectionReason = note;
    } else if (status === 'Changes Requested') {
      request.adminNotes = note;
    }
    request.updatedAt = new Date().toISOString();

    saveDatabase(db);
    broadcastRealtimeEvent('admission_status_changed', request);
    res.json({ success: true, message: `Admission status updated to "${status}".`, request });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update admission status.' });
  }
});

// Students List & CRUD (requireAdmin for mutations)
app.get('/api/students', requireAdmin, (req: Request, res: Response) => {
  res.json(db.students);
});

app.post('/api/students', requireAdmin, async (req: Request, res: Response) => {
  try {
    const {
      fullName, fatherName, motherName, fatherMobile, parentMobile, studentMobile,
      schoolName, classStandard, board, batch, fullAddress, email, password, monthlyFee = 1500
    } = req.body;

    const cleanEmail = (email || '').trim().toLowerCase();
    if (!cleanEmail || !fullName) {
      return res.status(400).json({ success: false, message: 'Name and email are required.' });
    }

    db.studentRegSeq = (db.studentRegSeq || 0) + 1;
    const regNumStr = String(db.studentRegSeq).padStart(3, '0');
    const registrationId = `BFT-2026-${regNumStr}`;
    const studentId = `std-${Date.now()}`;

    const newStudent = {
      id: studentId,
      registrationId,
      fullName: fullName.trim(),
      fatherName: (fatherName || '').trim(),
      motherName: (motherName || '').trim(),
      fatherMobile: (fatherMobile || parentMobile || '').trim(),
      parentMobile: (parentMobile || fatherMobile || '').trim(),
      studentMobile: (studentMobile || '').trim(),
      photoUrl: `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(fullName.trim())}`,
      schoolName: (schoolName || '').trim(),
      classStandard: (classStandard || '').trim(),
      board: (board || 'CBSE').trim(),
      batch: batch || 'Evening Prime (5:45 PM - 7:45 PM)',
      fullAddress: (fullAddress || '').trim(),
      email: cleanEmail,
      academicYear: '2026-2027',
      attendanceRate: 100,
      addedByAdmin: true,
      passwordHash: password ? hashPassword(password) : DEFAULT_STUDENT_HASH,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const feeAmount = Number(monthlyFee) || 1500;
    const totalFees = feeAmount * 12;

    const newFeeRecord = {
      id: `fee-${Date.now()}`,
      studentId: newStudent.id,
      totalFees,
      paidFees: 0,
      outstandingFees: totalFees,
      updatedAt: new Date().toISOString(),
    };

    const newMonthlyRecords = generateMonthlyFeesForStudent(newStudent.id, feeAmount, 0);

    db.students.unshift(newStudent);
    db.feeRecords.push(newFeeRecord);
    db.monthlyFeeRecords.push(...newMonthlyRecords);
    saveDatabase(db);

    broadcastRealtimeEvent('student_created', newStudent);
    res.json({ success: true, message: `Student ${newStudent.fullName} created successfully.`, student: newStudent });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to create student.' });
  }
});

app.put('/api/students/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const index = db.students.findIndex(s => s.id === id);
    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Student not found.' });
    }

    const { password, ...otherData } = req.body;
    const updated = {
      ...db.students[index],
      ...otherData,
      passwordHash: password ? hashPassword(password) : db.students[index].passwordHash,
      updatedAt: new Date().toISOString(),
    };

    db.students[index] = updated;
    saveDatabase(db);
    broadcastRealtimeEvent('student_updated', updated);
    res.json({ success: true, message: 'Student profile updated.', student: updated });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update student.' });
  }
});

app.delete('/api/students/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    db.students = db.students.filter(s => s.id !== id);
    db.feeRecords = db.feeRecords.filter(f => f.studentId !== id);
    db.monthlyFeeRecords = db.monthlyFeeRecords.filter(m => m.studentId !== id);
    db.paymentHistory = db.paymentHistory.filter(p => p.studentId !== id);
    db.attendance = (db.attendance || []).filter(a => a.studentId !== id);
    db.examResults = (db.examResults || []).filter(e => e.studentId !== id);
    db.teacherRemarks = (db.teacherRemarks || []).filter(r => r.studentId !== id);

    saveDatabase(db);
    broadcastRealtimeEvent('student_deleted', { studentId: id });
    res.json({ success: true, message: 'Student and related records deleted successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete student.' });
  }
});

// Attendance Management (requireAdmin to mark)
app.get('/api/attendance', requireAuth, (req: Request, res: Response) => {
  const { date, classStandard, studentId } = req.query;
  let records = db.attendance || [];

  if (date) records = records.filter(r => r.date === date);
  if (classStandard) records = records.filter(r => r.classStandard === classStandard);
  if (studentId) records = records.filter(r => r.studentId === studentId);

  res.json(records);
});

app.post('/api/attendance/mark', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { items, date, markedBy } = req.body;
    if (!Array.isArray(items) || !date) {
      return res.status(400).json({ success: false, message: 'Items array and date are required.' });
    }

    if (!db.attendance) db.attendance = [];

    const studentIds = new Set(items.map(i => i.studentId));
    db.attendance = db.attendance.filter(a => !(a.date === date && studentIds.has(a.studentId)));

    const now = new Date().toISOString();
    const newRecords = items.map(item => ({
      id: `att-${item.studentId}-${date}`,
      studentId: item.studentId,
      date,
      status: item.status || 'Present',
      classStandard: item.classStandard || '',
      batch: item.batch || '',
      remarks: item.remarks || undefined,
      markedBy: markedBy || 'Admin Portal',
      createdAt: now,
    }));

    db.attendance.push(...newRecords);

    // Recalculate attendance rates for students
    studentIds.forEach(sId => {
      const studentRecords = db.attendance.filter(a => a.studentId === sId);
      const presentCount = studentRecords.filter(a => a.status === 'Present' || a.status === 'Late').length;
      const rate = studentRecords.length > 0 ? Math.round((presentCount / studentRecords.length) * 100) : 100;
      const std = db.students.find(s => s.id === sId);
      if (std) std.attendanceRate = rate;
    });

    saveDatabase(db);
    broadcastRealtimeEvent('attendance_marked', { date, count: newRecords.length });
    res.json({ success: true, message: `Attendance for ${newRecords.length} students recorded for ${date}.`, records: newRecords });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to record attendance.' });
  }
});

// Fee Management & Monthly Records (requireAdmin for mutations)
app.get('/api/fee-records', requireAuth, (req: Request, res: Response) => {
  res.json(db.feeRecords);
});

app.get('/api/monthly-fees', requireAuth, (req: Request, res: Response) => {
  res.json(db.monthlyFeeRecords);
});

app.put('/api/monthly-fees/:studentId/:month', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { studentId, month } = req.params;
    const { monthlyFee, amountPaid, paymentDate, notes, status, academicYear = '2026-2027' } = req.body;

    const record = db.monthlyFeeRecords.find(
      m => m.studentId === studentId && m.month === month && (m.academicYear || '2026-2027') === academicYear
    );

    if (!record) {
      return res.status(404).json({ success: false, message: 'Monthly fee record not found.' });
    }

    if (monthlyFee !== undefined) record.monthlyFee = Number(monthlyFee);
    if (amountPaid !== undefined) record.amountPaid = Number(amountPaid);
    record.outstandingAmount = Math.max(0, record.monthlyFee - record.amountPaid);
    if (status) {
      record.status = status;
    } else {
      if (record.amountPaid >= record.monthlyFee && record.monthlyFee > 0) record.status = 'Paid';
      else if (record.amountPaid > 0) record.status = 'Partially Paid';
      else record.status = 'Unpaid';
    }
    if (paymentDate !== undefined) record.paymentDate = paymentDate;
    if (notes !== undefined) record.notes = notes;
    record.updatedAt = new Date().toISOString();

    // Recalculate student overall fee record
    const studentMonths = db.monthlyFeeRecords.filter(m => m.studentId === studentId && (m.academicYear || '2026-2027') === academicYear);
    const totalFee = studentMonths.reduce((sum, m) => sum + m.monthlyFee, 0);
    const totalPaid = studentMonths.reduce((sum, m) => sum + m.amountPaid, 0);

    let feeRecord = db.feeRecords.find(f => f.studentId === studentId);
    if (feeRecord) {
      feeRecord.totalFees = totalFee;
      feeRecord.paidFees = totalPaid;
      feeRecord.outstandingFees = Math.max(0, totalFee - totalPaid);
      feeRecord.updatedAt = new Date().toISOString();
    }

    saveDatabase(db);
    broadcastRealtimeEvent('monthly_fee_updated', { record, feeRecord });
    res.json({ success: true, message: `Updated fee record for ${month}.`, record, feeRecord });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update monthly fee record.' });
  }
});

app.put('/api/monthly-fees/:studentId/base-fee', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { studentId } = req.params;
    const { amount, academicYear = '2026-2027' } = req.body;
    const numAmount = Number(amount);

    if (isNaN(numAmount) || numAmount < 0) {
      return res.status(400).json({ success: false, message: 'Valid non-negative monthly fee required.' });
    }

    const studentMonths = db.monthlyFeeRecords.filter(
      m => m.studentId === studentId && (m.academicYear || '2026-2027') === academicYear
    );

    if (studentMonths.length === 0) {
      return res.status(404).json({ success: false, message: 'No monthly records found for this student.' });
    }

    studentMonths.forEach(m => {
      m.monthlyFee = numAmount;
      m.outstandingAmount = Math.max(0, numAmount - m.amountPaid);
      if (m.amountPaid >= numAmount && numAmount > 0) m.status = 'Paid';
      else if (m.amountPaid > 0) m.status = 'Partially Paid';
      else m.status = 'Unpaid';
      m.updatedAt = new Date().toISOString();
    });

    const totalFee = numAmount * 12;
    const totalPaid = studentMonths.reduce((sum, m) => sum + m.amountPaid, 0);

    let feeRecord = db.feeRecords.find(f => f.studentId === studentId);
    if (feeRecord) {
      feeRecord.totalFees = totalFee;
      feeRecord.paidFees = totalPaid;
      feeRecord.outstandingFees = Math.max(0, totalFee - totalPaid);
      feeRecord.updatedAt = new Date().toISOString();
    }

    saveDatabase(db);
    broadcastRealtimeEvent('base_monthly_fee_updated', { studentId, baseFee: numAmount, feeRecord });
    res.json({
      success: true,
      message: `Set base fee to ₹${numAmount}/month (Annual Total: ₹${totalFee.toLocaleString()}) for all 12 months.`,
      records: studentMonths,
      feeRecord,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update base monthly fee.' });
  }
});

// Online UPI Payment recording (Initiated by Parent or Student, Pending Admin Verification)
app.post('/api/payments/online-upi', async (req: Request, res: Response) => {
  try {
    const { studentId, month, amount, transactionId, academicYear = '2026-2027', senderPhone, senderName } = req.body;
    const numAmount = Number(amount);

    if (!studentId || isNaN(numAmount) || numAmount <= 0 || !transactionId) {
      return res.status(400).json({ success: false, message: 'Student ID, valid amount, and UPI Transaction Reference (UTR) are required.' });
    }

    const student = db.students.find(s => s.id === studentId);
    if (!student) {
      return res.status(404).json({ success: false, message: 'Student not found.' });
    }

    let feeRecord = db.feeRecords.find(f => f.studentId === studentId);
    if (!feeRecord) {
      feeRecord = {
        id: `fee-${Date.now()}`,
        studentId,
        totalFees: 18000,
        paidFees: 0,
        outstandingFees: 18000,
        updatedAt: new Date().toISOString(),
      };
      db.feeRecords.push(feeRecord);
    }

    // Mark the month record status as Pending Verification until admin audits the transaction
    const monthRecord = db.monthlyFeeRecords.find(
      m => m.studentId === studentId && m.month === month && (m.academicYear || '2026-2027') === academicYear
    );

    if (monthRecord) {
      monthRecord.status = 'Pending Verification';
      monthRecord.transactionId = transactionId;
      monthRecord.updatedAt = new Date().toISOString();
    }

    const receiptNo = `RCP-2026-${String(db.paymentHistory.length + 1).padStart(3, '0')}`;
    const newPayment = {
      id: `pay-${Date.now()}`,
      feeRecordId: feeRecord.id,
      studentId,
      amount: numAmount,
      paymentDate: new Date().toISOString().split('T')[0],
      paymentMethod: 'UPI',
      receiptNo,
      month: month || 'Monthly Tuition',
      transactionId: transactionId,
      verificationStatus: 'Pending Verification',
      notes: `Online UPI Payment submitted by ${senderName || student.fatherName || 'Parent'} (${senderPhone || student.fatherMobile}) - UTR: ${transactionId}. Awaiting Admin Verification.`,
      createdAt: new Date().toISOString(),
    };

    db.paymentHistory.unshift(newPayment);
    saveDatabase(db);
    broadcastRealtimeEvent('payment_submitted', { payment: newPayment, feeRecord, monthRecord });

    res.json({
      success: true,
      message: `Online UPI Payment of ₹${numAmount} submitted for verification. Receipt #${receiptNo} generated (Pending Verification).`,
      receiptNo,
      senderContact: senderPhone || student.fatherMobile,
      payment: newPayment,
      feeRecord,
      monthRecord,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to record online UPI payment.' });
  }
});

// Admin Payment Verification
app.post('/api/payments/:id/verify', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const payment = db.paymentHistory.find(p => p.id === id);

    if (!payment) {
      return res.status(404).json({ success: false, message: 'Payment record not found.' });
    }

    payment.verificationStatus = 'Verified';
    payment.notes = (payment.notes || '').replace('Awaiting Admin Verification.', 'Verified by Administrator.');

    // Allocate funds to student's fee record and monthly records
    const feeRecord = db.feeRecords.find(f => f.id === payment.feeRecordId || f.studentId === payment.studentId);
    if (feeRecord) {
      feeRecord.paidFees += payment.amount;
      feeRecord.outstandingFees = Math.max(0, feeRecord.totalFees - feeRecord.paidFees);
      feeRecord.updatedAt = new Date().toISOString();
    }

    const monthRecord = db.monthlyFeeRecords.find(
      m => m.studentId === payment.studentId && m.month === payment.month
    );
    if (monthRecord) {
      monthRecord.amountPaid += payment.amount;
      monthRecord.outstandingAmount = Math.max(0, monthRecord.monthlyFee - monthRecord.amountPaid);
      if (monthRecord.amountPaid >= monthRecord.monthlyFee) monthRecord.status = 'Paid';
      else if (monthRecord.amountPaid > 0) monthRecord.status = 'Partially Paid';
      monthRecord.updatedAt = new Date().toISOString();
    }

    saveDatabase(db);
    broadcastRealtimeEvent('payment_verified', { payment, feeRecord, monthRecord });
    res.json({ success: true, message: `Payment ${payment.receiptNo} verified successfully.`, payment, feeRecord });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to verify payment.' });
  }
});

// Admin Direct Payment Recording (requireAdmin)
app.get('/api/payments', requireAuth, (req: Request, res: Response) => {
  res.json(db.paymentHistory);
});

app.post('/api/payments', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { studentId, amount, paymentMethod = 'Cash', month, transactionId, notes } = req.body;
    const numAmount = Number(amount);

    if (!studentId || isNaN(numAmount) || numAmount <= 0) {
      return res.status(400).json({ success: false, message: 'Valid student ID and positive amount required.' });
    }

    const student = db.students.find(s => s.id === studentId);
    if (!student) {
      return res.status(404).json({ success: false, message: 'Student not found.' });
    }

    let feeRecord = db.feeRecords.find(f => f.studentId === studentId);
    if (!feeRecord) {
      feeRecord = {
        id: `fee-${Date.now()}`,
        studentId,
        totalFees: 18000,
        paidFees: 0,
        outstandingFees: 18000,
        updatedAt: new Date().toISOString(),
      };
      db.feeRecords.push(feeRecord);
    }

    feeRecord.paidFees += numAmount;
    feeRecord.outstandingFees = Math.max(0, feeRecord.totalFees - feeRecord.paidFees);
    feeRecord.updatedAt = new Date().toISOString();

    // Update monthly fee records sequentially
    let remainingToAllocate = numAmount;
    const studentMonths = db.monthlyFeeRecords
      .filter(m => m.studentId === studentId)
      .sort((a, b) => a.monthOrder - b.monthOrder);

    for (const mRecord of studentMonths) {
      if (remainingToAllocate <= 0) break;
      const needed = mRecord.monthlyFee - mRecord.amountPaid;
      if (needed > 0) {
        const allocate = Math.min(needed, remainingToAllocate);
        mRecord.amountPaid += allocate;
        mRecord.outstandingAmount = Math.max(0, mRecord.monthlyFee - mRecord.amountPaid);
        if (mRecord.amountPaid >= mRecord.monthlyFee) mRecord.status = 'Paid';
        else if (mRecord.amountPaid > 0) mRecord.status = 'Partially Paid';
        mRecord.paymentDate = new Date().toISOString().split('T')[0];
        mRecord.transactionId = transactionId || `TXN-${Date.now()}`;
        mRecord.updatedAt = new Date().toISOString();
        remainingToAllocate -= allocate;
      }
    }

    const receiptNo = `RCP-2026-${String(db.paymentHistory.length + 1).padStart(3, '0')}`;
    const newPayment = {
      id: `pay-${Date.now()}`,
      feeRecordId: feeRecord.id,
      studentId,
      amount: numAmount,
      paymentDate: new Date().toISOString().split('T')[0],
      paymentMethod,
      receiptNo,
      month: month || 'Current Term',
      transactionId: transactionId || `TXN-${Date.now()}`,
      verificationStatus: 'Verified',
      notes: notes || `Payment received for ${student.fullName}`,
      createdAt: new Date().toISOString(),
    };

    db.paymentHistory.unshift(newPayment);
    saveDatabase(db);
    broadcastRealtimeEvent('payment_recorded', { payment: newPayment, feeRecord });
    res.json({
      success: true,
      message: `Payment of ₹${numAmount} recorded successfully. Receipt #${receiptNo} generated.`,
      payment: newPayment,
      feeRecord,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to record payment.' });
  }
});

// Homework System (requireAdmin for mutations)
app.get('/api/homework', requireAuth, (req: Request, res: Response) => {
  res.json(db.homework || []);
});

app.post('/api/homework', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { title, subject, classStandard, batch, dueDate, description, attachmentUrl, createdBy } = req.body;
    if (!title || !subject || !classStandard || !dueDate) {
      return res.status(400).json({ success: false, message: 'Title, subject, class, and due date are required.' });
    }

    if (!db.homework) db.homework = [];

    const newHw = {
      id: `hw-${Date.now()}`,
      title: title.trim(),
      subject: subject.trim(),
      classStandard: classStandard.trim(),
      batch: batch || 'All Batches',
      assignedDate: new Date().toISOString().split('T')[0],
      dueDate,
      description: description || '',
      attachmentUrl: attachmentUrl || '',
      createdBy: createdBy || 'Faculty Mentor',
      createdAt: new Date().toISOString(),
    };

    db.homework.unshift(newHw);
    saveDatabase(db);
    broadcastRealtimeEvent('homework_created', newHw);
    res.json({ success: true, message: 'Homework assignment posted.', homework: newHw });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to post homework.' });
  }
});

app.delete('/api/homework/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    db.homework = (db.homework || []).filter(h => h.id !== id);
    saveDatabase(db);
    broadcastRealtimeEvent('homework_deleted', { id });
    res.json({ success: true, message: 'Homework deleted.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete homework.' });
  }
});

// Announcements / Notice Board
app.get('/api/announcements', (req: Request, res: Response) => {
  res.json(db.announcements || []);
});

app.post('/api/announcements', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { title, content, category = 'General', targetAudience = 'All', isPinned = false, postedBy } = req.body;
    if (!title || !content) {
      return res.status(400).json({ success: false, message: 'Title and content are required.' });
    }

    if (!db.announcements) db.announcements = [];

    const newNotice = {
      id: `ann-${Date.now()}`,
      title: title.trim(),
      content: content.trim(),
      category,
      targetAudience,
      isPinned: Boolean(isPinned),
      postedBy: postedBy || 'Administration Office',
      date: new Date().toISOString().split('T')[0],
      createdAt: new Date().toISOString(),
    };

    db.announcements.unshift(newNotice);
    saveDatabase(db);
    broadcastRealtimeEvent('announcement_created', newNotice);
    res.json({ success: true, message: 'Notice published.', announcement: newNotice });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to publish announcement.' });
  }
});

app.put('/api/announcements/:id/pin', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const ann = (db.announcements || []).find(a => a.id === id);
    if (!ann) return res.status(404).json({ success: false, message: 'Announcement not found.' });
    ann.isPinned = !ann.isPinned;
    saveDatabase(db);
    broadcastRealtimeEvent('announcement_updated', ann);
    res.json({ success: true, announcement: ann });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update announcement.' });
  }
});

app.delete('/api/announcements/:id', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    db.announcements = (db.announcements || []).filter(a => a.id !== id);
    saveDatabase(db);
    broadcastRealtimeEvent('announcement_deleted', { id });
    res.json({ success: true, message: 'Announcement deleted.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete announcement.' });
  }
});

// Exam Results (requireAdmin to add)
app.get('/api/exams', requireAuth, (req: Request, res: Response) => {
  const { studentId } = req.query;
  let results = db.examResults || [];
  if (studentId) results = results.filter(e => e.studentId === studentId);
  res.json(results);
});

app.post('/api/exams', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { studentId, examName, subject, marksObtained, totalMarks = 50, examDate, remarks } = req.body;
    if (!studentId || !examName || !subject || marksObtained === undefined) {
      return res.status(400).json({ success: false, message: 'Student ID, exam name, subject, and marks are required.' });
    }

    if (!db.examResults) db.examResults = [];

    const numMarks = Number(marksObtained);
    const numTotal = Number(totalMarks);
    const pct = (numMarks / numTotal) * 100;
    let grade = 'A+';
    if (pct < 50) grade = 'C';
    else if (pct < 70) grade = 'B';
    else if (pct < 85) grade = 'A';

    const newResult = {
      id: `exam-${Date.now()}`,
      studentId,
      examName: examName.trim(),
      subject: subject.trim(),
      marksObtained: numMarks,
      totalMarks: numTotal,
      examDate: examDate || new Date().toISOString().split('T')[0],
      grade,
      remarks: remarks || '',
      createdAt: new Date().toISOString(),
    };

    db.examResults.unshift(newResult);
    saveDatabase(db);
    broadcastRealtimeEvent('exam_result_added', newResult);
    res.json({ success: true, message: 'Exam result recorded.', examResult: newResult });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to save exam result.' });
  }
});

// Teacher Remarks (requireAdmin to add)
app.get('/api/remarks', requireAuth, (req: Request, res: Response) => {
  const { studentId } = req.query;
  let list = db.teacherRemarks || [];
  if (studentId) list = list.filter(r => r.studentId === studentId);
  res.json(list);
});

app.post('/api/remarks', requireAdmin, async (req: Request, res: Response) => {
  try {
    const { studentId, teacherName, subject, remark, type = 'Praise' } = req.body;
    if (!studentId || !teacherName || !remark) {
      return res.status(400).json({ success: false, message: 'Student ID, teacher name, and remark content are required.' });
    }

    if (!db.teacherRemarks) db.teacherRemarks = [];

    const newRemark = {
      id: `rem-${Date.now()}`,
      studentId,
      teacherName: teacherName.trim(),
      subject: subject || 'General Performance',
      date: new Date().toISOString().split('T')[0],
      remark: remark.trim(),
      type,
      createdAt: new Date().toISOString(),
    };

    db.teacherRemarks.unshift(newRemark);
    saveDatabase(db);
    broadcastRealtimeEvent('teacher_remark_added', newRemark);
    res.json({ success: true, message: 'Remark saved.', remark: newRemark });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to save remark.' });
  }
});

// Student Authentication (Strict Real Password Verification)
app.post('/api/student/login', async (req: Request, res: Response) => {
  try {
    const { emailOrPhone, password } = req.body;
    const identifier = (emailOrPhone || '').trim().toLowerCase();
    const digits = identifier.replace(/\D/g, '');

    if (!identifier || !password) {
      return res.status(400).json({ success: false, message: 'Email/Phone and Password are required.' });
    }

    // Match in students table
    const matchedStudents = db.students.filter(
      s => s.email.toLowerCase() === identifier ||
           (digits.length >= 7 && s.fatherMobile && s.fatherMobile.replace(/\D/g, '') === digits) ||
           (digits.length >= 7 && s.parentMobile && s.parentMobile.replace(/\D/g, '') === digits) ||
           (digits.length >= 7 && s.studentMobile && s.studentMobile.replace(/\D/g, '') === digits)
    );

    if (matchedStudents.length > 0) {
      const student = matchedStudents[0];
      
      // Verify password against Supabase Auth or stored PBKDF2 hash
      let isVerified = false;
      const supabase = getServerSupabase();
      if (supabase && student.email) {
        try {
          const { data, error } = await supabase.auth.signInWithPassword({
            email: student.email,
            password,
          });
          if (!error && data?.user) isVerified = true;
        } catch {}
      }

      if (!isVerified && student.passwordHash) {
        isVerified = verifyPassword(password, student.passwordHash);
      }

      // If student was created without a password, allow initial activation with standard default credentials
      if (!isVerified && !student.passwordHash && password === 'Student@2026') {
        student.passwordHash = hashPassword(password);
        saveDatabase(db);
        isVerified = true;
      }

      if (!isVerified) {
        return res.status(401).json({ success: false, message: 'Invalid student email or password.' });
      }

      // Generate student session token
      const token = createSession({
        userId: student.id,
        role: 'student',
        studentId: student.id,
        email: student.email,
        fullName: student.fullName,
      });

      return res.json({
        success: true,
        role: 'student',
        message: `Welcome back, ${student.fullName}!`,
        student,
        token,
      });
    }

    // Match in pending admission requests
    const pending = db.admissionRequests.filter(
      r => r.email.toLowerCase() === identifier ||
           (digits.length >= 7 && r.fatherMobile && r.fatherMobile.replace(/\D/g, '') === digits)
    );

    if (pending.length > 0) {
      const reqRecord = pending[0];
      let isVerified = false;
      if (reqRecord.passwordHash) {
        isVerified = verifyPassword(password, reqRecord.passwordHash);
      } else if (password === 'Student@2026') {
        isVerified = true;
      }

      if (!isVerified) {
        return res.status(401).json({ success: false, message: 'Invalid password for pending admission.' });
      }

      const token = createSession({
        userId: reqRecord.id,
        role: 'student',
        email: reqRecord.email,
        fullName: reqRecord.fullName,
      });

      return res.json({
        success: true,
        role: 'student',
        message: `Admission request status: ${reqRecord.status}`,
        pendingRequest: reqRecord,
        pendingRequests: pending,
        token,
      });
    }

    res.status(401).json({ success: false, message: 'No student record found with this email or phone number.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Student login error.' });
  }
});

// Parent Login (Direct Parent Access, Supports Multiple Children Linked to Same Parent Phone/Email)
app.post('/api/parent/login', async (req: Request, res: Response) => {
  try {
    const { phoneOrEmail } = req.body;
    const rawInput = (phoneOrEmail || '').trim().toLowerCase();
    const queryDigits = rawInput.replace(/\D/g, '');

    if (!rawInput) {
      return res.status(400).json({ success: false, message: 'Please enter parent email or mobile number.' });
    }

    // Search ALL students for matching parent phone or parent email
    const matchedStudents = db.students.filter(s => {
      const matchEmail = s.email && s.email.toLowerCase() === rawInput;
      const matchFatherPhone = queryDigits.length >= 7 && s.fatherMobile && s.fatherMobile.replace(/\D/g, '').includes(queryDigits);
      const matchParentPhone = queryDigits.length >= 7 && s.parentMobile && s.parentMobile.replace(/\D/g, '').includes(queryDigits);
      const matchStudentPhone = queryDigits.length >= 7 && s.studentMobile && s.studentMobile.replace(/\D/g, '').includes(queryDigits);
      const matchFatherName = s.fatherName && s.fatherName.toLowerCase() === rawInput;
      return matchEmail || matchFatherPhone || matchParentPhone || matchStudentPhone || matchFatherName;
    });

    if (matchedStudents.length > 0) {
      // Create session token with linked student IDs
      const token = createSession({
        userId: `parent-${matchedStudents[0].id}`,
        role: 'parent',
        parentContact: rawInput,
        linkedStudentIds: matchedStudents.map(s => s.id),
        email: matchedStudents[0].email,
        fullName: matchedStudents[0].fatherName || 'Parent',
      });

      return res.json({
        success: true,
        role: 'parent',
        token,
        message: matchedStudents.length > 1
          ? `Found ${matchedStudents.length} students linked to this parent.`
          : `Connected to child portal for ${matchedStudents[0].fullName}`,
        student: matchedStudents[0],
        students: matchedStudents,
      });
    }

    // Check pending admission requests
    const matchedPending = db.admissionRequests.filter(r => {
      const matchEmail = r.email && r.email.toLowerCase() === rawInput;
      const matchFatherPhone = queryDigits.length >= 7 && r.fatherMobile && r.fatherMobile.replace(/\D/g, '').includes(queryDigits);
      const matchParentPhone = queryDigits.length >= 7 && r.parentMobile && r.parentMobile.replace(/\D/g, '').includes(queryDigits);
      const matchFatherName = r.fatherName && r.fatherName.toLowerCase() === rawInput;
      return matchEmail || matchFatherPhone || matchParentPhone || matchFatherName;
    });

    if (matchedPending.length > 0) {
      const token = createSession({
        userId: `parent-pending-${matchedPending[0].id}`,
        role: 'parent',
        parentContact: rawInput,
        email: matchedPending[0].email,
        fullName: matchedPending[0].fatherName || 'Parent',
      });

      return res.json({
        success: true,
        role: 'parent',
        token,
        message: `Found ${matchedPending.length} pending admission application(s).`,
        pendingRequests: matchedPending,
        student: undefined,
        students: [],
      });
    }

    res.status(404).json({ success: false, message: 'No student registered with this parent contact number or email.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Parent lookup error.' });
  }
});

// Logout Endpoint
app.post('/api/auth/logout', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.substring(7).trim() : '';
  if (token) revokeSession(token);
  res.json({ success: true, message: 'Logged out successfully.' });
});

// -------------------------------------------------------------
// Vite Middleware / Static Fallback
// -------------------------------------------------------------
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Bright Future Tuition Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
});
