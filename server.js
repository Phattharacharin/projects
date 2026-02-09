require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const db = require('./db');

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('No token');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // ⭐ ผูก user กับ request
    next();
  } catch {
    return res.status(401).send('Invalid token');
  }
}
function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).send('No permission');
    }
    next();
  };
}

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});


app.get('/', (req, res) => {
  res.send('Server is running');
});

app.post('/register', async (req, res) => {
  const { firstname, lastname, email, password, phone } = req.body;

  if (!firstname || !lastname || !email || !password || !phone) {
    return res.status(400).send('ข้อมูลไม่ครบ');
  }

  db.query(
    'SELECT id FROM users WHERE email=?',
    [email],
    async (err, results) => {
      if (err) return res.status(500).send('DB error');
      if (results.length > 0)
        return res.status(400).send('อีเมลนี้ถูกใช้แล้ว');

      const hashedPassword = await bcrypt.hash(password, 10);

      // ลบ pending เก่า (กรณีสมัครใหม่)
      db.query('DELETE FROM pending_users WHERE email=?', [email]);

      db.query(
        `INSERT INTO pending_users
        (firstname, lastname, email, password, phone)
        VALUES (?, ?, ?, ?, ?)`,
        [firstname, lastname, email, hashedPassword, phone],
        err => {
          if (err) return res.status(500).send('Insert failed');
          res.json({
            success: true,
            message: 'สมัครสมาชิกสำเร็จ กรุณายืนยัน OTP ที่ส่งไปยังอีเมลของคุณ',
            next: 'send-otp'
          })
        }
      );
    }
  );
});
         app.post('/send-otp', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send('Missing email');

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otp_expired_at = new Date(Date.now() + 3 * 60 * 1000);

  db.query(
    `UPDATE pending_users 
     SET otp=?, otp_expired_at=?
     WHERE email=?`,
    [otp, otp_expired_at, email],
    (err, result) => {
      if (err) return res.status(500).send('DB error');

      if (result.affectedRows === 0) {
        return res.status(404).send('ไม่พบอีเมลนี้ กรุณาสมัครก่อน');
      }

      transporter.sendMail(
        {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Supatt Dental Clinic',
          text: 'Your OTP is ' + otp
        },
        err => {
          if (err) return res.status(500).send('Email failed');
          res.send('OTP sent');
        }
      );
    }
  );
});
          
app.post('/verify-otp',async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).send('Missing email or OTP');
  }

  db.query(
    'SELECT * FROM pending_users WHERE email=? AND otp=? AND otp_expired_at > NOW()',
    [email, otp],
    (err, results) => {
      if (err) return res.status(500).send('DB error');
      if (results.length === 0)
        return res.status(400).send('OTP ไม่ถูกหรือหมดอายุ');

      const user = results[0];
  

      // ✅ INSERT เข้า users (ยืนยันแล้ว)
      db.query(
        `INSERT INTO users (firstname, lastname, email, password, phone, is_verified)
         VALUES (?, ?, ?, ?, ?, 1)`,
        [user.firstname, user.lastname, user.email, user.password, user.phone],
        err => {
          if (err) return res.status(500).send('Create user failed');

          // ✅ ลบออกจาก pending
          db.query(
            'DELETE FROM pending_users WHERE email=?',
            [email]
          );

          res.send('สมัครสมาชิกสำเร็จ');
        
        }
      );
    }
  );
});
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).send('ข้อมูลไม่ครบ');
  }

  db.query(
    'SELECT * FROM users WHERE email=? AND is_verified=1',
    [email],
    async (err, results) => {
      if (err) return res.status(500).send('DB error');
      if (results.length === 0)
        return res.status(401).send('อีเมลหรือรหัสผ่านไม่ถูกต้อง');

      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch)
        return res.status(401).send('อีเมลหรือรหัสผ่านไม่ถูกต้อง');

      res.json({
        success: true,
        user: {
          firstname: user.firstname,
          email: user.email,
          role: user.role
        }
      });
    }
  );
});
app.post(
  '/admin/create-doctor',
  authMiddleware,
  requireRole('admin'),
  async (req, res) => {
    const {
      firstname,
      lastname,
      email,
      phone,
      license_number,
      specialization
    } = req.body;

    if (!email.endsWith('@ku.th')) {
      return res.status(400).send('ต้องใช้อีเมลองค์กร');
    }

    const tempPassword = 'Doctor@123';
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

    db.query(
      `INSERT INTO users
       (firstname, lastname, email, password, phone, role, is_verified)
       VALUES (?, ?, ?, ?, ?, 'doctor', 1)`,
      [firstname, lastname, email, hashedPassword, phone],
      (err, result) => {
        if (err) return res.status(500).send('Create user failed');

        const userId = result.insertId;

        db.query(
          `INSERT INTO doctors
           (user_id, license_number, specialization, phone, email)
           VALUES (?, ?, ?, ?, ?)`,
          [userId, license_number, specialization, phone, email],
          err => {
            if (err) return res.status(500).send('Create doctor failed');

            res.json({
              success: true,
              message: 'เพิ่มหมอสำเร็จ',
              tempPassword
            });
          }
        );
      }
    );
  }
);

app.listen(3000, () => {
  console.log('Server running on port 3000');
});