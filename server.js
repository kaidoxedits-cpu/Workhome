const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'homecraft_wb_sms_2fa_secret_2026';

const FAST2SMS_API_KEY = process.env.FAST2SMS_API_KEY || '';

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname)));

const db = new sqlite3.Database(path.join(__dirname, 'homecraft.db'), (err) => {
  if (err) console.error('❌ Error opening database:', err.message);
  else console.log('✅ Connected to SQLite database file: homecraft.db');
});

async function sendSMSVerification(phoneNumber, otpCode) {
  const cleanPhone = phoneNumber.replace(/\D/g, '');

  if (FAST2SMS_API_KEY) {
    try {
      await axios.post(
        'https://www.fast2sms.com/dev/bulkV2',
        {
          variables_values: otpCode,
          route: 'otp',
          numbers: cleanPhone,
        },
        {
          headers: {
            authorization: FAST2SMS_API_KEY,
            'Content-Type': 'application/json',
          },
        }
      );
      console.log(`📱 [SMS SENT REAL] OTP ${otpCode} sent via SMS to ${cleanPhone}`);
      return true;
    } catch (error) {
      console.error('❌ SMS Gateway Error:', error.response?.data || error.message);
    }
  }

  console.log(`\n==================================================`);
  console.log(`📲 [REAL WORKABLE SMS SIMULATION]`);
  console.log(`Recipient Mobile: +91 ${cleanPhone}`);
  console.log(`Your HomeCraft Verification OTP Code is: ${otpCode}`);
  console.log(`==================================================\n`);
  return true;
}

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      phone TEXT NOT NULL,
      role TEXT CHECK(role IN ('customer', 'lister')) NOT NULL,
      city TEXT NOT NULL,
      address TEXT,
      is_phone_verified INTEGER DEFAULT 0,
      otp_code TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS lister_profiles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER UNIQUE NOT NULL,
      category TEXT NOT NULL,
      rate REAL NOT NULL,
      experience_years INTEGER DEFAULT 1,
      profile_pic TEXT NOT NULL,
      bio TEXT,
      is_active INTEGER DEFAULT 1,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id INTEGER NOT NULL,
      lister_user_id INTEGER NOT NULL,
      category TEXT NOT NULL,
      amount REAL NOT NULL,
      payment_method TEXT NOT NULL,
      status TEXT DEFAULT 'Confirmed',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(customer_id) REFERENCES users(id),
      FOREIGN KEY(lister_user_id) REFERENCES users(id)
    )
  `);
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. Please sign in.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Session expired. Please sign in again.' });
    req.user = user;
    next();
  });
};

app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password, phone, role, city, address, category, rate, experience_years, profile_pic, bio } = req.body;

  if (!name || !email || !password || !phone || !role || !city) {
    return res.status(400).json({ error: 'All basic registration fields are required.' });
  }

  if (role === 'lister' && (!profile_pic || profile_pic.trim() === '')) {
    return res.status(400).json({ error: 'Profile Photo is MANDATORY for Listers.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();

    db.run(
      `INSERT INTO users (name, email, password, phone, role, city, address, otp_code, is_phone_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`,
      [name, email, hashedPassword, phone, role, city, address || '', otpCode],
      async function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'This email address is already registered.' });
          }
          return res.status(500).json({ error: err.message });
        }

        const userId = this.lastID;
        await sendSMSVerification(phone, otpCode);

        if (role === 'lister') {
          db.run(
            `INSERT INTO lister_profiles (user_id, category, rate, experience_years, profile_pic, bio) VALUES (?, ?, ?, ?, ?, ?)`,
            [userId, category || 'Other', rate || 25, experience_years || 1, profile_pic, bio || ''],
            (pErr) => {
              if (pErr) return res.status(500).json({ error: pErr.message });
              res.status(201).json({ requires2FA: true, userId, phone, message: 'SMS OTP sent successfully!' });
            }
          );
        } else {
          res.status(201).json({ requires2FA: true, userId, phone, message: 'SMS OTP sent successfully!' });
        }
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Authentication processing failed.' });
  }
});

app.post('/api/auth/verify-sms', (req, res) => {
  const { userId, otp } = req.body;

  if (!userId || !otp) {
    return res.status(400).json({ error: 'User ID and OTP are required for verification.' });
  }

  db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'User account not found.' });

    if (String(user.otp_code).trim() === String(otp).trim()) {
      db.run(`UPDATE users SET is_phone_verified = 1, otp_code = NULL WHERE id = ?`, [userId], (upErr) => {
        if (upErr) return res.status(500).json({ error: upErr.message });
        sendAuthResponse(user.id, user.name, user.email, user.role, user.city, user.phone, res);
      });
    } else {
      res.status(400).json({ error: 'Invalid SMS OTP Code. Please check terminal output or SMS inbox.' });
    }
  });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Invalid email or password.' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid email or password.' });

    if (user.is_phone_verified === 0) {
      return res.status(403).json({ error: 'SMS verification incomplete. Please verify your phone number first.' });
    }

    sendAuthResponse(user.id, user.name, user.email, user.role, user.city, user.phone, res);
  });
});

function sendAuthResponse(id, name, email, role, city, phone, res) {
  const token = jwt.sign({ id, name, email, role, city, phone }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id, name, email, role, city, phone } });
}

app.get('/api/user/profile', authenticateToken, (req, res) => {
  db.get(`SELECT id, name, email, phone, role, city, address, is_phone_verified, created_at FROM users WHERE id = ?`, [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'Profile not found.' });

    if (user.role === 'lister') {
      db.get(`SELECT * FROM lister_profiles WHERE user_id = ?`, [user.id], (pErr, profile) => {
        res.json({ user, profile });
      });
    } else {
      res.json({ user, profile: null });
    }
  });
});

app.get('/api/workers', (req, res) => {
  const { city, category } = req.query;

  let query = `
    SELECT u.id as lister_user_id, u.name, u.email, u.phone, u.city, lp.category, lp.rate, lp.experience_years, lp.profile_pic, lp.bio
    FROM users u
    JOIN lister_profiles lp ON u.id = lp.user_id
    WHERE u.role = 'lister' AND lp.is_active = 1 AND u.is_phone_verified = 1
  `;
  let params = [];

  if (city) {
    query += ` AND LOWER(u.city) = ?`;
    params.push(city.toLowerCase());
  }
  if (category && category !== 'All') {
    query += ` AND lp.category = ?`;
    params.push(category);
  }

  query += ` ORDER BY u.id DESC`;

  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/orders', authenticateToken, (req, res) => {
  if (req.user.role !== 'customer') {
    return res.status(403).json({ error: 'Only logged-in customer accounts can place bookings.' });
  }

  const { listerUserId, category, amount, paymentMethod } = req.body;

  db.run(
    `INSERT INTO orders (customer_id, lister_user_id, category, amount, payment_method) VALUES (?, ?, ?, ?, ?)`,
    [req.user.id, listerUserId, category, amount, paymentMethod || 'Cash'],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ success: true, orderId: this.lastID, message: 'Service booked successfully!' });
    }
  );
});

app.get('/api/customer/orders', authenticateToken, (req, res) => {
  db.all(
    `SELECT o.id, o.category, o.amount, o.payment_method, o.status, o.created_at, u.name as lister_name, u.phone as lister_phone 
     FROM orders o JOIN users u ON o.lister_user_id = u.id 
     WHERE o.customer_id = ? ORDER BY o.id DESC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.get('/api/lister/dashboard', authenticateToken, (req, res) => {
  if (req.user.role !== 'lister') return res.status(403).json({ error: 'Access restricted to Seller accounts.' });

  db.get(`SELECT * FROM lister_profiles WHERE user_id = ?`, [req.user.id], (err, profile) => {
    if (err) return res.status(500).json({ error: err.message });

    db.all(
      `SELECT o.id, o.category, o.amount, o.payment_method, o.status, o.created_at, u.name as customer_name, u.phone as customer_phone, u.address as service_address 
       FROM orders o JOIN users u ON o.customer_id = u.id 
       WHERE o.lister_user_id = ? ORDER BY o.id DESC`,
      [req.user.id],
      (orderErr, orders) => {
        if (orderErr) return res.status(500).json({ error: orderErr.message });
        res.json({ profile, orders });
      }
    );
  });
});

app.listen(PORT, () => {
  console.log(`🚀 HomeCraft Active on http://localhost:${PORT}`);
});