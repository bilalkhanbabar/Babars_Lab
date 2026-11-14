const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Database Setup (Railway persistent path or local fallback)
const dbPath = path.resolve(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to the SQLite database successfully.');
    }
});

// Create Users Table with credit-based subscription model
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    phone TEXT,
    password TEXT,
    credits INTEGER DEFAULT 100000,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// 1. REGISTER API
app.post('/api/register', async (req, res) => {
    const { name, email, phone, password } = req.body;
    
    if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: "Please fill all required fields!" });
    }

    try {
        // Hash the password securely
        const hashedPassword = await bcrypt.hash(password, 10);
        const defaultCredits = 100000; // Free starter tier allocation

        const query = `INSERT INTO users (name, email, phone, password, credits) VALUES (?, ?, ?, ?, ?)`;
        db.run(query, [name, email, phone, hashedPassword, defaultCredits], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ success: false, message: "Email is already registered!" });
                }
                return res.status(500).json({ success: false, message: err.message });
            }
            res.json({ 
                success: true, 
                message: "Registration successful! Welcome to BABAR LAB.",
                user: { id: this.lastID, name, email, credits: defaultCredits }
            });
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error during registration." });
    }
});

// 2. LOGIN API
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Please enter email and password!" });
    }

    const query = `SELECT * FROM users WHERE email = ?`;
    db.get(query, [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ success: false, message: "Database error." });
        }
        if (!user) {
            return res.status(400).json({ success: false, message: "User not found with this email!" });
        }

        // Compare password with hashed password in DB
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: "Invalid password!" });
        }

        res.json({
            success: true,
            message: "Login successful!",
            user: { id: user.id, name: user.name, email: user.email, credits: user.credits }
        });
    });
});

// 3. FORGOT PASSWORD API
app.post('/api/forgot-password', async (req, res) => {
    const { email, tillId, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ success: false, message: "Email and new password are required!" });
    }

    const query = `SELECT * FROM users WHERE email = ?`;
    db.get(query, [email], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ success: false, message: "Email not found in database!" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.run(`UPDATE users SET password = ? WHERE email = ?`, [hashedPassword, email], (updateErr) => {
            if (updateErr) {
                return res.status(500).json({ success: false, message: "Error updating password." });
            }
            res.json({ success: true, message: "Password reset successfully!" });
        });
    });
});

// 4. DEDUCT CREDITS API
app.post('/api/deduct-credits', (req, res) => {
    const { email, cost, moduleType } = req.body;

    if (!email || !cost) {
        return res.status(400).json({ success: false, message: "Email and cost are required!" });
    }

    const selectQuery = `SELECT credits FROM users WHERE email = ?`;
    db.get(selectQuery, [email], (err, row) => {
        if (err || !row) {
            return res.status(400).json({ success: false, message: "User not found in database!" });
        }

        if (row.credits < cost) {
            return res.status(400).json({ success: false, message: "Insufficient credits in database!" });
        }

        const newCredits = row.credits - cost;

        const updateQuery = `UPDATE users SET credits = ? WHERE email = ?`;
        db.run(updateQuery, [newCredits, email], function(updateErr) {
            if (updateErr) {
                return res.status(500).json({ success: false, message: "Error updating credits." });
            }
            res.json({
                success: true,
                message: `${cost} credits deducted successfully for ${moduleType}!`,
                remainingCredits: newCredits
            });
        });
    });
});

// 5. TEST ROUTE
app.get('/api/test', (req, res) => {
    res.json({ message: "BABAR LAB Backend Server is Running Live with APIs!" });
});

// ==========================================
// 6. DEBUG ROUTE TO VIEW ALL USERS IN DATABASE
// ==========================================
app.get('/api/debug/users', (req, res) => {
    db.all("SELECT id, name, email, credits, created_at FROM users", [], (err, rows) => {
        if (err) {
            res.status(500).json({ success: false, error: err.message });
        } else {
            res.json({ success: true, total_users: rows.length, users: rows });
        }
    });
});

// Server Start
// Server Start
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running smoothly at http://0.0.0.0:${PORT}`);
});

// Force restart trigger