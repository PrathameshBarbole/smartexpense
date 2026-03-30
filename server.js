/**
 * ══════════════════════════════════════════════════════════
 *   SMART EXPENSE MANAGER — SERVER
 *   Node.js + Express + built-in SQLite (node:sqlite)
 *   Database saved as: expense.db  (same folder as server.js)
 * ══════════════════════════════════════════════════════════
 *
 *  HOW TO RUN:
 *    1.  npm install
 *    2.  node server.js
 *    3.  Open http://localhost:3001
 */

'use strict';

const express = require('express');
const session = require('express-session');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('crypto');
const path = require('path');

// ── Config ─────────────────────────────────────────────────
const PORT = 3001;
const DB_FILE = path.join(__dirname, 'expense.db');

// ── Database ────────────────────────────────────────────────
const db = new DatabaseSync(DB_FILE);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;'); // Better concurrent access

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fullname      TEXT    NOT NULL,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    salt          TEXT    NOT NULL,
    currency      TEXT    NOT NULL DEFAULT '₹',
    theme         TEXT    NOT NULL DEFAULT 'light',
    created_at    TEXT    DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    type       TEXT    CHECK(type IN ('income','expense')) NOT NULL,
    category   TEXT    NOT NULL,
    amount     REAL    NOT NULL,
    note       TEXT    NOT NULL DEFAULT '',
    date       TEXT    NOT NULL,
    created_at TEXT    DEFAULT (datetime('now','localtime')),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS budgets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    category      TEXT    NOT NULL,
    monthly_limit REAL    NOT NULL,
    UNIQUE(user_id, category),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_txn_user  ON transactions(user_id);
  CREATE INDEX IF NOT EXISTS idx_txn_date  ON transactions(date);
  CREATE INDEX IF NOT EXISTS idx_bud_user  ON budgets(user_id);
`);

// ── Helpers ─────────────────────────────────────────────────
function genSalt() { return crypto.randomBytes(16).toString('hex'); }
function hashPwd(pwd, salt) {
    return crypto.createHash('sha256').update(pwd + salt).digest('hex');
}

// ── Express App ─────────────────────────────────────────────
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Serve index.html + static files from same folder
app.use(express.static(__dirname));

// Session
app.use(session({
    secret: 'sem_super_secret_2024_xJ9k',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 7 * 24 * 60 * 60 * 1000,   // 7 days
        httpOnly: true,
        sameSite: 'lax',
    }
}));

// Auth guard middleware
function auth(req, res, next) {
    if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
    next();
}

// ══════════════════════════════════════════════════════════
//   AUTH ROUTES
// ══════════════════════════════════════════════════════════

// Register
app.post('/api/auth/register', (req, res) => {
    const { fullname, username, password } = req.body;

    if (!fullname || !username || !password)
        return res.status(400).json({ error: 'All fields are required.' });
    if (username.length < 3)
        return res.status(400).json({ error: 'Username must be at least 3 characters.' });
    if (!/^[a-z0-9_]+$/.test(username.toLowerCase()))
        return res.status(400).json({ error: 'Username: letters, numbers, underscore only.' });
    if (password.length < 6)
        return res.status(400).json({ error: 'Password must be at least 6 characters.' });

    const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username.toLowerCase());
    if (exists) return res.status(400).json({ error: 'Username already taken.' });

    const salt = genSalt();
    const hash = hashPwd(password, salt);
    db.prepare('INSERT INTO users (fullname, username, password_hash, salt) VALUES (?, ?, ?, ?)')
        .run(fullname.trim(), username.toLowerCase(), hash, salt);

    res.json({ success: true, message: 'Account created successfully!' });
});

// Login
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ error: 'Username and password required.' });

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase());
    if (!user) return res.status(401).json({ error: 'Invalid username or password.' });

    const hash = hashPwd(password, user.salt);
    if (hash !== user.password_hash)
        return res.status(401).json({ error: 'Invalid username or password.' });

    req.session.userId = user.id;
    res.json({
        success: true,
        user: { id: user.id, fullname: user.fullname, username: user.username, currency: user.currency, theme: user.theme }
    });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
    req.session.destroy(() => res.json({ success: true }));
});

// Get current user (session restore)
app.get('/api/me', auth, (req, res) => {
    const user = db.prepare('SELECT id, fullname, username, currency, theme FROM users WHERE id = ?')
        .get(req.session.userId);
    if (!user) return res.status(401).json({ error: 'User not found.' });
    res.json(user);
});

// Check username availability
app.get('/api/auth/check/:username', (req, res) => {
    const exists = db.prepare('SELECT id FROM users WHERE username = ?')
        .get(req.params.username.toLowerCase());
    res.json({ available: !exists });
});

// ══════════════════════════════════════════════════════════
//   TRANSACTION ROUTES
// ══════════════════════════════════════════════════════════

app.get('/api/transactions', auth, (req, res) => {
    const rows = db.prepare(
        'SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC, id DESC'
    ).all(req.session.userId);
    res.json(rows);
});

app.post('/api/transactions', auth, (req, res) => {
    const { type, category, amount, note, date } = req.body;
    if (!type || !category || !amount || !date)
        return res.status(400).json({ error: 'Missing required fields.' });
    const r = db.prepare(
        'INSERT INTO transactions (user_id, type, category, amount, note, date) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(req.session.userId, type, category, parseFloat(amount), note || '', date);
    res.json({ id: r.lastInsertRowid, user_id: req.session.userId, type, category, amount: parseFloat(amount), note: note || '', date });
});

app.put('/api/transactions/:id', auth, (req, res) => {
    const { type, category, amount, note, date } = req.body;
    db.prepare(
        'UPDATE transactions SET type=?, category=?, amount=?, note=?, date=? WHERE id=? AND user_id=?'
    ).run(type, category, parseFloat(amount), note || '', date, req.params.id, req.session.userId);
    res.json({ success: true });
});

app.delete('/api/transactions/:id', auth, (req, res) => {
    db.prepare('DELETE FROM transactions WHERE id = ? AND user_id = ?')
        .run(req.params.id, req.session.userId);
    res.json({ success: true });
});

// Clear all user transactions
app.delete('/api/transactions', auth, (req, res) => {
    db.prepare('DELETE FROM transactions WHERE user_id = ?').run(req.session.userId);
    res.json({ success: true });
});

// ══════════════════════════════════════════════════════════
//   BUDGET ROUTES
// ══════════════════════════════════════════════════════════

app.get('/api/budgets', auth, (req, res) => {
    const rows = db.prepare('SELECT * FROM budgets WHERE user_id = ?').all(req.session.userId);
    res.json(rows);
});

app.post('/api/budgets', auth, (req, res) => {
    const { category, monthly_limit } = req.body;
    if (!category || !monthly_limit)
        return res.status(400).json({ error: 'Category and limit required.' });
    db.prepare(
        'INSERT INTO budgets (user_id, category, monthly_limit) VALUES (?, ?, ?) ON CONFLICT(user_id, category) DO UPDATE SET monthly_limit = ?'
    ).run(req.session.userId, category, parseFloat(monthly_limit), parseFloat(monthly_limit));
    res.json({ success: true });
});

app.delete('/api/budgets/:id', auth, (req, res) => {
    db.prepare('DELETE FROM budgets WHERE id = ? AND user_id = ?')
        .run(req.params.id, req.session.userId);
    res.json({ success: true });
});

// Clear all user budgets
app.delete('/api/budgets', auth, (req, res) => {
    db.prepare('DELETE FROM budgets WHERE user_id = ?').run(req.session.userId);
    res.json({ success: true });
});

// ══════════════════════════════════════════════════════════
//   SETTINGS ROUTES
// ══════════════════════════════════════════════════════════

app.put('/api/settings', auth, (req, res) => {
    const { fullname, currency, theme } = req.body;
    db.prepare('UPDATE users SET fullname = ?, currency = ?, theme = ? WHERE id = ?')
        .run(fullname || 'User', currency || '₹', theme || 'light', req.session.userId);
    res.json({ success: true });
});

app.put('/api/settings/password', auth, (req, res) => {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password)
        return res.status(400).json({ error: 'Both passwords required.' });
    if (new_password.length < 6)
        return res.status(400).json({ error: 'New password must be at least 6 characters.' });

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
    const hash = hashPwd(current_password, user.salt);
    if (hash !== user.password_hash)
        return res.status(401).json({ error: 'Current password is incorrect.' });

    const salt = genSalt();
    const newHash = hashPwd(new_password, salt);
    db.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?')
        .run(newHash, salt, req.session.userId);
    res.json({ success: true });
});

// Delete account
app.delete('/api/account', auth, (req, res) => {
    const { password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
    const hash = hashPwd(password, user.salt);
    if (hash !== user.password_hash)
        return res.status(401).json({ error: 'Incorrect password.' });

    // CASCADE will delete transactions + budgets
    db.prepare('DELETE FROM users WHERE id = ?').run(req.session.userId);
    req.session.destroy(() => res.json({ success: true }));
});

// ══════════════════════════════════════════════════════════
//   START
// ══════════════════════════════════════════════════════════
app.listen(PORT, () => {
    console.log('\n╔════════════════════════════════════════════╗');
    console.log('║     SMART EXPENSE MANAGER — SERVER         ║');
    console.log('╠════════════════════════════════════════════╣');
    console.log(`║  URL  : http://localhost:${PORT}           ║`);
    console.log(`║  Database : expense.db                     ║`);
    console.log('╚════════════════════════════════════════════╝\n');
    console.log('  Press Ctrl+C to stop the server\n');
});
