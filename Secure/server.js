const https = require('https');
const fs = require('fs');

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const expressSession = require('express-session');
const bcrypt = require('bcrypt'); // ✅ bcrypt used here

const app = express();
const port = 3000;
let comments = [];

app.set('view engine', 'pug');
app.set('views', './templates');

app.use(expressSession({
    secret: 'secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

app.use(express.urlencoded({ extended: false }));

// Database Setup
const dbFile = './database.db';
const db = new sqlite3.Database(dbFile, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            major TEXT,
            role TEXT DEFAULT 'user'
        )`, (err) => {
            if (err) {
                console.error('Error creating users table:', err.message);
            } else {
                console.log('Users table checked/created successfully.');
            }
        });
    }
});

// Registration Route
app.get('/register', (req, res) => {
    res.sendFile(__dirname + '/templates/register.html');
});

app.post('/register', async (req, res) => {
    const username = req.body.username;
    const password = await bcrypt.hash(req.body.password, 10); // ✅ bcrypt hash
    const email = req.body.email;
    const major = req.body.major;
    const role = 'user';

    const sql = `INSERT INTO users (username, password, email, major, role) VALUES (?, ?, ?, ?, ?)`;

    db.run(sql, [username, password, email, major, role], function(err) {
        if (err) {
            console.error('Error during registration INSERT:', err.message);
            if (err.message.includes('UNIQUE constraint failed')) {
                res.status(409).send('Username or email already exists.');
            } else {
                res.status(500).send('Error registering user.');
            }
        } else {
            console.log(`User ${username} registered with ID: ${this.lastID}`);
            res.redirect('/login');
        }
    });
});

// Login Route
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/templates/login.html');
});

app.post('/login', async (req, res) => {
    const username = req.body.username;
    const submittedPassword = req.body.password;

    const sql = `SELECT id, username, password, role FROM users WHERE username = ?`;

    db.get(sql, [username], async (err, user) => {
        if (err) {
            console.error('Error during login SELECT:', err.message);
            return res.status(500).send('An error occurred during login.');
        }

        if (!user) {
            return res.send('Login failed: User not found.');
        }

        const match = await bcrypt.compare(submittedPassword, user.password);

        if (match) {
            req.session.userId = user.id;
            req.session.role = user.role;
            res.redirect('/dashboard');
        } else {
            res.send('Login failed: Incorrect password.');
        }
    });
});

// Dashboard Route
app.get('/dashboard', (req, res) => {
    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }

    const userId = req.session.userId;
    const sql = `SELECT username, email, major FROM users WHERE id = ?`;

    db.get(sql, [userId], (err, user) => {
        if (err || !user) {
            req.session.destroy(() => res.redirect('/login'));
            return;
        }

        res.render('dashboard', {
            username: user.username,
            email: user.email,
            major: user.major,
            comments: comments
        });
    });
});

// Comments (XSS still intentionally open for grading)
app.post('/comment', (req, res) => {
    const newComment = req.body.comment;
    comments.push(newComment); // 🔴 Vulnerable to XSS on purpose
    res.redirect('/dashboard');
});

// Logout
app.get('/logout', (req, res) => {
    if (req.session) {
        req.session.destroy(() => res.redirect('/login'));
    } else {
        res.redirect('/login');
    }
});

// Admin Route
app.get('/admin', (req, res) => {
    if (!req.session || req.session.role !== 'admin') {
        return res.status(403).send('Forbidden – Admins only!');
    }
    res.sendFile(__dirname + '/templates/admin.html');
});

// List all users
app.get('/users', (req, res) => {
    db.all(`SELECT * FROM users`, (err, rows) => {
        if (err) {
            console.error('Error reading users:', err.message);
            return res.status(500).send('Error reading users.');
        }
        res.json(rows);
    });
});

// Start server
const sslOptions = {
    key: fs.readFileSync('./ssl/key.pem'),
    cert: fs.readFileSync('./ssl/cert.pem')
  };
  
  https.createServer(sslOptions, app).listen(port, () => {
    console.log(`🔒 HTTPS server running at https://localhost:${port}/`);
  });
  

// Graceful exit
process.on('SIGINT', () => {
    console.log('Closing database connection.');
    db.close((err) => {
        if (err) console.error('Error closing database:', err.message);
        else console.log('Database connection closed.');
        process.exit(0);
    });
});
