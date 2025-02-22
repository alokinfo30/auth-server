const express = require('express');
const app = express();
const db = require('./db');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
// const validator = require('validator'); 
const winston = require('winston');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();
const path = require('path');


app.use(express.json()); // Parse JSON request bodies
app.use(cors());
// Allow all origins (for development - restrict in production)
// app.use(helmet()); // for security
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"], // Or use hashes/nonces
        scriptSrcAttr: ["'self'", "'unsafe-inline'"],
    }
}));
app.use(express.static(path.join(__dirname, './')));
// Serve static files from the current directory

const PORT = process.env.PORT || 3000;
const RATE_LIMIT_WINDOW = process.env.RATE_LIMIT_WINDOW || 60000; // 1 minute
const MAX_ATTEMPTS = process.env.MAX_ATTEMPTS || 5;
const LOCKOUT_DURATION = process.env.LOCKOUT_DURATION || 3600000; // 1 hour
const TOKEN_EXPIRY = process.env.TOKEN_EXPIRY || 86400000;
const LINK_EXPIRY = process.env.LINK_EXPIRY || 600000; // 10 minutes

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [new winston.transports.Console()],
});

// Utility Functions
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function generateLink() {
    return crypto.randomBytes(20).toString('hex');
}

// Rate Limiting (Simple In-Memory)
const loginAttempts = {};

function rateLimit(req, res, next) {
    const username = req.body.username;
    if (!loginAttempts[username]) {
        loginAttempts[username] = { attempts: 0, lastAttempt: 0 };
    }
    const now = Date.now();
    if (now - loginAttempts[username].lastAttempt > RATE_LIMIT_WINDOW) {
        loginAttempts[username].attempts = 0;
    }
    loginAttempts[username].lastAttempt = now;
    if (loginAttempts[username].attempts >= MAX_ATTEMPTS) {
        return res.status(429).json({ error: 'Too manyin attempts. Account locked.' });
    }
    loginAttempts[username].attempts++;
    next();
}

// Authentication (Username/Password)
app.post('/login', rateLimit, async (req, res) => {
    const { username, password } = req.body;
    try {
        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
            if (err) {
                logger.error(err.message);
                return res.status(500).json({ error: err.message });
            }
            if (!user) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            if (user.locked === 1) {
                if (Date.now() < user.lockout_time) {
                    return res.status(403).json({ error: 'Account Locked. Try again later.' });
                } else {
                    db.run('Update users SET locked = 0 WHERE id = ?', [user.id]);
                }
            }

            const passwordMatch = await bcrypt.compare(password, user.password);

            if (passwordMatch) {
                const token = generateToken();
                const expiry = Date.now() + 86400000; // 24 hours
                db.run('INSERT INTO tokens (token, user_id, expiry) VALUES (?, ?, ?)', [token, user.id, expiry], (err) => {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }
                    res.json({ token });
                });
            } else {
                db.run('UPDATE users SET locked = 1, lockout_time = ? WHERE id = ? AND locked = 0', [Date.now() + LOCKOUT_DURATION, user.id], (err) => {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }
                    res.status(401).json({ error: 'Invalid credentials' });
                });
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Authentication (One-Time Link)
app.post('/generate-link', (req, res) => {
    const { username } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            logger.error(err.message);
            return res.status(500).json({ error: err.message });
        }
        if (!user) return res.status(404).json({ error: 'User not found' });

        const link = generateLink();
        const expiry = Date.now() + LINK_EXPIRY;
        db.run('INSERT INTO one_time_links (link, user_id, expiry) VALUES (?, ?, ?)', [link, user.id, expiry], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ link });
        });
    });
});

app.get('/link/:link', (req, res) => {
    const { link } = req.params;
    db.get('SELECT * FROM one_time_links WHERE link = ? AND used = 0 AND expiry > ?', [link, Date.now()], (err, linkData) => {
        if (err) {
            logger.error(err.message);
            return res.status(500).json({ error: err.message });
        }
        if (!linkData) return res.status(404).json({ error: 'Invalid or expired link' });

        db.run('UPDATE one_time_links SET used = 1 WHERE link = ?', [link], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            const token = generateToken();
            const expiry = Date.now() + 86400000; // 24 hours
            db.run('INSERT INTO tokens (token, user_id, expiry) VALUES (?, ?, ?)', [token, linkData.user_id, expiry], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ token });
            });
        });
    });
});

// Get Time API
app.get('/time', (req, res) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    db.get('SELECT * FROM tokens WHERE token = ? AND expiry > ?', [token, Date.now()], (err, tokenData) => {
        if (err) {
            logger.error(err.message);
            return res.status(500).json({ error: err.message });
        }
        if (!tokenData) return res.status(401).json({ error: 'Invalid token' });

        res.json({ time: new Date().toISOString() });
    });
});

// Kickout API
app.post('/kickout', (req, res) => {
    const { username } = req.body;
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            logger.error(err.message);
            return res.status(500).json({ error: err.message });
        }
        if (!user) return res.status(404).json({ error: 'User not found' });

        db.run('DELETE FROM tokens WHERE user_id = ?', [user.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'User kicked out' });
        });
    });
});

app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});