const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.db');
const bcrypt = require('bcrypt');

async function hashPassword(password) {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
}

db.serialize(async () => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        locked INTEGER DEFAULT 0,
        lockout_time INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        expiry INTEGER,
        used INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS one_time_links (
        link TEXT PRIMARY KEY,
        user_id INTEGER,
        expiry INTEGER,
        used INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // Seed data
    try {
        const hashedPassword1 = await hashPassword('test123');
        const hashedPassword2 = await hashPassword('12345');

        db.run('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', ['test@test.com', hashedPassword1]);
        db.run('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', ['0123456789', hashedPassword2]);

    } catch (err) {
        console.error('Error seeding data:', err);
    }

});

module.exports = db;