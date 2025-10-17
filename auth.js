// auth.js
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

// 1. Database Connection Pool
const pool = new Pool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    ssl: { rejectUnauthorized: false } 
});

// Test Connection and Create User Table
pool.query(`
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'employee'
    );
`).then(() => {
    console.log("Database connection successful. 'users' table ensured.");
    
    // --- Initial User Setup (for testing the first login) ---
    const adminEmail = 'admin@company.com';
    const adminPassword = 'Password123!'; // **CHANGE THIS IMMEDIATELY AFTER FIRST LOGIN!**

    // Check if admin user exists (Admin is created manually, as requested)
    pool.query('SELECT * FROM users WHERE email = $1', [adminEmail])
        .then(res => {
            if (res.rows.length === 0) {
                bcrypt.hash(adminPassword, 10)
                    .then(hash => {
                        pool.query('INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)', 
                            [adminEmail, hash, 'admin'])
                            .then(() => console.log(`Default admin user created: ${adminEmail}`))
                            .catch(err => console.error('Error inserting admin user:', err));
                    });
            }
        })
        .catch(err => console.error('Error checking for admin user:', err));

}).catch(err => {
    console.error('Database connection failed:', err.message);
    process.exit(1);
});


// 2. Passport Local Strategy Configuration
passport.use(new LocalStrategy(
    { usernameField: 'email' },
    async (email, password, done) => {
        try {
            const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            const user = result.rows[0];

            if (!user) {
                return done(null, false, { message: 'Incorrect email or password.' });
            }

            const isMatch = await bcrypt.compare(password, user.password_hash);

            if (isMatch) {
                return done(null, user); // Success
            } else {
                return done(null, false, { message: 'Incorrect email or password.' });
            }
        } catch (err) {
            return done(err);
        }
    }
));

// 3. Serialization (What to store in the session cookie)
passport.serializeUser((user, done) => {
    done(null, user.id); 
});

// 4. Deserialization (Retrieve full user info from DB using the ID from the cookie)
passport.deserializeUser(async (id, done) => {
    try {
        const result = await pool.query('SELECT id, email, role FROM users WHERE id = $1', [id]);
        const user = result.rows[0];
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// 5. Middleware to check if user is authenticated (THE CORE SECURITY CHECK)
const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next(); // User is logged in, allow access
    }
    // NOT logged in: redirect to login page
    res.redirect('/login'); 
};

module.exports = { 
    passport, 
    isAuthenticated,
    pool 
}; 
