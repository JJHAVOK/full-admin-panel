// server.js
const express = require('express');
const path = require('path');
const session = require('express-session');
require('dotenv').config(); 

// Import Passport and the security middleware
const { passport, isAuthenticated } = require('./auth'); 

const app = express();
const PORT = process.env.PORT || 3000;

// --- Middlewares ---

// Body parser for form data
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Serve static files (CSS, JS, images for all pages)
app.use(express.static(path.join(__dirname, 'public'))); 

// Session Setup
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 24 hours
}));

// Passport Initialization
app.use(passport.initialize());
app.use(passport.session());


// --- Routes ---

// 1. GET: Login Page
app.get('/login', (req, res) => {
    // If already logged in, redirect to the dashboard
    if (req.isAuthenticated()) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// 2. POST: Handle Login Submission
app.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login?error=1', 
}));

// 3. GET: Logout
app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        res.redirect('/login');
    });
});

// --- SECURED ADMIN PANEL ROUTES ---

// The isAuthenticated middleware is applied to ALL routes below this line
// This is the core of your security requirement!

// 4. GET: Dashboard (Priority 1)
app.get('/dashboard', isAuthenticated, (req, res) => {
    // You can access user info here: req.user.email, req.user.role
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// 5. FUTURE ROUTES (Protected by isAuthenticated)
app.get('/analytics', isAuthenticated, (req, res) => {
    res.send('Analytics Page (SECURED)'); 
});
app.get('/crm', isAuthenticated, (req, res) => {
    res.send('CRM Page (SECURED)'); 
});
// ... and so on for all 7 menu items + others ...

// Default root redirect
app.get('/', (req, res) => {
    res.redirect('/dashboard');
});


// --- Server Start ---
app.listen(PORT, () => {
  console.log(`Admin Panel Server is running on port ${PORT}`);
  console.log(`Test Login URL: http://localhost:${PORT}/login`);
}); 
