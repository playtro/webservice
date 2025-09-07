// 1. Import Libraries
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt'); // Import bcrypt

// 2. App Setup
const app = express();
const PORT = 3000;
const saltRounds = 10; // For bcrypt hashing

// This is our "fake" database. It's an in-memory array.
// NOTE: This will reset every time the server restarts!
// In a real app, you would use a proper database like PostgreSQL, MongoDB, or SQLite.
let users = [];

// 3. Middleware
app.use(express.static('public')); 
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'a-very-strong-and-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } 
}));

function checkAuth(req, res, next) {
    if (req.session.isLoggedIn) {
        next(); 
    } else {
        res.redirect('/');
    }
}

// 4. Routes
// === NEW: REGISTRATION ROUTE ===
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check if username already exists
        const existingUser = users.find(user => user.username === username);
        if (existingUser) {
            return res.redirect('/register.html?error=Username already taken');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Store the new user
        users.push({ username, password: hashedPassword });
        console.log('Users array:', users); // For debugging

        // Redirect to login page with a success message
        res.redirect('/?success=1');
    } catch {
        res.redirect('/register.html?error=Something went wrong');
    }
});


// === UPDATED: LOGIN ROUTE ===
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find the user in our users array
        const user = users.find(u => u.username === username);
        
        // If user exists and password is correct (using bcrypt.compare)
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.isLoggedIn = true;
            req.session.username = username;
            res.redirect('/dashboard');
        } else {
            res.redirect('/?error=1');
        }
    } catch {
        res.redirect('/?error=1');
    }
});


// (These routes remain the same)
app.get('/dashboard', checkAuth, (req, res) => {
    res.send(`
        <h1>Welcome to your Dashboard, ${req.session.username}!</h1>
        <p>This page is protected. Only logged-in users can see it.</p>
        <a href="/logout">Logout</a>
    `);
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/dashboard');
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});


// 5. Start the Server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});