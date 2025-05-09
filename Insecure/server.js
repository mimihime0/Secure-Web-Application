// 1-Initial Setup
// Import the libraries installed (in node_modules)
const crypto = require('crypto');
const express = require('express');
let comments = []; // XSS testing only


// The DB library
// .verbose() gives detailed error messages when database error happens
 const sqlite3 = require('sqlite3').verbose();

//  library to set up a user session
 const expressSession = require('express-session'); 

// creates an instance of an Express application
const app = express();

// Configure Templating Engine (to create dynamic html files)
app.set('view engine', 'pug'); // Set the view engine to pug
app.set('views', './templates'); // Specify the directory where the HTML files are located

// Set the port number 
const port = 3000; 
app.use(express.static('css'));
//  Session Middleware Setup 
// so every incoming request will pass through this middleware before reaching routes
app.use(expressSession({
    secret: 'secret_key', // a secret key used to sign the session ID in the cookie
    // If someone tries to change the session ID in the cookie, Express will detect that the signature is invalid
    resave: false, // Don't save session if unmodified
    saveUninitialized: false, // Don't create session until something is stored in it 
    cookie: { secure: false } // Set to true if using HTTPS but false means using HTTP
}));
// then each user has unique req.session object to store information (like their user ID) across their requests

// Middleware to parse request bodies before responding to the user
app.use(express.urlencoded({ extended: false })); 
//  For parsing content-type of application/x-www-form-urlencoded, which is the default format for HTML 
// then after parsing, users data will be stored in the req.body property of the request object

//------------------------------

// 2-Database Setup 
// This defines the name and location of the SQLite database file
const dbFile = './database.db'; 

// Create and open the database connection
// sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE: Opens the database for reading and writing. If the database file does not exist, it is created.
// after attempting to open/create the database file a callback funtion is called with an Error object passed to it
const db = new sqlite3.Database(dbFile, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to the SQLite database.');

    // Create the users table if it doesn't exist
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        major TEXT
    )`, (err) => {
      if (err) {
        console.error('Error creating users table:', err.message);
      } else {
        console.log('Users table checked/created successfully.');
      }
    });
  }
});

//------------------------------

// 3- Handling requests
// Route to display the registration form when a /register GET request is received 
app.get('/register', (req, res) => {
    res.sendFile(__dirname + '/templates/register.html');
  });

// Route to handle registration form submission (POST request)
// vulnerable to SQL Injection
app.post('/register', (req, res) => {
    // Get user input from the POST request body 
    const username = req.body.username;
    const password = crypto.createHash('md5').update(req.body.password).digest('hex');
    const email = req.body.email;
    const major = req.body.major; 

    // We are embedding user input directly into the SQL query string.
    // This is what makes it vulnerable to SQL Injection.
    const sql = `INSERT INTO users (username, password, email, major) VALUES ('${username}', '${password}', '${email}', '${major}')`;
    db.exec(sql, function(err) { 
        if (err) {
            console.error('Error during registration INSERT:', err.message);

            // Check if the error is due to unique constraint (username or email already exists)
            if (err.message.includes('UNIQUE constraint failed')) {
                res.status(409).send('Username or email already exists.'); 
            } else {
                res.status(500).send('Error registering user.'); 
            }

        } else {
            // Registration successful
            console.log(`User ${username} registered with ID: ${this.lastID}`); // this.lastID is the ID of the newly inserted row

            // Redirect to the login page after successful registration
            res.redirect('/login');
        }
    });
});

// Route to display the login form
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/templates/login.html');
});

// Route to handle login form submission (POST request)
// Password verification is INSECURE 
app.post('/login', (req, res) => {
    const username = req.body.username;
    const submittedPassword = crypto.createHash('md5').update(req.body.password).digest('hex');

    // Basic validation
    if (!username || !submittedPassword) {
        return res.status(400).send('Username and password are required.');
    }

    // const sql = `SELECT id, username, password FROM users WHERE username = '${username}'`; 
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${submittedPassword}'`;

    db.get(sql, (err, user) => { 
        if (err) {
            console.error('Error during login SELECT:', err.message);
            res.status(500).send('An error occurred during login.');
            return;
        }

        // Check if a user with that username was found
        if (!user) {
            // User not found
            console.log(`Login failed: User ${username} not found.`);
            res.send('Login failed: User not found.'); 
            return;
        }

        // Comparing submitted password directly to the stored password from the database
        if (user) {
            console.log(`Login bypassed via SQL injection or regular login.`);
            req.session.userId = user.id;
            res.redirect('/dashboard');
        } else {
            res.send('Login failed: No user found.');
        }
        
    });
});

// Route for the Dashboard (requires login)
app.get('/dashboard', (req, res) => {
    // Check if the user is logged in by looking for their ID in the session
    if (!req.session || !req.session.userId) {
        console.log('Access Denied: Attempted to access dashboard without login.');
        // If not logged in, redirect to the login page
        return res.redirect('/login');
    }

    // User is logged in, retrieve their details from the database
    const userId = req.session.userId;
    const sql = `SELECT username, email, major FROM users WHERE id = ${userId}`; 
    db.get(sql, (err, user) => { 
        if (err) {
            console.error('Error retrieving user for dashboard:', err.message);
            res.status(500).send('Error loading dashboard.');
            return;
        }

        // Check if user was found 
        if (!user) {
             console.error(`User with ID ${userId} not found in DB despite session.`);
             // Clear the invalid session and redirect to login
             req.session.destroy(err => {
                if (err) console.error('Error destroying session:', err);
                res.redirect('/login');
             });
             return;
        }

        // Render the Dashboard Template 
        // Use res.render() to send the HTML file and pass the user data
        res.render('dashboard', { // 'dashboard' matches the dashboard.pug filename
            username: user.username,
            email: user.email,
            major: user.major,
            comments: comments
        });
    });
});
app.post('/comment', (req, res) => {
    const newComment = req.body.comment;
    comments.push(newComment); // Unsafe on purpose
    res.redirect('/dashboard');
});


// Route for Logout
app.get('/logout', (req, res) => {
    // Check if a session exists before trying to destroy it
    if (req.session) {
        // Destroy the session
        req.session.destroy(err => {
            if (err) {
                console.error('Error destroying session:', err);
                // Even if there's an error destroying session, redirect to login
                res.redirect('/login');
            } else {
                console.log('User logged out.');
                // Redirect to the login page after successful logout
                res.redirect('/login');
            }
        });
    } else {
        // If no session exists, just redirect to login 
        res.redirect('/login');
    }
});

// Route for the Admin Page
app.get('/admin', (req, res) => {
    console.log('Accessing Admin page');
    res.sendFile(__dirname + '/templates/admin.html');
});

//------------------------------

app.get('/users', (req, res) => {
    db.all(`SELECT * FROM users`, (err, rows) => {
        if (err) {
            console.error('Error reading users:', err.message);
            return res.status(500).send('Error reading users.');
        }
        res.json(rows); // Show all users in browser
    });
});

// Start the server 
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}/`);
});

//------------------------------
// 4- Closing DB connection 
// if Ctrl+C in the terminal, it will try to close the database connection before the application exits
process.on('SIGINT', () => {
  console.log('Closing database connection.');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed.');
    }
    process.exit(0); 
  });
});