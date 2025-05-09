# Secure-Web-Application
This project implements a secure web application with user management functionality, addressing common security vulnerabilities. The application includes user registration, login, and dashboard features, with mitigations for SQL injection, weak password storage, XSS, access control issues, and encryption.

# Acknowledgement
We would like to acknowledge that we used OpenAI’s ChatGPT as a supplementary tool while working on this project. We used it for language refinement and clarification on technical concepts. 

# Features
1. User registration and login

2. Dashboard displaying user information

3. Secure session management

4. Role-based access control (admin/user roles)

5. Comment system (for XSS demonstration)

# Security Implementations
1. SQL Injection Mitigation: Uses parameterized queries

2. Password Storage: Uses bcrypt for secure hashing

3. XSS Prevention: (Intentionally left vulnerable for grading purposes)

4. Access Control: Role-based restrictions (admin pages protected)

5. Encryption: HTTPS implemented with TLS/SSL

# How to Run
1. Install dependencies: `npm install express sqlite3 express-session bcrypt pug`

2. Generate SSL certificates and place in `/ssl` folder

3. Start server: `node server.js`

4. Access at: `https://localhost:3000`

# Testing Security Features
1. SQL Injection: Try `' OR '1'='1` in login - should fail

2. Password Storage: Check database to see bcrypt hashes

3. XSS: Try `<script>alert(1)</script>` in comments - intentionally vulnerable

4. Access Control: Try accessing `/admin` as regular user - should be blocked

5. HTTPS: Verify padlock icon in browser
