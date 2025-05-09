# Secure Web Application

## Overview

This Node.js + Express application demonstrates common web security vulnerabilities and how to fix them.  
It includes:

- User registration and login  
- Secure password storage (MD5 → bcrypt)  
- SQL Injection protection  
- Cross-Site Scripting (XSS) prevention  
- Role-Based Access Control (RBAC)  
- HTTPS encryption using self-signed certificates  

---

## Steps to Run the Application

1. **Install dependencies**
```bash
npm install
```

2. **Generate HTTPS certificates (self-signed)**
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

3. **Run the application**
```bash
node server.js
```

4. **Open the application in your browser**
```
https://localhost:3000
```

---

## How to Test Security Features

### ✅ SQL Injection

- Initially: Try logging in using `' OR '1'='1` as the username to bypass authentication.
- After Fix: The same attempt should fail.
- **Screenshot Tip**: Before and after fixing `login` route (using raw SQL vs. prepared statements).

### ✅ Weak Password Storage (MD5 → bcrypt)

- Initially: Check database for MD5 hashed passwords.
- After Fix: Passwords are hashed using bcrypt.
- **Screenshot Tip**: Database contents before and after switching to bcrypt.

### ✅ Cross-Site Scripting (XSS)

- Initially: Submit a comment like `<script>alert('XSS')</script>` on dashboard.
- After Fix: The script tag should appear as text and not execute.
- **Screenshot Tip**: Page before and after adding input sanitization.

### ✅ Access Control (RBAC)

- Initially: Login as a regular user and try to access `/admin`.
- After Fix: Only users with role "admin" can access it.
- **Screenshot Tip**: Forbidden message before fix, proper access after fix.


### ✅ Encryption (HTTPS - TLS/SSL)

- Verify that your app runs on `https://localhost:3000`.
- Click the lock icon in your browser to view the self-signed certificate.
- **Screenshot Tip**: Warning page and lock icon showing HTTPS.

This project uses self-signed SSL certificates (key.pem and cert.pem) to enable HTTPS for secure communication. These files are required to run the application locally with TLS/SSL encryption.
Note:  
Although key.pem and cert.pem are part of the local project setup, they were not added to GitHub for security reasons. 
