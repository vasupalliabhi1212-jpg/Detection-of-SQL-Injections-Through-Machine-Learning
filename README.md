# 🎯 Cybersecurity Threat Detection System

A comprehensive web application for real-time attack detection, user authentication, and threat intelligence.

## 🚀 Quick Start

### Option 1: Double-click to run
- Double-click `start_server.bat` to start the application

### Option 2: Command line
```bash
python server.py
```

## 🌐 Access Your Application

Once started, access these URLs:

- **🏠 Home Page**: http://localhost:5000/
- **📊 Dashboard**: http://localhost:5000/dashboard
- **🔐 Login**: http://localhost:5000/login
- **📝 Signup**: http://localhost:5000/signup
- **ℹ️ About**: http://localhost:5000/about

## 🛡️ Features

- ✅ **Real-time Attack Detection** (SQL Injection, XSS, Command Injection, etc.)
- ✅ **Email Notifications** for detected threats
- ✅ **User Authentication** with secure password hashing
- ✅ **Threat Intelligence Dashboard** with live metrics
- ✅ **Login Monitoring** for suspicious activity
- ✅ **SQLite Database** for data persistence

## 📧 Email Configuration

The system sends email alerts from `datapropro9@gmail.com` when attacks are detected.

## 🗂️ Project Structure

```
├── server.py              # Main Flask application
├── .env                   # Email configuration (secure)
├── requirements.txt       # Python dependencies
├── start_server.bat      # Windows startup script
├── templates/             # HTML templates
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   ├── dashboard.html
│   ├── shopping.html
│   └── about.html
├── static/                # CSS and JavaScript files
└── users.db              # SQLite database (auto-created)
```

## 🧪 Testing Features

1. **Attack Detection**: Go to dashboard and enter payloads like `SELECT * FROM users`
2. **User Registration**: Create accounts via the signup page
3. **Login Security**: Try suspicious passwords to trigger alerts
4. **Email Testing**: Use the `/api/test-email` endpoint

## 🔧 Configuration

Edit `.env` file to change email settings:
```env
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
```

## 🛑 Stopping the Server

Press `Ctrl+C` in the terminal to stop the server.

---

**Built with Flask, scikit-learn, and SQLite**