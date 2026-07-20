## 🛡️ VerifiXAI — AI-Based Email Phishing Detection System

VerifiXAI is a complete **AI-powered email phishing detection system** that uses **Machine Learning**, **Natural Language Processing**, and **Explainable AI (SHAP)** to identify phishing emails with **95%+ accuracy**. It provides real-time analysis, user authentication, scan history, and an admin dashboard — all in a secure, scalable package.

## Key Features:
AI-Powered Detection — Uses a Random Forest classifier trained on 80,000+ emails with 95%+ accuracy.
Explainable AI (SHAP) — Provides detailed, human-readable explanations for why an email is flagged as phishing or safe.
Real-Time Analysis — Paste or upload .txt files for instant email scanning.
User Authentication — Secure registration and login with JWT tokens.
Scan History — Users can view all past email analyses.
Dashboard & Statistics — Visual insights into total scans, phishing vs. safe emails, and user activity.
Admin Panel — Manage users, view system analytics, and monitor ML model performance.
Secure & Scalable — Password hashing with bcrypt, JWT authentication, and MySQL database.

## Tech Stack:
Layer	Technology
Frontend	HTML5, CSS3, JavaScript
Backend	FastAPI (Python)
Machine Learning	scikit-learn, NLTK, SHAP
Database	MySQL
Authentication	JWT (PyJWT) + bcrypt
Deployment	Uvicorn (ASGI server)

## Project Structure:
text
VerifiXAI/
├── backend/
│   ├── main.py              # FastAPI application
│   ├── db_connector.py      # MySQL database handler
│   ├── preprocessor.py      # NLP text preprocessing
│   ├── shap_explainer.py    # SHAP explainability logic
│   └── ml_model.py          # Model training & prediction
├── frontend/
│   ├── index.html           # Landing page
│   ├── user_login.html      # User login
│   ├── register.html        # User registration
│   ├── user_dashboard.html  # User dashboard
│   ├── admin_login.html     # Admin login
│   ├── admin_dashboard.html # Admin panel
│   └── api.js               # Frontend-backend API client
├── models/
│   ├── rf_model.pkl         # Trained Random Forest model
│   └── tfidf_vectorizer.pkl # TF-IDF vectorizer
├── dataset/                 # Training dataset (CSV)
├── .env                     # Environment variables
└── requirements.txt         # Python dependencies


## Screenshots

| User Login | User Dashboard |
|------------|----------------|
| ![User Login](screenshots/user_login.png) | ![User Dashboard](screenshots/user_dashboard.png) |

| Admin Login | Admin Dashboard |
|-------------|-----------------|
| ![Admin Login](screenshots/admin_login.png) | ![Admin Dashboard](screenshots/admin_dashboard.png) |

| Email Analysis | Registration |
|---------------|--------------|
| ![Email Check](screenshots/email_check.png) | ![Register](screenshots/register.png) |

Virtual environment (recommended)
