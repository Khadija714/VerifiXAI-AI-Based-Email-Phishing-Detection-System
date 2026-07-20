# backend/main.py
import sys
import os
import time
import jwt
import bcrypt
import joblib
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv
import traceback

# Ensure backend folder is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from preprocessor import preprocess_text
from shap_explainer import SHAPExplainer
from backend.db_connector import DatabaseHandler

load_dotenv()

app = FastAPI(title="AI Phishing Detection API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT settings
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 60 * 24  # 24 hours

# Global ML components
rf_model = None
tfidf = None
shap_explainer = None
db = DatabaseHandler()

# -------------------- Helper --------------------
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")

def predict_email(email_text: str):
    processed = preprocess_text(email_text)
    vec = tfidf.transform([processed]).toarray()
    prob = rf_model.predict_proba(vec)[0]
    phishing_prob = prob[1] * 100.0
    if phishing_prob >= 50:
        result = "phishing"
        confidence = round(phishing_prob, 2)
    else:
        result = "safe"
        confidence = round(100 - phishing_prob, 2)
    if confidence < 50:
        risk_level = "low"
    elif confidence < 75:
        risk_level = "medium"
    else:
        risk_level = "high"
    shap_result = shap_explainer.explain_email(email_text, top_n=5)
    risk_factors = [f["feature"] for f in shap_result.get("factors", [])]
    return {
        "result": result,
        "confidence": confidence,
        "risk_level": risk_level,
        "risk_factors": risk_factors
    }

# -------------------- Startup --------------------
@app.on_event("startup")
async def startup():
    global rf_model, tfidf, shap_explainer
    model_path = "models/rf_model.pkl"
    vec_path = "models/tfidf_vectorizer.pkl"
    if os.path.exists(model_path) and os.path.exists(vec_path):
        rf_model = joblib.load(model_path)
        tfidf = joblib.load(vec_path)
        shap_explainer = SHAPExplainer(rf_model, tfidf)
        print("ML models loaded")
    else:
        print("WARNING: Model files missing. Please train first.")
    # Connect to database
    if db.connect():
        print("Database connected")
    else:
        print("WARNING: Database connection failed")

@app.on_event("shutdown")
async def shutdown():
    db.close()

# -------------------- Request/Response models --------------------
class RegisterRequest(BaseModel):
    user_name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class EmailRequest(BaseModel):
    email_text: str
    user_id: Optional[int] = None

class FeedbackRequest(BaseModel):
    scan_id: int
    correct_prediction: bool
    feedback_rating: int
    feedback_text: Optional[str] = None
    reported_category: Optional[str] = None

# -------------------- Auth Endpoints (with enhanced error handling) --------------------
@app.post("/api/auth/register")
async def register(req: RegisterRequest):
    try:
        print(f"🔐 Registration attempt: {req.email}")
        
        # Check if email already exists
        existing = db.get_user_by_email(req.email)
        if existing:
            print(f"❌ Email already registered: {req.email}")
            raise HTTPException(400, "Email already registered")
        
        # Create user
        user_id = db.create_user(req.user_name, req.email, req.password)
        if not user_id:
            print(f"❌ Registration failed for: {req.email}")
            raise HTTPException(500, "Registration failed")
        
        print(f"✅ User registered successfully: ID={user_id}, Email={req.email}")
        
        # Generate token
        token = create_access_token({"sub": str(user_id), "email": req.email})
        
        return {
            "success": True,
            "access_token": token,
            "user_id": user_id,
            "username": req.user_name,
            "email": req.email
        }
    except HTTPException:
        raise
    except Exception as e:
        print("=" * 60)
        print("🔥 UNHANDLED ERROR IN REGISTER")
        print(f"Error: {e}")
        traceback.print_exc()
        print("=" * 60)
        raise HTTPException(500, f"Internal server error: {str(e)}")

@app.post("/api/auth/login")
async def login(req: LoginRequest):
    try:
        print(f"🔐 Login attempt: {req.email}")
        print(f"🔍 Debug: Password received: {req.password[:3]}...")
        
        user = db.get_user_by_email(req.email)
        print(f"🔍 Debug: User found: {user is not None}")
        
        if not user:
            print(f"❌ User not found: {req.email}")
            raise HTTPException(401, "Invalid credentials")
        
        print(f"🔍 Debug: Stored hash: {user['password'][:20]}...")
        
        if not bcrypt.checkpw(req.password.encode('utf-8'), user['password'].encode('utf-8')):
            print(f"❌ Password mismatch for: {req.email}")
            raise HTTPException(401, "Invalid credentials")
        
        print(f"✅ Password match for: {req.email}")
        
        db.update_last_login(user['user_id'])
        token = create_access_token({"sub": str(user['user_id']), "email": user['email']})
        
        return {
            "success": True,
            "access_token": token,
            "user_id": user['user_id'],
            "username": user['user_name'],
            "email": user['email']
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"🔥 Login error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Login failed: {str(e)}")
    
# -------------------- Admin Auth Endpoint --------------------
@app.post("/api/admin/login")
async def admin_login(req: LoginRequest):
    try:
        print(f"🔐 Admin login attempt: {req.email}")
        admin = db.get_admin_by_username(req.email)
        if not admin:
            print(f"❌ Admin not found: {req.email}")
            raise HTTPException(401, "Invalid credentials")
        
        if not bcrypt.checkpw(req.password.encode('utf-8'), admin['password'].encode('utf-8')):
            print(f"❌ Invalid password for admin: {req.email}")
            raise HTTPException(401, "Invalid credentials")
        
        token = create_access_token({
            "sub": str(admin['admin_id']),
            "role": admin['role'],
            "username": admin['username']
        })
        
        print(f"✅ Admin login successful: {admin['username']}")
        
        return {
            "success": True,
            "access_token": token,
            "username": admin['username'],
            "role": admin['role']
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"🔥 Admin login error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Admin login failed: {str(e)}")

@app.get("/api/users/me")
async def get_me(authorization: Optional[str] = Header(None)):
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Missing token")
        token = authorization.split(" ")[1]
        payload = verify_token(token)
        user_id = int(payload.get("sub"))
        user = db.get_user_by_id(user_id)
        if not user:
            raise HTTPException(404, "User not found")
        return {
            "user_id": user['user_id'],
            "username": user['user_name'],
            "email": user['email'],
            "total_scans": user['total_scans']
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"🔥 Get me error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Error: {str(e)}")

# -------------------- Analysis Endpoint --------------------
@app.post("/api/analyze")
async def analyze_email(req: EmailRequest):
    try:
        if rf_model is None:
            raise HTTPException(503, "Model not loaded")
        start_time = time.time()
        pred = predict_email(req.email_text)
        elapsed = int((time.time() - start_time) * 1000)
        scan_id = None
        if req.user_id:
            active_model = db.get_active_model()
            model_id = active_model['model_id'] if active_model else 1
            scan_id = db.save_scan(
                user_id=req.user_id,
                model_id=model_id,
                original_text=req.email_text,
                prediction_result=pred['result'],
                confidence_score=pred['confidence'],
                risk_level=pred['risk_level'],
                processing_time=elapsed
            )
        return {
            "success": True,
            "result": pred['result'],
            "confidence": pred['confidence'],
            "risk_level": pred['risk_level'],
            "risk_factors": pred['risk_factors'],
            "scan_id": scan_id,
            "processing_time_ms": elapsed
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"🔥 Analysis error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Analysis failed: {str(e)}")

# -------------------- User Stats & History --------------------
@app.get("/api/user/{user_id}/stats")
async def get_user_stats(user_id: int, authorization: Optional[str] = Header(None)):
    try:
        stats = db.get_user_stats(user_id)
        return {"stats": stats}
    except Exception as e:
        print(f"🔥 Stats error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Stats error: {str(e)}")

@app.get("/api/user/{user_id}/scans")
async def get_user_scans(user_id: int, limit: int = 50, page: int = 1,
                         authorization: Optional[str] = Header(None)):
    try:
        scans = db.get_user_scans(user_id, limit, page)
        return {"scans": scans, "total": len(scans), "page": page}
    except Exception as e:
        print(f"🔥 Scans error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Scans error: {str(e)}")

@app.delete("/api/user/{user_id}/scan/{scan_id}")
async def delete_scan(user_id: int, scan_id: int, authorization: Optional[str] = Header(None)):
    try:
        success = db.delete_scan(user_id, scan_id)
        if not success:
            raise HTTPException(404, "Scan not found")
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        print(f"🔥 Delete scan error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Delete error: {str(e)}")

# -------------------- Feedback --------------------
@app.post("/api/feedback")
async def submit_feedback(req: FeedbackRequest, authorization: Optional[str] = Header(None)):
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Missing token")
        token = authorization.split(" ")[1]
        payload = verify_token(token)
        user_id = int(payload.get("sub"))
        success = db.save_feedback(
            user_id=user_id,
            scan_id=req.scan_id,
            correct_prediction=req.correct_prediction,
            feedback_rating=req.feedback_rating,
            feedback_text=req.feedback_text,
            reported_category=req.reported_category
        )
        if not success:
            raise HTTPException(500, "Failed to save feedback")
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        print(f"🔥 Feedback error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Feedback error: {str(e)}")

# -------------------- Additional endpoints --------------------
@app.get("/api/patterns")
async def get_patterns():
    try:
        patterns = db.get_active_patterns()
        return {"patterns": patterns}
    except Exception as e:
        print(f"🔥 Patterns error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Patterns error: {str(e)}")

@app.get("/api/model/info")
async def model_info():
    try:
        active_model = db.get_active_model()
        if active_model:
            return {"model": active_model['model_name'], "algo": active_model['algo'],
                    "accuracy": active_model['accuracy'], "f1_score": active_model['f1_score']}
        else:
            return {"model": "RandomForest", "version": "1.0", "accuracy": 93.6}
    except Exception as e:
        print(f"Model info error: {e}")
        traceback.print_exc()
        return {"model": "RandomForest", "version": "1.0", "accuracy": 93.6}

@app.get("/api/health")
async def health():
    db_ok = db.conn is not None and db.conn.is_connected()
    return {"status": "ok", "database": "connected" if db_ok else "disconnected",
            "ml_model": "loaded" if rf_model else "not loaded"}



        # -------------------- Admin Dashboard Endpoints --------------------

@app.get("/api/admin/stats")
async def admin_stats(authorization: Optional[str] = Header(None)):
    """Get admin dashboard statistics"""
    try:
        # Verify admin token
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Missing token")
        token = authorization.split(" ")[1]
        payload = verify_token(token)
        if payload.get("role") != "admin":
            raise HTTPException(403, "Admin access required")
        
        # Get stats from database
        total_users = db.count_users()
        total_scans = db.count_scans()
        phishing_count = db.count_phishing_scans()
        safe_count = db.count_safe_scans()
        
        return {
            "success": True,
            "stats": {
                "total_users": total_users,
                "total_scans": total_scans,
                "phishing_count": phishing_count,
                "safe_count": safe_count
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"🔥 Admin stats error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Stats error: {str(e)}")

@app.get("/api/admin/users")
async def admin_users(limit: int = 20, page: int = 1, authorization: Optional[str] = Header(None)):
    """Get list of users for admin dashboard"""
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Missing token")
        token = authorization.split(" ")[1]
        payload = verify_token(token)
        if payload.get("role") != "admin":
            raise HTTPException(403, "Admin access required")
        
        users = db.get_all_users(limit=limit, page=page)
        total = db.count_users()
        
        return {
            "success": True,
            "users": users,
            "total": total,
            "page": page,
            "limit": limit
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"🔥 Admin users error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Users error: {str(e)}")

@app.get("/api/admin/scans")
async def admin_scans(limit: int = 50, page: int = 1, authorization: Optional[str] = Header(None)):
    """Get list of all scans for admin dashboard"""
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Missing token")
        token = authorization.split(" ")[1]
        payload = verify_token(token)
        if payload.get("role") != "admin":
            raise HTTPException(403, "Admin access required")
        
        scans = db.get_all_scans(limit=limit, page=page)
        total = db.count_scans()
        
        return {
            "success": True,
            "scans": scans,
            "total": total,
            "page": page,
            "limit": limit
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"🔥 Admin scans error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Scans error: {str(e)}")

@app.get("/api/admin/analytics")
async def admin_analytics(authorization: Optional[str] = Header(None)):
    """Get analytics data for admin dashboard charts"""
    try:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Missing token")
        token = authorization.split(" ")[1]
        payload = verify_token(token)
        if payload.get("role") != "admin":
            raise HTTPException(403, "Admin access required")
        
        daily_data = db.get_daily_scans(days=7)
        
        return {
            "success": True,
            "analytics": {
                "daily_scans": daily_data
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"🔥 Admin analytics error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Analytics error: {str(e)}")