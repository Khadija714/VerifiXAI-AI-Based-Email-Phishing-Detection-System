# backend/db_connector.py
import os
import mysql.connector
from mysql.connector import Error
import bcrypt
from datetime import datetime
from typing import Optional, Dict, List, Any
from dotenv import load_dotenv
import traceback

load_dotenv()

class DatabaseHandler:
    def __init__(self):
        self.conn = None
        self.cursor = None
        self.config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'database': os.getenv('DB_NAME', 'phishing_detection'),
            'user': os.getenv('DB_USER', 'root'),
            'password': os.getenv('DB_PASSWORD', ''),
            'port': int(os.getenv('DB_PORT', 3306))
        }
    
    def connect(self):
        try:
            self.conn = mysql.connector.connect(**self.config)
            self.cursor = self.conn.cursor(dictionary=True)
            return True
        except Error as e:
            print(f"Database connection error: {e}")
            return False
    
    def close(self):
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
    
    def ensure_connection(self):
        if not self.conn or not self.conn.is_connected():
            self.connect()
    
    # ---------- USER OPERATIONS ----------
    def create_user(self, user_name: str, email: str, password: str) -> Optional[int]:
        """Register new user"""
        self.ensure_connection()
        try:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            query = """
                INSERT INTO users (user_name, email, password, created_at, is_active, total_scans)
                VALUES (%s, %s, %s, NOW(), 1, 0)
            """
            self.cursor.execute(query, (user_name, email, password_hash))
            self.conn.commit()
            return self.cursor.lastrowid
        except Exception as e:
            print("=" * 60)
            print("❌ REGISTRATION ERROR")
            print(f"Error type: {type(e).__name__}")
            print(f"Error message: {e}")
            print("Traceback:")
            traceback.print_exc()
            print("=" * 60)
            return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        self.ensure_connection()
        query = "SELECT * FROM users WHERE email = %s"
        self.cursor.execute(query, (email,))
        return self.cursor.fetchone()
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        self.ensure_connection()
        query = "SELECT * FROM users WHERE user_id = %s"
        self.cursor.execute(query, (user_id,))
        return self.cursor.fetchone()
    
    def update_last_login(self, user_id: int):
        self.ensure_connection()
        query = "UPDATE users SET last_login = NOW() WHERE user_id = %s"
        self.cursor.execute(query, (user_id,))
        self.conn.commit()
    
    def increment_total_scans(self, user_id: int):
        self.ensure_connection()
        query = "UPDATE users SET total_scans = total_scans + 1 WHERE user_id = %s"
        self.cursor.execute(query, (user_id,))
        self.conn.commit()
    
    # ---------- SCAN OPERATIONS ----------
    def save_scan(self, user_id: int, model_id: int, original_text: str,
                  prediction_result: str, confidence_score: float,
                  risk_level: str, processing_time: int = 0) -> Optional[int]:
        self.ensure_connection()
        query = """
            INSERT INTO email_scans 
            (user_id, model_id, original_text, prediction_result, confidence_score, 
             risk_level, scan_timestamp, processing_time)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s)
        """
        try:
            self.cursor.execute(query, (user_id, model_id, original_text,
                                        prediction_result, confidence_score,
                                        risk_level, processing_time))
            self.conn.commit()
            scan_id = self.cursor.lastrowid
            self.increment_total_scans(user_id)
            return scan_id
        except Error as e:
            print(f"Error saving scan: {e}")
            return None
    
    def get_user_scans(self, user_id: int, limit: int = 50, page: int = 1) -> List[Dict]:
        self.ensure_connection()
        offset = (page - 1) * limit
        query = """
            SELECT scan_id, original_text, prediction_result, confidence_score,
                   risk_level, scan_timestamp, processing_time
            FROM email_scans
            WHERE user_id = %s
            ORDER BY scan_timestamp DESC
            LIMIT %s OFFSET %s
        """
        self.cursor.execute(query, (user_id, limit, offset))
        return self.cursor.fetchall()
    
    def get_user_stats(self, user_id: int) -> Dict:
        self.ensure_connection()
        user = self.get_user_by_id(user_id)
        total = user['total_scans'] if user else 0
        query = """
            SELECT 
                COUNT(CASE WHEN prediction_result = 'phishing' THEN 1 END) AS phishing_count,
                COUNT(CASE WHEN prediction_result = 'safe' THEN 1 END) AS safe_count
            FROM email_scans
            WHERE user_id = %s
        """
        self.cursor.execute(query, (user_id,))
        result = self.cursor.fetchone()
        return {
            'total_scans': total,
            'phishing_count': result['phishing_count'] or 0,
            'safe_count': result['safe_count'] or 0
        }
    
    def delete_scan(self, user_id: int, scan_id: int) -> bool:
        self.ensure_connection()
        query = "DELETE FROM email_scans WHERE scan_id = %s AND user_id = %s"
        try:
            self.cursor.execute(query, (scan_id, user_id))
            self.conn.commit()
            if self.cursor.rowcount > 0:
                update_query = "UPDATE users SET total_scans = total_scans - 1 WHERE user_id = %s AND total_scans > 0"
                self.cursor.execute(update_query, (user_id,))
                self.conn.commit()
            return self.cursor.rowcount > 0
        except Error as e:
            print(f"Error deleting scan: {e}")
            return False
    
    # ---------- FEEDBACK ----------
    def save_feedback(self, user_id: int, scan_id: int, correct_prediction: bool,
                      feedback_rating: int, feedback_text: str = None,
                      reported_category: str = None) -> bool:
        self.ensure_connection()
        query = """
            INSERT INTO user_feedback
            (user_id, scan_id, correct_prediction, feedback_rating, feedback_text, reported_category)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        try:
            self.cursor.execute(query, (user_id, scan_id, correct_prediction,
                                        feedback_rating, feedback_text, reported_category))
            self.conn.commit()
            return True
        except Error as e:
            print(f"Error saving feedback: {e}")
            return False
    
    # ---------- PHISHING PATTERNS ----------
    def get_active_patterns(self) -> List[Dict]:
        self.ensure_connection()
        query = """
            SELECT pattern_id, pattern_category, keyword, regex_pattern, risk_weight
            FROM phishing_patterns
            WHERE is_active = 1
        """
        self.cursor.execute(query)
        return self.cursor.fetchall()
    
    # ---------- MODEL INFO ----------
    def get_active_model(self) -> Optional[Dict]:
        self.ensure_connection()
        query = """
            SELECT model_id, model_name, algo, accuracy, f1_score, model_path
            FROM ml_model
            WHERE is_active = 1
            ORDER BY model_id DESC LIMIT 1
        """
        self.cursor.execute(query)
        return self.cursor.fetchone()
    
    # ---------- SAVE SHAP EXPLANATION ----------
    def save_shap_explanation(self, scan_id: int, shap_data: List[Dict]):
        self.ensure_connection()
        query = """
            INSERT INTO shap_explanation (scan_id, feature_impact, shap_value, base_value)
            VALUES (%s, %s, %s, %s)
        """
        for item in shap_data:
            self.cursor.execute(query, (
                scan_id,
                item.get('feature_impact', ''),
                item.get('shap_value', 0.0),
                item.get('base_value', 0.0)
            ))
        self.conn.commit()
    
    # ---------- ADMIN AUTH ----------
    def get_admin_by_username(self, username: str) -> Optional[Dict]:
        self.ensure_connection()
        query = "SELECT * FROM admin_users WHERE username = %s"
        self.cursor.execute(query, (username,))
        return self.cursor.fetchone()

    # ---------- ADMIN DASHBOARD ----------
    def count_users(self) -> int:
        self.ensure_connection()
        query = "SELECT COUNT(*) AS total FROM users"
        self.cursor.execute(query)
        result = self.cursor.fetchone()
        return result['total'] if result else 0

    def count_scans(self) -> int:
        self.ensure_connection()
        query = "SELECT COUNT(*) AS total FROM email_scans"
        self.cursor.execute(query)
        result = self.cursor.fetchone()
        return result['total'] if result else 0

    def count_phishing_scans(self) -> int:
        self.ensure_connection()
        query = "SELECT COUNT(*) AS total FROM email_scans WHERE prediction_result = 'phishing'"
        self.cursor.execute(query)
        result = self.cursor.fetchone()
        return result['total'] if result else 0

    def count_safe_scans(self) -> int:
        self.ensure_connection()
        query = "SELECT COUNT(*) AS total FROM email_scans WHERE prediction_result = 'safe'"
        self.cursor.execute(query)
        result = self.cursor.fetchone()
        return result['total'] if result else 0

    def get_all_users(self, limit: int = 20, page: int = 1) -> List[Dict]:
        self.ensure_connection()
        offset = (page - 1) * limit
        query = """
            SELECT user_id, user_name, email, created_at, last_login, total_scans, is_active
            FROM users
            ORDER BY user_id DESC
            LIMIT %s OFFSET %s
        """
        self.cursor.execute(query, (limit, offset))
        return self.cursor.fetchall()

    def get_all_scans(self, limit: int = 50, page: int = 1) -> List[Dict]:
        self.ensure_connection()
        offset = (page - 1) * limit
        query = """
            SELECT s.scan_id, s.user_id, u.user_name, u.email, s.prediction_result, 
                   s.confidence_score, s.risk_level, s.scan_timestamp
            FROM email_scans s
            JOIN users u ON s.user_id = u.user_id
            ORDER BY s.scan_timestamp DESC
            LIMIT %s OFFSET %s
        """
        self.cursor.execute(query, (limit, offset))
        return self.cursor.fetchall()

    def get_daily_scans(self, days: int = 7) -> List[Dict]:
        self.ensure_connection()
        query = """
            SELECT DATE(scan_timestamp) AS date, 
                   COUNT(*) AS total,
                   SUM(CASE WHEN prediction_result = 'phishing' THEN 1 ELSE 0 END) AS phishing,
                   SUM(CASE WHEN prediction_result = 'safe' THEN 1 ELSE 0 END) AS safe
            FROM email_scans
            WHERE scan_timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY DATE(scan_timestamp)
            ORDER BY date ASC
        """
        self.cursor.execute(query, (days,))
        return self.cursor.fetchall()
        