/**
 * api.js — Shared API configuration
 * Har HTML file mein <script src="api.js"></script> add karo
 */

const API = {
    BASE_URL: 'http://localhost:8000',

    getHeaders(withAuth = false) {
        const headers = { 'Content-Type': 'application/json' };
        if (withAuth) {
            const user = JSON.parse(localStorage.getItem('user') || '{}');
            if (user.access_token) {
                headers['Authorization'] = `Bearer ${user.access_token}`;
            }
        }
        return headers;
    },

    getCurrentUser() {
        return JSON.parse(localStorage.getItem('user') || 'null');
    },

    isLoggedIn() {
        const user = this.getCurrentUser();
        return user !== null && user.user_id && user.access_token;
    },

    logout() {
        localStorage.removeItem('user');
        localStorage.removeItem('isLoggedIn');
        window.location.href = 'user_login.html';
    },

    // Health check
    async health() {
        const r = await fetch(`${this.BASE_URL}/api/health`);
        return r.json();
    },

    // Auth
    async login(email, password) {
        const r = await fetch(`${this.BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({ email, password })
        });
        return r.json();
    },

    async register(username, email, password) {
        const r = await fetch(`${this.BASE_URL}/api/auth/register`, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify({ username, email, password })
        });
        return r.json();
    },

    // User
    async getMe() {
        const r = await fetch(`${this.BASE_URL}/api/users/me`, {
            headers: this.getHeaders(true)
        });
        return r.json();
    },

    // Scans
    async analyzeEmail(emailText, userId = null) {
        const body = { email_text: emailText };
        if (userId) body.user_id = userId;
        const r = await fetch(`${this.BASE_URL}/api/analyze`, {
            method: 'POST',
            headers: this.getHeaders(true),
            body: JSON.stringify(body)
        });
        return r.json();
    },

    async getUserScans(userId, limit = 50, page = 1) {
        const r = await fetch(
            `${this.BASE_URL}/api/user/${userId}/scans?limit=${limit}&page=${page}`,
            { headers: this.getHeaders(true) }
        );
        return r.json();
    },

    async getUserStats(userId) {
        const r = await fetch(`${this.BASE_URL}/api/user/${userId}/stats`, {
            headers: this.getHeaders(true)
        });
        return r.json();
    },

    async deleteScan(userId, scanId) {
        const r = await fetch(`${this.BASE_URL}/api/user/${userId}/scan/${scanId}`, {
            method: 'DELETE',
            headers: this.getHeaders(true)
        });
        return r.json();
    },

    // Patterns
    async getPatterns() {
        const r = await fetch(`${this.BASE_URL}/api/patterns`);
        return r.json();
    },

    // Model info
    async getModelInfo() {
        const r = await fetch(`${this.BASE_URL}/api/model/info`);
        return r.json();
    }
};

// =====================================================
// GLOBAL AVATAR LOADER
// Automatically har page pe sidebar avatar apply karta hai
// api.js already sab pages mein include hai — isliye yahan
// likhne se koi alag changes nahi karni padtein
// =====================================================
(function () {
    function applyAvatar() {
        try {
            const user = JSON.parse(localStorage.getItem('user') || 'null');
            
            // Agar user login nahi hai toh default avatar set karein
            if (!user || !user.user_id) {
                document.querySelectorAll('.profile-img, #sidebarAvatar, .avatar, .user-avatar').forEach(img => {
                    img.src = 'https://ui-avatars.com/api/?name=User&background=2ab5c0&color=fff&size=100';
                });
                return;
            }

            // User ka name lein (username ya user_name)
            const name = user.username || user.user_name || 'User';
            
            // Custom avatar check karein (agar user ne upload kiya hai)
            const customAvatar = localStorage.getItem(`avatar_${user.user_id}`);
            
            // Agar custom avatar hai toh use karein, nahi toh UI Avatars se generate karein
            const avatarUrl = customAvatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=2ab5c0&color=fff&size=100&bold=true`;

            // Sab images mein avatar set karein
            document.querySelectorAll('.profile-img, #sidebarAvatar, .avatar, .user-avatar').forEach(img => {
                img.src = avatarUrl;
            });
        } catch (e) {
            // Fallback: agar kuch fail ho toh default avatar
            document.querySelectorAll('.profile-img, #sidebarAvatar, .avatar, .user-avatar').forEach(img => {
                img.src = 'https://ui-avatars.com/api/?name=User&background=2ab5c0&color=fff&size=100';
            });
        }
    }

    // DOM ready hone pe chalao
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', applyAvatar);
    } else {
        applyAvatar();
    }

    // Agar user baad mein login kare ya avatar badlay tab bhi update ho
    window.addEventListener('storage', function (e) {
        if (e.key && (e.key.startsWith('avatar_') || e.key === 'user')) {
            applyAvatar();
        }
    });
})();