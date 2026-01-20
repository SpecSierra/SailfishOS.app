# Sailfishos.app MVP Development Plan

## Overview
A compatibility database for Android apps on SailfishOS, similar to ProtonDB or Wine AppDB. Built with Flask, server-side rendering, Bootstrap CSS, and FontAwesome icons.

---

## Phase 1: Project Setup - COMPLETED

- [x] Create project directory structure
- [x] Create `requirements.txt` with dependencies
- [x] Create Flask app factory in `app/__init__.py`
- [x] Create `config.py` with app configuration
- [x] Create `run.py` entry point

---

## Phase 2: Data Structure - COMPLETED

- [x] Design JSON data schema for apps
- [x] Create initial `data/apps.json` with sample data (10 apps)
- [x] Define app categories list (15 categories)
- [x] Create data loading/saving utility functions in `models.py`

---

## Phase 3: Base Templates & Styling - COMPLETED

- [x] Create `base.html` template with Bootstrap 4.6 & FontAwesome 5
- [x] Create ocean/blue theme CSS
- [x] Responsive design (mobile + desktop)
- [x] Firefox ESR 78 compatibility (using vendor prefixes)

---

## Phase 4: Frontend (Public Pages) - COMPLETED

- [x] Main app list page with two-column layout
- [x] App detail page with full information
- [x] Search functionality (server-side)
- [x] Category filter dropdown
- [x] Status filter (works/partial/no/unknown/native)
- [x] Pagination
- [x] About page

---

## Phase 5: Authentication System - COMPLETED

- [x] User model with argon2 password hashing
- [x] Flask-Login integration
- [x] Login form with WTForms
- [x] CSRF protection with Flask-WTF
- [x] `init_admin.py` script for admin user creation

---

## Phase 6: Dashboard (Admin Panel) - COMPLETED

- [x] Dashboard base template with sidebar
- [x] Dashboard home with stats
- [x] App management (list, add, edit, delete)
- [x] Category management (list, add, edit, delete)
- [x] All forms with proper validation

---

## Phase 7: User Reports (Crowdsourcing) - COMPLETED

- [x] Report form on app detail page (no account required)
- [x] hCaptcha integration for spam prevention
- [x] Reports stored in `data/reports.json`
- [x] Display community reports on app pages
- [x] Report includes: name, status, rating, device, SFOS version, app version, notes
- [x] Reports count auto-updates on apps

---

## Phase 8: Initial Data Population

- [ ] Research and compile list of top 500 Android apps
- [ ] Categorize apps properly
- [ ] Add known SailfishOS native alternatives
- [ ] Document known Android App Support compatibility
- [ ] Create seed data script

---

## Phase 9: Testing & Polish

- [ ] Test all routes and forms
- [ ] Test on mobile devices
- [ ] Test on Firefox ESR 78
- [ ] Validate HTML/CSS
- [ ] Add error handling (404, 500 pages)
- [ ] Performance optimization

---

## Phase 10: Deployment Preparation

- [ ] Create production config
- [ ] Add environment variable support
- [ ] Create deployment documentation
- [ ] Set up proper secret key management

---

## How to Run

```bash
cd /root/sailfishos.app
source venv/bin/activate
python run.py
```

Visit `http://localhost:5000`

**Admin Login**: `/dashboard/login`
- Username: `admin`
- Password: `admin123`

---

## hCaptcha Configuration

For production, set these environment variables:
```bash
export HCAPTCHA_SITE_KEY="your-site-key"
export HCAPTCHA_SECRET_KEY="your-secret-key"
```

Get keys from: https://www.hcaptcha.com/

The app uses test keys by default for development.

---

## Technical Notes

### Browser Compatibility (Firefox ESR 78)
- Using Bootstrap 4.6 (not 5.x) for compatibility
- CSS uses vendor prefixes (-webkit-, -ms-)
- Avoiding modern CSS features (gap, aspect-ratio, clamp)

### Color Theme Reference
```css
:root {
  --primary: #1a5f7a;      /* Deep ocean */
  --secondary: #57c5b6;    /* Sea foam */
  --accent: #159895;       /* Teal */
  --light: #e8f6f3;        /* Light sea */
  --dark: #0a2647;         /* Deep sea */
}
```

### JSON Data Files
- `data/apps.json` - App compatibility data
- `data/users.json` - Admin users
- `data/categories.json` - App categories
- `data/reports.json` - Community reports
