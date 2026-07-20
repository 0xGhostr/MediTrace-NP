# MediTrace-Np — Patient Record Access & Security Monitoring

## Project Title

**Design, Development and Evaluation of a Lightweight Behavioural Anomaly Detection System for Patient Record Access Monitoring in Healthcare Institutions of Kathmandu Valley, Nepal, While Maintaining Patient Privacy**

## Description

Academic thesis prototype for monitoring simulated patient record access in healthcare institutions. The system logs who accessed which record, when, from which department/device, and whether behaviour was suspicious using:

- **Rule-based detection** (7 rules)
- **Controlled Isolation Forest** behavioural anomaly scoring from historical access metadata
- **Explainable numeric hybrid scoring** with rule contributions and minimum-risk overrides
- **Human admin review** (no automatic punishment)

**This is NOT a commercial hospital product.** All patient data is simulated.

## Features

- Staff self-registration with admin approval workflow
- Role-based access control (Admin, Doctor, Nurse, Receptionist, Billing, Laboratory)
- Simulated patient records (fake codes PR-001, etc.)
- Full access event logging
- Rule engine + confidence-aware behavioural anomaly and hybrid scoring
- Admin dashboard with Chart.js visualizations
- Alert management with resolve/notes
- Daily CSV reports (scheduled + manual)
- Privacy-focused reporting (no full patient content in exports)
- **USB Monitoring** (admin-only, simulation mode) — whitelist management, leakage detection, dashboard & daily report stats
- **Security Management** — login history, 3-strike / 2-minute account lockout, admin unlock
- **Secure Account Recovery** — generic public intake, duplicate/rate protection, administrator assignment, recorded identity verification, and audited resolution
- **Administrative Account Editing** — permission-scoped username updates and temporary password resets with session invalidation
- Forced temporary-password rotation before access to authenticated system functions
- Complete English/Nepali interface with per-user language persistence and English fallback

## Technologies

- Python Flask, SQLite, Flask-Login, Flask-WTF
- HTML, CSS, Bootstrap 5, JavaScript, Chart.js
- scikit-learn Isolation Forest, NumPy
- APScheduler for daily reports
- Werkzeug password hashing

## Setup

```bash
cd patient_monitoring_system
python -m venv venv

# Windows
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Seed Database

```bash
python seed_data.py --fresh
```

This creates:
- Default admin account
- Sample staff, pending, rejected, suspended users
- 35 simulated patient records
- Normal and suspicious access events + alerts
- Trained behavioural model with metadata (`ml_model/model.pkl`)

**Output:**
- Super Admin only: `superadmin` / `Super@123` (create Admin users from **Manage Admins** after login)

## Run Application

```bash
python app.py
```

Open: **http://127.0.0.1:5000**

## Default Logins

| Username | Password | Role | Status |
|----------|----------|------|--------|
| superadmin | Super@123 | Super Admin | Approved (full access; create Admins manually) |
| doctor1 | Staff@123 | Doctor | Approved |
| nurse1 | Staff@123 | Nurse | Approved |
| reception1 | Staff@123 | Receptionist | Approved |
| billing1 | Staff@123 | Billing Staff | Approved |
| lab1 | Staff@123 | Laboratory Staff | Approved |
| pending1 | Staff@123 | Nurse | Pending (login blocked) |
| rejected1 | Staff@123 | Doctor | Rejected |
| suspended1 | Staff@123 | Billing | Suspended |

## Main Demo Flow

1. Register new staff at `/register`
2. Login as `admin` / `Admin@123`
3. Go to **Pending Users** → approve registration
4. Staff logs in → views patient records
5. Open allowed record (e.g. PR-001 as doctor) → Normal access logged
6. Open restricted record (e.g. PR-009 HIV as reception1) → Alert created
7. Admin views **Alerts** → add notes → resolve
8. Admin → **Reports** → **Generate Today's Report** → download CSV

## Test Scenarios

| # | Test | How |
|---|------|-----|
| 1 | Pending login blocked | Login as `pending1` |
| 2 | Approve then login | Approve pending user, login |
| 3 | Normal doctor access | Login `doctor1`, view PR-001 during hours |
| 4 | Receptionist confidential | Login `reception1`, view PR-013 |
| 5 | Billing psychiatric | Login `billing1`, view PR-011 |
| 6 | After-hours sensitive | View PR-009 as reception1 (or check seeded events) |
| 7 | Bulk access | Open 10+ records quickly as any staff |
| 8 | Repeated sensitive | Open 3+ High/Critical records in 30 min |
| 9 | Blocked permanent-delete attempt | Submit a forged record-delete request and verify the 403 response, retained row, audit event, and security evaluation |
| 10 | Daily report | Admin → Reports → Generate Today's Report |
| 11 | Account recovery | Login page → Account Recovery Request → authorized admin review |
| 12 | Temporary password | Admin resets password → user signs in → required password change |

Run the isolated account-recovery security workflow without modifying the live database:

```bash
python verify_account_recovery.py
```

## Privacy Note

- **No real patient data** — all records use fake codes (PR-001, etc.)
- Reports contain record IDs, categories, and sensitivity only
- Alerts require human administrator review
- Behavioural anomaly scores are relative anomaly percentiles, not probabilities of malicious intent
- Cold-start events use role, department or global baselines with reduced anomaly weight
- Missing models fail safely to transparent statistical or rules-only assessment
- Patient diagnosis, demographics, vitals, medication and clinical text are excluded from scoring

## Academic Scope

Prototype for BSc (Hons) Ethical Hacking and Cybersecurity thesis evaluation. Not intended for production deployment in hospitals without full security audit, legal review, and compliance assessment.

## Project Structure

```
patient_monitoring_system/
├── app.py              # Main Flask application
├── config.py           # Configuration
├── database.py         # SQLite schema
├── models.py           # Data helpers
├── auth.py             # Authentication
├── rule_engine.py      # Rule-based detection
├── ai_engine.py        # Isolation Forest ML
├── risk_engine.py      # Hybrid risk scoring
├── access_service.py   # Access pipeline
├── account_recovery.py # Recovery workflow and secure account editing
├── report_generator.py # CSV reports
├── seed_data.py        # Database seeding
├── instance/database.db
├── ml_model/model.pkl
├── reports/
├── static/
└── templates/
```

## Author

BSc Thesis Prototype — Kathmandu Valley Healthcare Simulation

## English–Nepali Interface

MediTrace-NP supports exactly two interface locales: English (`en`) and Nepali
(`ne`). The implementation is dependency-free because Flask-Babel/Babel are not
part of this project environment. `i18n.py` provides request-locale resolution,
English fallback, safe display-value translation, WTForms localization, and
rendered fixed-text localization. Nepali messages are maintained in the UTF-8
catalogue `translations/ne.json`.

Locale selection order is:

1. an explicit, CSRF-protected language change;
2. the authenticated user's `users.preferred_language` value;
3. the current session;
4. the harmless `meditrace_language` cookie;
5. the browser `Accept-Language` header;
6. English fallback.

The `/language` endpoint accepts POST requests only, permits only `en` and `ne`,
and redirects only to application-local paths. Existing users and new users
default to English. Authenticated choices are persisted; logout preserves the
non-sensitive language preference. Canonical database values, rule identifiers,
model versions, usernames, names, clinical text, audit evidence, and CSV exports
remain unchanged.

### Adding or changing UI text

1. Write the stable English source text in Python or a template.
2. Add the exact English source key and its Nepali translation to
   `translations/ne.json`. Do not create a second ad-hoc translation dictionary.
3. Use `_('Source text')` for Python/template text containing dynamic values, for
   example `_('Welcome, {name}', name=user.full_name)`.
4. Use `tr_display(value)` only for canonical user-facing enums such as roles,
   departments, status, sensitivity, and risk. Never translate the submitted or
   stored `value` attribute.
5. Add `data-no-translate` around user-authored text, names, raw evidence, rule
   codes, or model metadata that must be displayed verbatim.
6. For JavaScript-visible text, add the source key to `js_messages()` in
   `i18n.py`, then read it from `window.MediTraceI18n.messages`.
7. Run the bilingual regression checks and the existing workflow checks:

```bash
python audit_i18n.py
python test_i18n.py
python test_app.py
python verify_account_recovery.py
python test_usb_security.py
```

Missing Nepali keys intentionally render the English source text so that a new
or incomplete string never produces a blank or broken interface.
