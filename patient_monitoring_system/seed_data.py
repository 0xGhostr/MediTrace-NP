"""
Seed database with simulated users, patient records, and access events.
Run: python seed_data.py [--fresh]
"""
import argparse
import json
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from werkzeug.security import generate_password_hash

from config import Config
from database import init_db, clear_all_data, get_db
import ai_engine
from access_service import process_access
from auth import User
from models import (
    create_patient_record, create_user, get_user_by_username, get_patient_record,
    insert_access_event, insert_alert,
)


def seed_users():
    """Create admin, staff, pending, rejected, suspended users."""
    conn = get_db()
    now = datetime.utcnow().isoformat()
    super_pw = generate_password_hash('Super@123')
    staff_password = generate_password_hash('Staff@123')

    users_data = [
        # Built-in Super Admin only — create Admin accounts from Manage Admins after login
        ('Super Administrator', 'SAD001', 'superadmin@hospital.demo', 'superadmin', super_pw,
         'Super Admin', 'Administration', '08:00', '17:00', 'approved', 1, None, None),
        # Approved staff
        ('Dr. Suman Sharma', 'DOC001', 'suman@hospital.demo', 'doctor1', staff_password,
         'Doctor', 'General Medicine', '08:00', '17:00', 'approved', 1, None, None),
        ('Nurse Anjali Thapa', 'NUR001', 'anjali@hospital.demo', 'nurse1', staff_password,
         'Nurse', 'General Medicine', '07:00', '15:00', 'approved', 1, None, None),
        ('Receptionist Ramesh Karki', 'REC001', 'ramesh@hospital.demo', 'reception1', staff_password,
         'Receptionist', 'Reception', '08:00', '16:00', 'approved', 1, None, None),
        ('Billing Staff Sita Gurung', 'BIL001', 'sita@hospital.demo', 'billing1', staff_password,
         'Billing Staff', 'Billing', '09:00', '17:00', 'approved', 1, None, None),
        ('Lab Tech Prakash Rai', 'LAB001', 'prakash@hospital.demo', 'lab1', staff_password,
         'Laboratory Staff', 'Laboratory', '08:00', '16:00', 'approved', 1, None, None),
        # Pending users (login blocked)
        ('Pending User One', 'PEN001', 'pending1@hospital.demo', 'pending1', staff_password,
         'Nurse', 'General Medicine', '08:00', '17:00', 'pending', 1, None, None),
        ('Pending User Two', 'PEN002', 'pending2@hospital.demo', 'pending2', staff_password,
         'Receptionist', 'Reception', '08:00', '17:00', 'pending', 1, None, None),
        # Rejected
        ('Rejected User', 'REJ001', 'rejected@hospital.demo', 'rejected1', staff_password,
         'Doctor', 'General Medicine', '08:00', '17:00', 'rejected', 0, None, 'Incomplete documentation'),
        # Suspended
        ('Suspended User', 'SUS001', 'suspended@hospital.demo', 'suspended1', staff_password,
         'Billing Staff', 'Billing', '09:00', '17:00', 'suspended', 0, None, None),
    ]

    for i, u in enumerate(users_data):
        pwd = u[4]
        conn.execute('''
            INSERT INTO users (full_name, staff_id, email, username, password_hash,
                role, department, work_start, work_end, approval_status, is_active,
                rejection_reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (u[0], u[1], u[2], u[3], pwd, u[5], u[6], u[7], u[8], u[9], u[10], u[12], now))

    conn.commit()
    conn.close()


def seed_patient_records():
    """Create 35+ fake patient records."""
    records = [
        ('PR-001', 'Annual Checkup Summary', 'General Medical', 'General Medicine', 'Low',
         'Simulated: routine annual examination notes. No real patient data.'),
        ('PR-002', 'Ward Admission Notes', 'General Medical', 'General Medicine', 'Medium',
         'Simulated: inpatient ward admission documentation.'),
        ('PR-003', 'Emergency Triage Report', 'Emergency', 'Emergency', 'High',
         'Simulated: emergency department triage assessment.'),
        ('PR-004', 'Emergency Surgery Notes', 'Emergency', 'Emergency', 'Critical',
         'Simulated: emergency surgical procedure documentation.'),
        ('PR-005', 'Invoice Summary Q1', 'Billing', 'Billing', 'Low',
         'Simulated: quarterly billing invoice summary.'),
        ('PR-006', 'Insurance Claim Form', 'Billing', 'Billing', 'Medium',
         'Simulated: health insurance claim processing record.'),
        ('PR-007', 'Blood Test Results', 'Laboratory', 'Laboratory', 'Medium',
         'Simulated: complete blood count laboratory results.'),
        ('PR-008', 'Urinalysis Report', 'Laboratory', 'Laboratory', 'Low',
         'Simulated: standard urinalysis test results.'),
        ('PR-009', 'HIV Screening Result', 'HIV-related', 'Infectious Disease', 'Critical',
         'Simulated: confidential HIV screening test result. Synthetic data only.'),
        ('PR-010', 'HIV Treatment Plan', 'HIV-related', 'Infectious Disease', 'Critical',
         'Simulated: HIV treatment and care plan. Highly sensitive synthetic record.'),
        ('PR-011', 'Psychiatric Evaluation', 'Psychiatric', 'Psychiatry', 'High',
         'Simulated: initial psychiatric assessment notes.'),
        ('PR-012', 'Mental Health Care Plan', 'Psychiatric', 'Psychiatry', 'High',
         'Simulated: ongoing mental health treatment plan.'),
        ('PR-013', 'Confidential Diagnosis', 'Confidential', 'General Medicine', 'Critical',
         'Simulated: confidential medical diagnosis record.'),
        ('PR-014', 'Physician Confidential Notes', 'Confidential', 'General Medicine', 'High',
         'Simulated: physician-only confidential clinical notes.'),
        ('PR-015', 'Outpatient Registration', 'General Medical', 'Reception', 'Low',
         'Simulated: outpatient registration and demographic data.'),
        ('PR-016', 'Discharge Summary', 'General Medical', 'General Medicine', 'Medium',
         'Simulated: patient discharge summary documentation.'),
        ('PR-017', 'Medication Prescription', 'General Medical', 'General Medicine', 'Medium',
         'Simulated: prescribed medication list and dosage instructions.'),
        ('PR-018', 'Nursing Care Plan', 'General Medical', 'General Medicine', 'Medium',
         'Simulated: nursing care plan and vital signs monitoring.'),
        ('PR-019', 'Pathology Report', 'Laboratory', 'Laboratory', 'High',
         'Simulated: tissue pathology examination report.'),
        ('PR-020', 'Microbiology Culture', 'Laboratory', 'Laboratory', 'High',
         'Simulated: bacterial culture and sensitivity results.'),
        ('PR-021', 'Payment History', 'Billing', 'Billing', 'Low',
         'Simulated: patient payment transaction history.'),
        ('PR-022', 'Outstanding Balance Notice', 'Billing', 'Billing', 'Medium',
         'Simulated: outstanding balance notification letter.'),
        ('PR-023', 'Trauma Assessment', 'Emergency', 'Emergency', 'High',
         'Simulated: trauma patient initial assessment.'),
        ('PR-024', 'ICU Monitoring Log', 'Emergency', 'Emergency', 'Critical',
         'Simulated: intensive care unit monitoring records.'),
        ('PR-025', 'Therapy Session Notes', 'Psychiatric', 'Psychiatry', 'High',
         'Simulated: psychotherapy session documentation.'),
        ('PR-026', 'Substance Abuse Assessment', 'Psychiatric', 'Psychiatry', 'Critical',
         'Simulated: substance abuse evaluation record.'),
        ('PR-027', 'Research Confidential Data', 'Confidential', 'Administration', 'Critical',
         'Simulated: confidential research participant data.'),
        ('PR-028', 'Immunization Record', 'General Medical', 'General Medicine', 'Low',
         'Simulated: vaccination history and schedule.'),
        ('PR-029', 'Allergy Documentation', 'General Medical', 'General Medicine', 'Medium',
         'Simulated: known allergies and adverse reactions.'),
        ('PR-030', 'Radiology Report', 'Laboratory', 'Laboratory', 'Medium',
         'Simulated: X-ray imaging interpretation report.'),
        ('PR-031', 'Hepatitis Panel', 'Laboratory', 'Laboratory', 'High',
         'Simulated: hepatitis screening panel results.'),
        ('PR-032', 'Surgical Consent Form', 'Confidential', 'General Medicine', 'High',
         'Simulated: informed surgical consent documentation.'),
        ('PR-033', 'Advance Directive', 'Confidential', 'General Medicine', 'Critical',
         'Simulated: patient advance healthcare directive.'),
        ('PR-034', 'Referral Letter', 'General Medical', 'General Medicine', 'Low',
         'Simulated: specialist referral correspondence.'),
        ('PR-035', 'Follow-up Appointment', 'General Medical', 'Reception', 'Low',
         'Simulated: scheduled follow-up appointment record.'),
    ]

    ward_by_department = {
        'General Medicine': 'General Ward',
        'Emergency': 'Emergency Unit',
        'Billing': 'Administrative Services',
        'Laboratory': 'Diagnostic Laboratory',
        'Psychiatry': 'Behavioural Health Unit',
        'Infectious Disease': 'Specialist Care Unit',
        'Reception': 'Outpatient Services',
        'Administration': 'Research Administration',
    }
    condition_by_category = {
        'General Medical': 'General medical review',
        'Emergency': 'Emergency care assessment',
        'Billing': 'Administrative billing record',
        'Laboratory': 'Laboratory investigation',
        'HIV-related': 'Confidential specialist care record',
        'Psychiatric': 'Behavioural health assessment',
        'Confidential': 'Restricted clinical documentation',
    }
    treatment_by_category = {
        'General Medical': 'Routine monitoring',
        'Emergency': 'Emergency observation\nSupportive care simulation',
        'HIV-related': 'Simulated care-plan review',
        'Psychiatric': 'Simulated follow-up plan',
    }
    clinical_categories = {'General Medical', 'Emergency', 'HIV-related', 'Psychiatric', 'Confidential'}
    vital_categories = {'General Medical', 'Emergency'}
    seeded_at = datetime.utcnow()

    for index, record in enumerate(records, start=1):
        code, title, category, department, sensitivity, content = record
        has_clinical_context = category in clinical_categories
        has_vitals = category in vital_categories
        create_patient_record({
            'patient_code': code,
            'record_title': title,
            'record_category': category,
            'department': department,
            'sensitivity_level': sensitivity,
            'content': content,
            'patient_identifier': f'SIM-PT-{10000 + index}',
            'patient_name': f'Simulated Patient {index:03d}',
            'patient_age': 18 + ((index * 7) % 68),
            'patient_gender': ['Female', 'Male', 'Not specified'][index % 3],
            'ward': ward_by_department.get(department),
            'admission_date': (
                (seeded_at - timedelta(days=(index % 21) + 1)).strftime('%Y-%m-%d')
                if has_clinical_context else None
            ),
            'attending_doctor': (
                f'Dr. Simulated Clinician {(index % 6) + 1}'
                if has_clinical_context else None
            ),
            'primary_condition': condition_by_category.get(category),
            'clinical_notes': (
                f'Simulated notes for {title.lower()}. Academic prototype data only.'
                if has_clinical_context else None
            ),
            'medication_or_treatment': treatment_by_category.get(category),
            'relevant_observations': (
                f'Synthetic observation set {index:02d}; review within the simulated workflow.'
                if has_clinical_context else None
            ),
            'heart_rate': 68 + ((index * 5) % 34) if has_vitals else None,
            'blood_pressure': (
                f'{108 + ((index * 3) % 24)}/{68 + ((index * 2) % 14)}'
                if has_vitals else None
            ),
            'temperature': round(36.4 + ((index % 8) * 0.1), 1) if has_vitals else None,
            'oxygen_saturation': 94 + (index % 6) if has_vitals else None,
        })


def seed_access_events_and_alerts():
    """Seed normal and suspicious access events for demo."""
    conn = get_db()

    def get_user(username):
        return conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

    def get_record(code):
        return conn.execute('SELECT * FROM patient_records WHERE patient_code = ?', (code,)).fetchone()

    def add_event(user, record, action, ts, risk, ml, rules, after_h, sensitive, dept_match, alert=0):
        rule_result = json.dumps({
            'severity': risk, 'reason': 'Seeded event', 'triggered_rules': rules
        })
        cursor = conn.execute('''
            INSERT INTO access_events (user_id, username, staff_id, role, department,
                record_id, record_category, sensitivity_level, action_type, timestamp,
                ip_address, computer_name, is_after_hours, is_sensitive, department_match,
                rule_result, ml_score, final_risk_level, alert_created)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user['id'], user['username'], user['staff_id'], user['role'], user['department'],
            record['id'] if record else None,
            record['record_category'] if record else None,
            record['sensitivity_level'] if record else None,
            action, ts, '192.168.1.100', 'SEED-DEVICE', after_h, sensitive, dept_match,
            rule_result, ml, risk, alert
        ))
        return cursor.lastrowid

    now = datetime.utcnow()

    doctor = get_user('doctor1')
    reception = get_user('reception1')
    billing = get_user('billing1')
    nurse = get_user('nurse1')

    # Scenario 3: Doctor normal access during hours
    rec = get_record('PR-001')
    ts = now.replace(hour=10, minute=30).isoformat()
    eid = add_event(doctor, rec, 'view', ts, 'Normal', 15, [], 0, 0, 1, 0)

    # Scenario 4: Receptionist confidential - suspicious
    rec = get_record('PR-013')
    ts = now.replace(hour=11, minute=0).isoformat()
    eid = add_event(reception, rec, 'view', ts, 'High', 72,
                    ['RULE_2_SENSITIVE_RECORD', 'RULE_ROLE_MISMATCH', 'RULE_3_CROSS_DEPARTMENT'], 0, 1, 0, 1)
    conn.execute('''
        INSERT INTO alerts (event_id, user_id, username, role, department, record_id,
            severity, reason, triggered_rules, ml_score, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
    ''', (eid, reception['id'], reception['username'], reception['role'],
          reception['department'], rec['id'], 'High',
          'Receptionist accessed Confidential Critical record outside assigned department.',
          json.dumps(['RULE_2_SENSITIVE_RECORD', 'RULE_ROLE_MISMATCH']), 72, ts))

    # Scenario 5: Billing psychiatric - high
    rec = get_record('PR-011')
    ts = now.replace(hour=14, minute=0).isoformat()
    eid = add_event(billing, rec, 'view', ts, 'High', 68,
                    ['RULE_ROLE_MISMATCH', 'RULE_3_CROSS_DEPARTMENT'], 0, 1, 0, 1)
    conn.execute('''
        INSERT INTO alerts (event_id, user_id, username, role, department, record_id,
            severity, reason, triggered_rules, ml_score, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
    ''', (eid, billing['id'], billing['username'], billing['role'],
          billing['department'], rec['id'], 'High',
          'Billing Staff accessed Psychiatric High record - role category mismatch.',
          json.dumps(['RULE_ROLE_MISMATCH']), 68, ts))

    # Scenario 6: After-hours sensitive - critical
    rec = get_record('PR-009')
    ts = (now - timedelta(days=1)).replace(hour=22, minute=30).isoformat()
    eid = add_event(reception, rec, 'view', ts, 'Critical', 87,
                    ['RULE_1_AFTER_HOURS', 'RULE_2_SENSITIVE_RECORD', 'RULE_3_CROSS_DEPARTMENT',
                     'RULE_7_CRITICAL_COMBO'], 1, 1, 0, 1)
    conn.execute('''
        INSERT INTO alerts (event_id, user_id, username, role, department, record_id,
            severity, reason, triggered_rules, ml_score, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
    ''', (eid, reception['id'], reception['username'], reception['role'],
          reception['department'], rec['id'], 'Critical',
          'Receptionist accessed HIV-related Critical record after working hours and outside assigned department.',
          json.dumps(['RULE_1_AFTER_HOURS', 'RULE_2_SENSITIVE_RECORD', 'RULE_3_CROSS_DEPARTMENT']), 87, ts))

    # Scenario 7: Bulk access
    for i in range(12):
        rec = get_record(f'PR-{i+1:03d}')
        if rec:
            ts = (now - timedelta(minutes=5)).isoformat()
            add_event(nurse, rec, 'view', ts, 'High' if i >= 9 else 'Medium', 55 + i,
                      ['RULE_4_BULK_ACCESS'] if i >= 9 else [], 0, 0, 1, 1 if i >= 9 else 0)

    # Scenario 8: Repeated sensitive
    for code in ['PR-009', 'PR-010', 'PR-013']:
        rec = get_record(code)
        ts = (now - timedelta(minutes=20)).isoformat()
        add_event(doctor, rec, 'view', ts, 'High', 70,
                  ['RULE_5_REPEATED_SENSITIVE'], 0, 1, 0, 1)

    # Scenario 9: Delete attempt
    rec = get_record('PR-002')
    ts = now.replace(hour=15, minute=0).isoformat()
    eid = add_event(billing, rec, 'delete_attempt', ts, 'Critical', 92,
                    ['RULE_6_DELETE_ATTEMPT'], 0, 0, 1, 1)
    conn.execute('''
        INSERT INTO alerts (event_id, user_id, username, role, department, record_id,
            severity, reason, triggered_rules, ml_score, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
    ''', (eid, billing['id'], billing['username'], billing['role'],
          billing['department'], rec['id'], 'Critical',
          'Non-admin user attempted to delete a patient record.',
          json.dumps(['RULE_6_DELETE_ATTEMPT']), 92, ts))

    # More normal events for charts
    for code in ['PR-015', 'PR-016', 'PR-028']:
        rec = get_record(code)
        if rec:
            for day_offset in range(12):
                ts = (now - timedelta(days=day_offset)).replace(hour=11).isoformat()
                add_event(doctor, rec, 'view', ts, 'Normal', 20, [], 0, 0, 1, 0)

    conn.commit()
    conn.close()


def run_live_pipeline_samples():
    """Run access pipeline on a few records for realistic ML integration."""
    doctor = get_user_by_username('doctor1')
    if doctor:
        user = User(doctor)
        rec = get_patient_record(1)
        if rec:
            process_access(user, rec, 'view')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fresh', action='store_true', help='Clear and reseed database')
    args = parser.parse_args()

    print('Initializing database...')
    init_db()

    if args.fresh:
        print('Clearing existing data...')
        clear_all_data()

    print('Seeding users...')
    seed_users()

    print('Seeding patient records...')
    seed_patient_records()

    print('Seeding access events and alerts...')
    seed_access_events_and_alerts()

    # Label seeded demonstration scores before controlled model training.
    init_db()

    print('Training behavioural anomaly model...')
    super_admin = get_user_by_username('superadmin')
    ai_engine.train_and_save_model(
        trained_by=super_admin['id'] if super_admin else None,
    )

    print('Running live pipeline samples...')
    try:
        run_live_pipeline_samples()
    except Exception as e:
        print(f'Pipeline sample skipped: {e}')

    print('')
    print('=' * 60)
    print('Default Super Admin: username=superadmin password=Super@123')
    print('Create Admin accounts from: Manage Admins (after login)')
    print('Staff test accounts password: Staff@123')
    print('  doctor1, nurse1, reception1, billing1, lab1')
    print('Pending (login blocked): pending1, pending2')
    print('Rejected: rejected1 | Suspended: suspended1')
    print('=' * 60)
    print('Run: python app.py')
    print('Open: http://127.0.0.1:5000')


if __name__ == '__main__':
    main()
