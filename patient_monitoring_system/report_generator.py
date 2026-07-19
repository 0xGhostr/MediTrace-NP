"""
Report generation for daily access monitoring.
Privacy: no full patient content - only record IDs, categories, sensitivity.
"""
import csv
import os
from datetime import datetime

from config import Config
from database import get_db


def _ensure_reports_dir():
    os.makedirs(Config.REPORTS_DIR, exist_ok=True)


def generate_daily_report(report_date=None, generated_by=None):
    """Generate daily CSV access report."""
    _ensure_reports_dir()
    if report_date is None:
        report_date = datetime.utcnow().strftime('%Y-%m-%d')
    if isinstance(report_date, datetime):
        report_date = report_date.strftime('%Y-%m-%d')

    date_prefix = report_date
    conn = get_db()

    total_accesses = conn.execute(
        "SELECT COUNT(*) as cnt FROM access_events WHERE timestamp LIKE ?",
        (f'{date_prefix}%',)
    ).fetchone()['cnt']

    active_users = conn.execute('''
        SELECT COUNT(DISTINCT user_id) as cnt FROM access_events
        WHERE timestamp LIKE ?
    ''', (f'{date_prefix}%',)).fetchone()['cnt']

    total_alerts = conn.execute(
        "SELECT COUNT(*) as cnt FROM alerts WHERE created_at LIKE ?",
        (f'{date_prefix}%',)
    ).fetchone()['cnt']

    risk_summary = {}
    for level in Config.RISK_LEVELS:
        risk_summary[level] = conn.execute(
            "SELECT COUNT(*) as cnt FROM access_events WHERE final_risk_level = ? AND timestamp LIKE ?",
            (level, f'{date_prefix}%')
        ).fetchone()['cnt']

    user_summary = conn.execute('''
        SELECT ae.user_id, ae.username, ae.staff_id, ae.role, ae.department,
               ae.computer_name,
               COUNT(*) as records_accessed,
               GROUP_CONCAT(DISTINCT ae.record_id) as record_ids,
               GROUP_CONCAT(DISTINCT ae.record_category) as categories,
               GROUP_CONCAT(DISTINCT ae.sensitivity_level) as sensitivities,
               GROUP_CONCAT(DISTINCT ae.final_risk_level) as risk_levels,
               ROUND(AVG(ae.rule_score), 1) as avg_rule_score,
               ROUND(AVG(ae.anomaly_score), 1) as avg_anomaly_score,
               ROUND(AVG(ae.hybrid_score), 1) as avg_hybrid_score,
               SUM(ae.alert_created) as alerts_generated
        FROM access_events ae
        WHERE ae.timestamp LIKE ?
        GROUP BY ae.user_id
    ''', (f'{date_prefix}%',)).fetchall()

    usb_total = conn.execute(
        "SELECT COUNT(*) as cnt FROM usb_events WHERE timestamp LIKE ?",
        (f'{date_prefix}%',),
    ).fetchone()['cnt']
    usb_unknown = conn.execute(
        """
        SELECT COUNT(*) as cnt FROM usb_events
        WHERE timestamp LIKE ? AND event_type = 'inserted' AND is_whitelisted = 0
        """,
        (f'{date_prefix}%',),
    ).fetchone()['cnt']
    usb_whitelisted = conn.execute(
        """
        SELECT COUNT(*) as cnt FROM usb_events
        WHERE timestamp LIKE ? AND event_type = 'whitelisted_insert'
        """,
        (f'{date_prefix}%',),
    ).fetchone()['cnt']
    usb_critical = conn.execute(
        """
        SELECT COUNT(*) as cnt FROM usb_events
        WHERE timestamp LIKE ? AND risk_level = 'Critical'
        """,
        (f'{date_prefix}%',),
    ).fetchone()['cnt']
    usb_user_summary = conn.execute('''
        SELECT username, staff_id, computer_name,
               GROUP_CONCAT(DISTINCT usb_serial) as usb_serials,
               COUNT(*) as event_count
        FROM usb_events
        WHERE timestamp LIKE ?
        GROUP BY user_id, computer_name
    ''', (f'{date_prefix}%',)).fetchall()

    conn.close()

    filename = f'{date_prefix}_daily_report.csv'
    filepath = os.path.join(Config.REPORTS_DIR, filename)

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Daily Patient Record Access Report'])
        writer.writerow(['Date', report_date])
        writer.writerow(['Generated At', datetime.utcnow().isoformat()])
        writer.writerow([])
        writer.writerow(['Summary Statistics'])
        writer.writerow(['Total Patient Record Accesses', total_accesses])
        writer.writerow(['Total Active Users', active_users])
        writer.writerow(['Total Alerts', total_alerts])
        writer.writerow(['Critical Alerts', risk_summary.get('Critical', 0)])
        writer.writerow(['High Alerts', risk_summary.get('High', 0)])
        writer.writerow(['Medium Alerts', risk_summary.get('Medium', 0)])
        writer.writerow(['Normal Events', risk_summary.get('Normal', 0)])
        writer.writerow([])
        writer.writerow([
            'Staff ID', 'Username', 'Role', 'Department', 'Device',
            'Records Accessed', 'Record IDs', 'Categories', 'Sensitivity Levels',
            'Risk Levels', 'Average Rule Score', 'Average Behavioural Anomaly Score',
            'Average Hybrid Score', 'Alerts Generated', 'Admin Review Status'
        ])
        for row in user_summary:
            writer.writerow([
                row['staff_id'], row['username'], row['role'], row['department'],
                row['computer_name'] or 'N/A',
                row['records_accessed'],
                row['record_ids'] or '',
                row['categories'] or '',
                row['sensitivities'] or '',
                row['risk_levels'] or '',
                row['avg_rule_score'] if row['avg_rule_score'] is not None else 'Legacy/unavailable',
                row['avg_anomaly_score'] if row['avg_anomaly_score'] is not None else 'Legacy/unavailable',
                row['avg_hybrid_score'] if row['avg_hybrid_score'] is not None else 'Legacy/unavailable',
                row['alerts_generated'],
                'Pending Review',
            ])
        writer.writerow([])
        writer.writerow(['USB Monitoring Summary'])
        writer.writerow(['Total USB Events', usb_total])
        writer.writerow(['Unknown USB Insertions', usb_unknown])
        writer.writerow(['Whitelisted USB Insertions', usb_whitelisted])
        writer.writerow(['USB Critical Alerts', usb_critical])
        writer.writerow([])
        writer.writerow(['USB Users Involved (no patient details)'])
        writer.writerow(['Username', 'Staff ID', 'PC/Device', 'USB Serial(s)', 'Event Count'])
        for row in usb_user_summary:
            writer.writerow([
                row['username'], row['staff_id'], row['computer_name'] or 'N/A',
                row['usb_serials'] or '', row['event_count'],
            ])

    # Save report metadata
    conn = get_db()
    now = datetime.utcnow().isoformat()
    conn.execute('''
        INSERT INTO reports (report_type, report_date, generated_by, generated_at, file_path, format)
        VALUES (?, ?, ?, ?, ?, 'csv')
    ''', ('daily', report_date, generated_by, now, filepath))
    conn.commit()
    conn.close()

    return filepath


def generate_alert_report(generated_by=None):
    """Generate CSV report of all alerts."""
    _ensure_reports_dir()
    conn = get_db()
    alerts = conn.execute('SELECT * FROM alerts ORDER BY created_at DESC').fetchall()
    conn.close()

    filename = f'alerts_report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
    filepath = os.path.join(Config.REPORTS_DIR, filename)

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Alert ID', 'Event ID', 'Username', 'Role', 'Department',
            'Record ID', 'Severity', 'Reason', 'Triggered Rules', 'Rule Score',
            'Behavioural Anomaly Score', 'Anomaly Method', 'Hybrid Score',
            'Baseline Source', 'Model Version', 'Model Confidence',
            'Minimum Risk Override', 'Human Review Required', 'Explainability JSON',
            'Status', 'Created At', 'Resolved At', 'Notes'
        ])
        for a in alerts:
            writer.writerow([
                a['id'], a['event_id'], a['username'], a['role'], a['department'],
                a['record_id'], a['severity'], a['reason'], a['triggered_rules'],
                a['rule_score'], a['anomaly_score'], a['anomaly_method'],
                a['hybrid_score'], a['baseline_source'], a['model_version'],
                a['model_confidence'], a['minimum_risk_override'],
                a['human_review_required'], a['explanation_json'],
                a['status'], a['created_at'], a['resolved_at'], a['notes']
            ])

    conn = get_db()
    now = datetime.utcnow().isoformat()
    conn.execute('''
        INSERT INTO reports (report_type, report_date, generated_by, generated_at, file_path, format)
        VALUES (?, ?, ?, ?, ?, 'csv')
    ''', ('alerts', datetime.utcnow().strftime('%Y-%m-%d'), generated_by, now, filepath))
    conn.commit()
    conn.close()

    return filepath


def generate_user_activity_report(generated_by=None):
    """Generate CSV user activity summary."""
    _ensure_reports_dir()
    conn = get_db()
    users = conn.execute('''
        SELECT u.staff_id, u.username, u.role, u.department, u.approval_status,
               COUNT(ae.id) as total_accesses,
               SUM(ae.alert_created) as total_alerts
        FROM users u
        LEFT JOIN access_events ae ON u.id = ae.user_id
        GROUP BY u.id
        ORDER BY total_accesses DESC
    ''').fetchall()
    conn.close()

    filename = f'user_activity_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
    filepath = os.path.join(Config.REPORTS_DIR, filename)

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Staff ID', 'Username', 'Role', 'Department', 'Approval Status',
            'Total Accesses', 'Alerts Generated'
        ])
        for u in users:
            writer.writerow([
                u['staff_id'], u['username'], u['role'], u['department'],
                u['approval_status'], u['total_accesses'], u['total_alerts'] or 0
            ])

    conn = get_db()
    now = datetime.utcnow().isoformat()
    conn.execute('''
        INSERT INTO reports (report_type, report_date, generated_by, generated_at, file_path, format)
        VALUES (?, ?, ?, ?, ?, 'csv')
    ''', ('user_activity', datetime.utcnow().strftime('%Y-%m-%d'), generated_by, now, filepath))
    conn.commit()
    conn.close()

    return filepath


def get_report_history():
    conn = get_db()
    reports = conn.execute('SELECT * FROM reports ORDER BY generated_at DESC LIMIT 50').fetchall()
    conn.close()
    return [dict(r) for r in reports]


def get_report_by_id(report_id):
    conn = get_db()
    report = conn.execute('SELECT * FROM reports WHERE id = ?', (report_id,)).fetchone()
    conn.close()
    return dict(report) if report else None


def read_report_as_table(file_path, max_rows=400):
    """Read CSV report into list of rows for in-app viewing."""
    if not os.path.exists(file_path):
        return []
    rows = []
    with open(file_path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            if i >= max_rows:
                rows.append(['...', '(truncated)'])
                break
            rows.append(row)
    return rows
