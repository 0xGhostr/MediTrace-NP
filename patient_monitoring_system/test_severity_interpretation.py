"""Controlled audit of record sensitivity, event risk, and alert severity."""
from __future__ import annotations

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from config import Config


PROJECT_ROOT = Path(__file__).resolve().parent


def run_checks():
    checks = []
    original_database = Config.DATABASE_PATH
    original_model_path = Config.ML_MODEL_PATH

    with tempfile.TemporaryDirectory(prefix='meditrace-severity-audit-') as temp_dir:
        Config.DATABASE_PATH = str(Path(temp_dir) / 'database.db')
        Config.ML_MODEL_PATH = str(Path(temp_dir) / 'missing-model.pkl')

        import ai_engine
        import risk_engine
        import rule_engine
        from database import get_db, init_db
        from models import create_patient_record, get_patient_record, is_after_hours

        ai_engine._model = None
        ai_engine._load_error = None
        init_db()

        conn = get_db()
        created_at = datetime(2026, 1, 1).isoformat()
        user_id = conn.execute(
            '''
            INSERT INTO users (
                full_name, staff_id, email, username, password_hash, role,
                department, work_start, work_end, approval_status, is_active,
                is_deleted, created_at
            ) VALUES (
                'Severity Test Doctor', 'SEV-001', 'severity@example.invalid',
                'severity_test', 'unused-test-hash', 'Doctor',
                'General Medicine', '08:00', '17:00', 'approved', 1, 0, ?
            )
            ''',
            (created_at,),
        ).lastrowid
        conn.commit()
        user = dict(conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone())
        conn.close()

        record_id = create_patient_record({
            'patient_code': 'SEV-MED-001',
            'record_title': 'Severity audit record',
            'record_category': 'General Medical',
            'department': 'General Medicine',
            'sensitivity_level': 'Medium',
            'content': 'Synthetic test-only content.',
        })
        cross_record_id = create_patient_record({
            'patient_code': 'SEV-MED-002',
            'record_title': 'Cross-department severity audit record',
            'record_category': 'General Medical',
            'department': 'Laboratory',
            'sensitivity_level': 'Medium',
            'content': 'Synthetic test-only content.',
        })
        record = get_patient_record(record_id)
        cross_record = get_patient_record(cross_record_id)

        # Eight prior Monday views establish a high-confidence, same-hour,
        # same-action, same-device user baseline without touching live data.
        event_time = datetime(2026, 7, 20, 6, 15)  # 12:00 Nepal Time
        conn = get_db()
        for weeks_ago in range(8, 0, -1):
            timestamp = event_time - timedelta(days=7 * weeks_ago)
            conn.execute(
                '''
                INSERT INTO access_events (
                    user_id, username, staff_id, role, department, record_id,
                    record_category, sensitivity_level, action_type, timestamp,
                    computer_name, is_after_hours, is_sensitive,
                    department_match, rule_result, ml_score, final_risk_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'Medium', 'view', ?,
                          'SEVERITY-TEST-PC', 0, 0, 1, '{}', 0, 'Normal')
                ''',
                (
                    user['id'], user['username'], user['staff_id'], user['role'],
                    user['department'], record['id'], record['record_category'],
                    timestamp.isoformat(),
                ),
            )
        conn.commit()
        conn.close()

        def assess(name, target_record, action_type, timestamp):
            context = {
                'timestamp': timestamp,
                'after_hours': is_after_hours(user, timestamp),
                'department_match': int(user['department'] == target_record['department']),
                'is_sensitive': False,
                'records_last_10_min': 0,
                'high_critical_last_30_min': 0,
                'records_accessed_today': 0,
                'sensitive_accesses_today': 0,
                'repeated_record_30m': 0,
                'time_since_previous_minutes': 7 * 24 * 60,
                'device_familiarity': 1,
                'computer_name': 'SEVERITY-TEST-PC',
            }
            rules = rule_engine.evaluate_access(user, target_record, action_type, context)
            anomaly = ai_engine.assess_event(user, target_record, action_type, context)
            hybrid = risk_engine.calculate_hybrid(rules, anomaly)
            return {
                'name': name,
                'sensitivity': target_record['sensitivity_level'],
                'rules': rules['triggered_rules'],
                'rule_score': rules['rule_score'],
                'anomaly_score': anomaly['anomaly_score'],
                'anomaly_method': anomaly['anomaly_method'],
                'final_score': hybrid['final_hybrid_score'],
                'final_risk': hybrid['final_risk_level'],
            }

        after_hours_time = datetime(2026, 7, 20, 0, 15)  # 06:00 Nepal Time
        results = {
            'clean': assess('clean view', record, 'view', event_time),
            'export': assess('export', record, 'export', event_time),
            'cross': assess('cross-department view', cross_record, 'view', event_time),
            'after': assess('after-hours view', record, 'view', after_hours_time),
            'combined': assess(
                'after-hours cross-department export', cross_record, 'export', after_hours_time,
            ),
            'delete': assess('non-admin delete attempt', record, 'delete_attempt', event_time),
        }

        assert results['clean'] == {
            'name': 'clean view', 'sensitivity': 'Medium', 'rules': [],
            'rule_score': 0, 'anomaly_score': 0,
            'anomaly_method': 'statistical_baseline', 'final_score': 0,
            'final_risk': 'Normal',
        }
        assert results['export']['rule_score'] == 0
        assert results['export']['anomaly_score'] == 10
        assert results['export']['final_score'] == 4
        assert results['export']['final_risk'] == 'Normal'
        assert results['cross']['rules'] == ['RULE_3_CROSS_DEPARTMENT']
        assert (results['cross']['rule_score'], results['cross']['anomaly_score']) == (20, 20)
        assert (results['cross']['final_score'], results['cross']['final_risk']) == (40, 'Medium')
        assert results['after']['rules'] == ['RULE_1_AFTER_HOURS']
        assert (results['after']['rule_score'], results['after']['anomaly_score']) == (30, 35)
        assert (results['after']['final_score'], results['after']['final_risk']) == (60, 'High')
        assert results['combined']['rules'] == [
            'RULE_1_AFTER_HOURS', 'RULE_3_CROSS_DEPARTMENT', 'RULE_7_COMBINED',
        ]
        assert (results['combined']['rule_score'], results['combined']['anomaly_score']) == (60, 65)
        assert (results['combined']['final_score'], results['combined']['final_risk']) == (62, 'High')
        assert results['delete']['rules'] == ['RULE_6_DELETE_ATTEMPT']
        assert (results['delete']['final_score'], results['delete']['final_risk']) == (80, 'Critical')
        assert all(result['sensitivity'] == 'Medium' for result in results.values())
        checks.append('six controlled Medium-record scoring scenarios with established baseline')

        access_service = (PROJECT_ROOT / 'access_service.py').read_text(encoding='utf-8')
        assert "'sensitivity_level': record['sensitivity_level']" in access_service
        assert "'final_risk_level': final_risk" in access_service
        assert "risk_engine.should_create_alert(final_risk)" in access_service
        assert "'severity': final_risk" in access_service
        checks.append('record sensitivity, final event risk, and alert severity remain separate')

        dashboard = (PROJECT_ROOT / 'templates' / 'admin_dashboard.html').read_text(encoding='utf-8')
        alerts = (PROJECT_ROOT / 'templates' / 'alerts.html').read_text(encoding='utf-8')
        dashboard_js = (PROJECT_ROOT / 'static' / 'js' / 'dashboard.js').read_text(encoding='utf-8')
        assert 'Alerts Today by Final Severity' in dashboard
        assert "Today's Access Events by Final Risk Level" in dashboard
        assert 'Alerts by Severity — Today' in dashboard
        assert 'Final Access Risk' in alerts and 'Alert Severity' in alerts
        assert 'Record Sensitivity' in alerts and 'Record Category' in alerts
        assert 'generateLabels: alertSeverityLegendLabels' in dashboard_js
        assert 'Chart.defaults.plugins.legend.labels.generateLabels' not in dashboard_js
        assert 'text: `${label}: ${count}`' in dashboard_js
        assert 'undefined' not in dashboard_js
        checks.append('clarified dashboard/detail wording and slice-safe chart legend')

    Config.DATABASE_PATH = original_database
    Config.ML_MODEL_PATH = original_model_path
    return checks


if __name__ == '__main__':
    completed = run_checks()
    print(f'Severity interpretation checks passed: {len(completed)}/{len(completed)}')
    for check in completed:
        print(f'  PASS - {check}')
