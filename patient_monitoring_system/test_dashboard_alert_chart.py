"""Focused regression checks for the Admin Dashboard current-day alert chart."""
from __future__ import annotations

import html
import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from config import Config


PROJECT_ROOT = Path(__file__).resolve().parent


def run_checks():
    checks = []
    original_database = Config.DATABASE_PATH

    with tempfile.TemporaryDirectory(prefix='meditrace-alert-chart-') as temp_dir:
        Config.DATABASE_PATH = str(Path(temp_dir) / 'database.db')

        import app as app_module
        from database import get_db, init_db
        from models import (
            get_alert_summary_today,
            get_chart_alerts_by_severity,
            get_dashboard_stats,
            get_nepal_day_utc_bounds,
        )

        if app_module.scheduler:
            app_module.scheduler.shutdown(wait=False)
            app_module.scheduler = None
        init_db()
        app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

        def clear_alerts():
            conn = get_db()
            conn.execute('DELETE FROM alerts')
            conn.execute('DELETE FROM access_events')
            conn.commit()
            conn.close()

        def add_alert(severity, created_at, status='open'):
            conn = get_db()
            user = conn.execute(
                "SELECT * FROM users WHERE username = 'superadmin'"
            ).fetchone()
            event = conn.execute(
                '''
                INSERT INTO access_events (
                    user_id, username, staff_id, role, department,
                    action_type, timestamp, final_risk_level
                ) VALUES (?, ?, ?, ?, ?, 'view', ?, ?)
                ''',
                (
                    user['id'], user['username'], user['staff_id'], user['role'],
                    user['department'], created_at, str(severity).strip().title(),
                ),
            )
            alert = conn.execute(
                '''
                INSERT INTO alerts (
                    event_id, user_id, username, role, department,
                    severity, reason, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'Chart regression test', ?, ?)
                ''',
                (
                    event.lastrowid, user['id'], user['username'], user['role'],
                    user['department'], severity, status, created_at,
                ),
            )
            conn.commit()
            conn.close()
            return alert.lastrowid

        fixed_now = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
        start_utc, end_utc = get_nepal_day_utc_bounds(fixed_now)
        assert start_utc == '2026-07-18T18:15:00'
        assert end_utc == '2026-07-19T18:15:00'
        add_alert('High', '2026-07-18T18:14:59')
        add_alert(' HIGH ', '2026-07-18T18:15:01')
        add_alert('critical', '2026-07-19T18:14:59')
        add_alert('Medium', '2026-07-19T18:15:00')
        boundary_summary = get_alert_summary_today(now=fixed_now)
        assert boundary_summary == {'medium': 0, 'high': 1, 'critical': 1, 'total': 2}
        checks.append('Asia/Kathmandu midnight boundaries converted to half-open UTC range')

        scenarios = (
            ({'medium': 1}, (1, 0, 0)),
            ({'high': 1}, (0, 1, 0)),
            ({'critical': 1}, (0, 0, 1)),
            ({'medium': 1, 'high': 1}, (1, 1, 0)),
            ({'high': 1, 'critical': 1}, (0, 1, 1)),
            ({'medium': 1, 'high': 1, 'critical': 1}, (1, 1, 1)),
            ({}, (0, 0, 0)),
        )
        current_start, current_end = get_nepal_day_utc_bounds()
        current_midpoint = (
            datetime.fromisoformat(current_start)
            + (datetime.fromisoformat(current_end) - datetime.fromisoformat(current_start)) / 2
        ).isoformat()
        for requested, expected in scenarios:
            clear_alerts()
            for severity, count in requested.items():
                for _ in range(count):
                    add_alert(severity, current_midpoint)
            summary = get_alert_summary_today()
            actual = (summary['medium'], summary['high'], summary['critical'])
            assert actual == expected
            assert summary['total'] == sum(expected)
        checks.append('all individual, combined, and zero-severity scenarios')

        clear_alerts()
        for _ in range(12):
            add_alert(' High ', current_midpoint)
        for _ in range(7):
            add_alert('CRITICAL', current_midpoint)
        add_alert('Normal', current_midpoint)
        summary = get_alert_summary_today()
        assert summary == {'medium': 0, 'high': 12, 'critical': 7, 'total': 19}
        stats = get_dashboard_stats()
        assert (
            stats['total_alerts_today'], stats['medium_alerts'],
            stats['high_alerts'], stats['critical_alerts'],
        ) == (19, 0, 12, 7)
        chart = get_chart_alerts_by_severity(stats['alert_summary_today'])
        assert chart == {
            'items': [
                {'key': 'medium', 'label': 'Medium', 'count': 0},
                {'key': 'high', 'label': 'High', 'count': 12},
                {'key': 'critical', 'label': 'Critical', 'count': 7},
            ],
            'total': 19,
        }
        checks.append('shared 0 + 12 + 7 = 19 card and chart snapshot; Normal excluded')

        conn = get_db()
        first_alert = conn.execute(
            "SELECT id FROM alerts WHERE LOWER(TRIM(severity)) = 'high' LIMIT 1"
        ).fetchone()['id']
        conn.execute("UPDATE alerts SET status = 'resolved' WHERE id = ?", (first_alert,))
        conn.commit()
        conn.close()
        assert get_alert_summary_today() == summary
        checks.append('distinct alert IDs counted once and resolution does not duplicate counts')

        client = app_module.app.test_client()
        login = client.post(
            '/login', data={'username': 'superadmin', 'password': 'Super@123'},
            follow_redirects=True,
        )
        assert login.status_code == 200
        english = client.get('/admin/dashboard').get_data(as_text=True)
        match = re.search(
            r'<script id="alertSeverityTodayData" type="application/json">(.*?)</script>',
            english,
        )
        assert match and json.loads(html.unescape(match.group(1))) == chart
        assert 'Alerts by Severity — Today' in english
        assert 'data-alert-count-template="{count} alerts"' in english
        api_response = client.get('/api/charts/alerts-by-severity')
        assert api_response.status_code == 200 and api_response.get_json() == chart
        assert "fetch('/api/charts/alerts-by-severity')" not in (
            PROJECT_ROOT / 'static' / 'js' / 'dashboard.js'
        ).read_text(encoding='utf-8')

        switched = client.post('/language', data={'language': 'ne', 'next': '/admin/dashboard'})
        assert switched.status_code == 302
        nepali = client.get('/admin/dashboard').get_data(as_text=True)
        ne_match = re.search(
            r'<script id="alertSeverityTodayData" type="application/json">(.*?)</script>',
            nepali,
        )
        assert ne_match and json.loads(html.unescape(ne_match.group(1))) == chart
        assert 'गम्भीरताअनुसार आजका चेतावनीहरू' in nepali
        assert 'data-alert-count-template="{count} चेतावनी"' in nepali
        checks.append('same server values in English and Nepali dashboard rendering')

        dashboard_js = (PROJECT_ROOT / 'static' / 'js' / 'dashboard.js').read_text(encoding='utf-8')
        assert "ctx.fillText(" in dashboard_js and 'dataset.noAlertsLabel' in dashboard_js
        assert 'generateLabels: alertSeverityLegendLabels' in dashboard_js
        assert 'Chart.defaults.plugins.legend.labels.generateLabels' not in dashboard_js
        assert 'text: `${label}: ${count}`' in dashboard_js
        assert "((value / total) * 100).toFixed(1)" in dashboard_js
        assert dashboard_js.count('new Chart(') == 3
        assert "fetch('/api/charts/access-timeline')" in dashboard_js
        assert "fetch('/api/charts/user-registrations')" in dashboard_js
        assert "document.addEventListener('meditrace:themechange'" in dashboard_js
        checks.append('zero-data message, counted legend, percentage tooltip, and theme compatibility')

    Config.DATABASE_PATH = original_database
    return checks


if __name__ == '__main__':
    completed = run_checks()
    print(f'Dashboard alert-chart checks passed: {len(completed)}/{len(completed)}')
    for check in completed:
        print(f'  PASS - {check}')
