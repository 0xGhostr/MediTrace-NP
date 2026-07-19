"""Focused bilingual-interface, persistence, and security regression checks."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import sqlite3
import tempfile
from collections import Counter
from pathlib import Path

import app as app_module
from config import Config
from i18n import localize_html, normalize_locale


PROJECT_ROOT = Path(__file__).resolve().parent


def csrf_token(html):
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match, 'CSRF token missing from rendered page'
    return match.group(1)


def login(client, username='admin', password='Admin@123'):
    page = client.get('/login')
    return client.post(
        '/login',
        data={
            'username': username,
            'password': password,
            'csrf_token': csrf_token(page.get_data(as_text=True)),
        },
    )


def database_snapshot(path):
    conn = sqlite3.connect(path)
    snapshot = {
        'roles': conn.execute('SELECT id, role, department FROM users ORDER BY id').fetchall(),
        'alerts': conn.execute('SELECT id, severity, status FROM alerts ORDER BY id').fetchall(),
        'records': conn.execute(
            'SELECT id, record_category, sensitivity_level FROM patient_records ORDER BY id'
        ).fetchall(),
        'events': conn.execute(
            'SELECT id, action_type, final_risk_level FROM access_events ORDER BY id'
        ).fetchall(),
    }
    conn.close()
    return snapshot


def run_checks():
    checks = []
    original_database = Config.DATABASE_PATH
    if app_module.scheduler:
        app_module.scheduler.shutdown(wait=False)
        app_module.scheduler = None

    with tempfile.TemporaryDirectory(prefix='meditrace-i18n-') as temp_dir:
        temp_database = Path(temp_dir) / 'database.db'
        shutil.copy2(original_database, temp_database)
        Config.DATABASE_PATH = str(temp_database)
        app_module.app.config.update(TESTING=True)

        conn = sqlite3.connect(temp_database)
        conn.execute("UPDATE users SET preferred_language = 'en' WHERE username = 'admin'")
        conn.commit()
        default_language = next(
            row[4] for row in conn.execute('PRAGMA table_info(users)')
            if row[1] == 'preferred_language'
        )
        conn.close()
        assert str(default_language).strip("'") == 'en'
        checks.append('additive preferred-language schema default')

        before = database_snapshot(temp_database)
        report_files = sorted((PROJECT_ROOT / 'reports').glob('*.csv'))
        report_hash = (
            hashlib.sha256(report_files[0].read_bytes()).hexdigest() if report_files else None
        )

        # Browser negotiation and English fallback.
        guest_ne = app_module.app.test_client()
        response = guest_ne.get('/login', headers={'Accept-Language': 'ne-NP,ne;q=0.9'})
        nepali_login = response.get_data(as_text=True)
        assert response.headers['Content-Language'] == 'ne'
        assert '<html lang="ne">' in nepali_login
        assert 'पुनः स्वागत छ' in nepali_login
        assert 'name="language" value="ne"' in nepali_login

        guest_en = app_module.app.test_client()
        response = guest_en.get('/login', headers={'Accept-Language': 'fr-FR,fr;q=0.9'})
        assert response.headers['Content-Language'] == 'en'
        assert 'Welcome back' in response.get_data(as_text=True)
        assert normalize_locale('ne-NP') == 'ne' and normalize_locale('xx') is None
        checks.append('browser negotiation and deterministic English fallback')

        # POST + CSRF + strict locale validation + local-only return URL.
        assert guest_en.get('/language').status_code == 405
        assert guest_en.post('/language', data={'language': 'ne', 'next': '/login'}).status_code == 400
        login_page = guest_en.get('/login').get_data(as_text=True)
        token = csrf_token(login_page)
        assert guest_en.post(
            '/language', data={'language': 'xx', 'next': '/login', 'csrf_token': token}
        ).status_code == 400
        response = guest_en.post(
            '/language',
            data={
                'language': 'ne',
                'next': 'https://attacker.example/steal',
                'csrf_token': token,
            },
        )
        assert response.status_code == 302
        assert response.location.endswith('/') and 'attacker.example' not in response.location
        assert 'meditrace_language=ne' in response.headers.get('Set-Cookie', '')
        for malicious_next in ('//attacker.example', '/\\attacker.example', '/%2f%2fattacker.example'):
            page = guest_en.get('/login').get_data(as_text=True)
            blocked = guest_en.post(
                '/language',
                data={'language': 'ne', 'next': malicious_next, 'csrf_token': csrf_token(page)},
            )
            assert blocked.location.endswith('/') and 'attacker.example' not in blocked.location
        checks.append('CSRF-protected locale allowlist and open-redirect prevention')

        # Public pages share the switch and translate labels without changing option values.
        register_page = guest_en.get('/register').get_data(as_text=True)
        recovery_page = guest_en.get('/account-recovery').get_data(as_text=True)
        assert '<html lang="ne">' in register_page
        assert 'कर्मचारी स्व-दर्ता' in register_page
        assert 'value="Doctor"' in register_page and 'चिकित्सक' in register_page
        assert 'खाता पुनर्प्राप्ति अनुरोध' in recovery_page
        assert 'value="forgot_password"' in recovery_page
        checks.append('public-page translation with canonical form values')

        # Saved authenticated preference is authoritative after login.
        auth_client = app_module.app.test_client()
        prelogin = auth_client.get('/login', headers={'Accept-Language': 'ne'}).get_data(as_text=True)
        assert '<html lang="ne">' in prelogin
        login_response = auth_client.post(
            '/login',
            data={
                'username': 'admin', 'password': 'Admin@123',
                'csrf_token': csrf_token(prelogin),
            },
            follow_redirects=True,
        )
        assert '<html lang="en">' in login_response.get_data(as_text=True)

        dashboard = auth_client.get('/admin/dashboard').get_data(as_text=True)
        token = csrf_token(dashboard)
        switched = auth_client.post(
            '/language',
            data={'language': 'ne', 'next': '/admin/dashboard', 'csrf_token': token},
            follow_redirects=True,
        )
        html = switched.get_data(as_text=True)
        assert '<html lang="ne">' in html
        assert 'प्रशासक ड्यासबोर्ड' in html and 'सुरक्षा चेतावनीहरू' in html
        assert html.index('language-switch') < html.index('header-user-avatar')
        conn = sqlite3.connect(temp_database)
        assert conn.execute(
            "SELECT preferred_language FROM users WHERE username = 'admin'"
        ).fetchone()[0] == 'ne'
        conn.close()
        checks.append('authenticated persistence and shared-header placement')

        # Representative admin pages and stable English evidence/codes.
        pages = {
            '/admin/alerts': 'मानवीय समीक्षा',
            '/admin/events': 'पहुँच घटना लगहरू',
            '/admin/usb-monitoring': 'USB उपकरण',
            '/admin/reports': 'प्रतिवेदन',
            '/records': 'बिरामी अभिलेखहरू',
            '/admin/account-recovery': 'पुनर्प्राप्ति अनुरोध',
        }
        for route, expected in pages.items():
            page = auth_client.get(route)
            assert page.status_code == 200, route
            assert expected in page.get_data(as_text=True), route
        alerts_html = auth_client.get('/admin/alerts').get_data(as_text=True)
        assert 'RULE_' in alerts_html  # Raw rule evidence remains canonical.
        assert 'iforest-behaviour-v2' in alerts_html  # Model version remains canonical.
        checks.append('major authenticated areas and immutable evidence rendering')

        # Logout keeps the harmless preference and public UI stays Nepali.
        logout_response = auth_client.get('/logout', follow_redirects=True)
        assert '<html lang="ne">' in logout_response.get_data(as_text=True)
        checks.append('logout preserves harmless language preference')

        # Translation assets are centralized and confirmation strings are not inline JS.
        raw_catalog = (PROJECT_ROOT / 'translations' / 'ne.json').read_text(encoding='utf-8')
        pairs = json.loads(raw_catalog, object_pairs_hook=lambda value: value)
        duplicates = [key for key, count in Counter(key for key, _ in pairs).items() if count > 1]
        assert not duplicates, duplicates
        assert len(pairs) >= 800
        assert not list((PROJECT_ROOT / 'templates').glob('**/*.po'))
        template_text = ''.join(
            path.read_text(encoding='utf-8') for path in (PROJECT_ROOT / 'templates').glob('*.html')
        )
        assert "confirm('" not in template_text
        for script in ('dashboard.js', 'patient-records.js', 'message-inbox.js', 'usb-monitor.js'):
            assert 'MediTraceI18n' in (PROJECT_ROOT / 'static' / 'js' / script).read_text(encoding='utf-8')
        checks.append('catalogue integrity and localized JavaScript strings')

        # Rendering language must never rewrite canonical DB values or CSV exports.
        after = database_snapshot(temp_database)
        assert before == after
        if report_files:
            assert hashlib.sha256(report_files[0].read_bytes()).hexdigest() == report_hash
        assert localize_html('<p>Unknown catalogue phrase</p>') == '<p>Unknown catalogue phrase</p>'
        checks.append('canonical database/report preservation and missing-key fallback')

    Config.DATABASE_PATH = original_database
    return checks


if __name__ == '__main__':
    completed = run_checks()
    for check in completed:
        print(f'[PASS] {check}')
    print(f'{len(completed)}/{len(completed)} bilingual-interface checks passed')
