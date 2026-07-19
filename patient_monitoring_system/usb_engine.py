"""
USB monitoring engine — auto-detect on patient access + simulation fallback.
Defensive patient data leakage detection for thesis demo.
"""
import json
from datetime import datetime

from database import get_db

# Demo USB profiles (simulation mode)
UNKNOWN_USB = {
    'usb_name': 'SanDisk Ultra 32GB',
    'usb_serial': 'UNKNOWN-USB-001',
    'usb_size': '32GB',
    'drive_letter': 'E:',
}

WHITELISTED_USB = {
    'usb_name': 'Hospital Backup USB',
    'usb_serial': 'APPROVED-USB-001',
    'usb_size': '64GB',
    'drive_letter': 'F:',
}


def is_usb_whitelisted(usb_serial):
    from models import get_usb_device_by_serial
    device = get_usb_device_by_serial(usb_serial)
    return bool(device and device.get('status') == 'whitelisted')


def get_usb_device_status(usb_serial):
    from models import get_usb_device_by_serial
    device = get_usb_device_by_serial(usb_serial)
    return device.get('status', 'pending') if device else 'pending'


def get_active_usb_connection(user_id):
    """Return active USB connection dict for user if not removed."""
    conn = get_db()
    events = conn.execute(
        '''
        SELECT e.*, d.status AS device_status
        FROM usb_events e
        LEFT JOIN usb_devices d ON d.id = e.device_id
        WHERE e.user_id = ?
        ORDER BY timestamp DESC LIMIT 30
        ''',
        (user_id,),
    ).fetchall()
    conn.close()
    for ev in events:
        ev = dict(ev)
        if ev['event_type'] == 'removed':
            continue
        if ev['event_type'] in (
            'inserted', 'whitelisted_insert', 'auto_detected',
            'export_to_usb', 'sensitive_access_usb', 'patient_access_usb',
        ):
            removed = any(
                dict(r)['event_type'] == 'removed'
                and dict(r)['usb_serial'] == ev['usb_serial']
                and dict(r)['timestamp'] > ev['timestamp']
                for r in events
            )
            if not removed:
                return ev
    return None


def is_usb_connection_active(user_id, usb_serial):
    """Return whether the latest event for this user/device is not a removal."""
    from models import normalize_usb_serial
    serial = normalize_usb_serial(usb_serial)
    conn = get_db()
    event = conn.execute(
        '''
        SELECT event_type FROM usb_events
        WHERE user_id = ? AND UPPER(TRIM(usb_serial)) = ?
        ORDER BY timestamp DESC, id DESC LIMIT 1
        ''',
        (user_id, serial),
    ).fetchone()
    conn.close()
    return bool(event and event['event_type'] != 'removed')


def _sync_session_usb(session, devices):
    """Keep session in sync with detected USB for simulation fallback."""
    if session is not None:
        session['connected_usb_devices'] = devices
        session.modified = True


def detect_usb_for_session(session=None, user=None, computer_name=None, browser_info=None):
    """Detect connected USB devices (Windows) or session simulation state."""
    import usb_detector
    devices = usb_detector.detect_connected_usb(session)
    if session is not None and devices:
        _sync_session_usb(session, devices)
    if user is not None:
        from models import register_usb_device
        enriched = []
        for usb_info in devices:
            device = register_usb_device(
                usb_info, user, computer_name=computer_name, browser_info=browser_info,
            )
            current = dict(usb_info)
            current['usb_serial'] = device['usb_serial']
            current['device_id'] = device['id']
            current['status'] = device['status']
            current['is_whitelisted'] = device['status'] == 'whitelisted'
            enriched.append(current)
        devices = enriched
    return devices


def record_usb_event(user, event_type, usb_info, computer_name=None, risk_level=None,
                     create_alert=False, record_id=None, browser_info=None):
    """Persist USB event and optionally create system alert."""
    from models import insert_access_event, insert_alert, register_usb_device

    user_dict = user._raw if hasattr(user, '_raw') else user
    if hasattr(user, 'id') and not isinstance(user_dict, dict):
        user_dict = user._raw
    device = register_usb_device(
        usb_info, user_dict, computer_name=computer_name, browser_info=browser_info,
    )
    usb_info = dict(usb_info)
    usb_info['usb_serial'] = device['usb_serial']
    device_status = device['status']
    whitelisted = 1 if device_status == 'whitelisted' else 0
    if event_type == 'whitelisted_insert' and not whitelisted:
        event_type = 'auto_detected'

    if risk_level is None:
        if event_type in ('whitelisted_insert', 'auto_detected') and whitelisted:
            risk_level = 'Normal'
        elif event_type in ('inserted', 'auto_detected') and not whitelisted:
            risk_level = 'Critical'
        elif event_type in ('export_to_usb', 'blocked_export', 'patient_access_usb', 'sensitive_access_usb'):
            risk_level = 'Critical'
        elif event_type == 'removed':
            risk_level = 'Normal'
        else:
            risk_level = 'Critical' if not whitelisted else 'Normal'

    now = datetime.utcnow().isoformat()
    conn = get_db()
    cursor = conn.execute(
        '''
        INSERT INTO usb_events (
            user_id, username, staff_id, role, department, computer_name,
            event_type, usb_name, usb_serial, usb_size, drive_letter,
            is_whitelisted, timestamp, risk_level, alert_created, device_id, browser_info
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            user_dict['id'], user_dict['username'], user_dict['staff_id'],
            user_dict['role'], user_dict['department'],
            computer_name or 'WORKSTATION',
            event_type, usb_info['usb_name'], usb_info['usb_serial'],
            usb_info['usb_size'], usb_info.get('drive_letter', ''),
            whitelisted, now, risk_level, 0, device['id'], browser_info,
        ),
    )
    usb_event_id = cursor.lastrowid
    conn.commit()
    conn.close()

    alert_created = 0
    rule_score = {'Critical': 85, 'High': 65, 'Medium': 45, 'Normal': 0}.get(risk_level, 0)
    human_review = risk_level in ('Critical', 'High', 'Medium')
    rule_result = {
        'severity': risk_level, 'rule_score': rule_score,
        'triggered_rules': ['USB_MONITOR'],
        'rule_contributions': [{
            'rule': 'USB_MONITOR', 'severity': risk_level, 'points': rule_score,
            'reason': f'USB policy event: {event_type}.',
        }],
    }
    explanation = {
        'schema_version': 2, 'scoring_method': 'rules_only',
        'triggered_rules': ['USB_MONITOR'], 'rule_score': rule_score,
        'rule_contributions': rule_result['rule_contributions'],
        'behavioural_anomaly_score': None, 'behavioural_deviations': [],
        'baseline_source': 'not_applicable_usb_policy',
        'model': {
            'available': False, 'type': None, 'version': None,
            'raw_decision_function': None, 'prediction': None,
            'confidence': 'not_applicable',
            'interpretation': 'USB policy events use deterministic rules, not an ML score.',
        },
        'hybrid': {
            'rule_score': rule_score, 'anomaly_score': None,
            'rule_weight': 1.0, 'anomaly_weight': 0.0,
            'final_hybrid_score': rule_score, 'final_risk_level': risk_level,
            'minimum_risk_override': None,
            'human_review_required': human_review,
            'calculation': f'{rule_score} × 1.00 = {rule_score}',
        },
        'final_hybrid_score': rule_score, 'final_risk_level': risk_level,
        'minimum_risk_override': None, 'human_review_required': human_review,
        'privacy_note': 'No patient medical content was used in this USB policy decision.',
    }
    explanation_json = json.dumps(explanation, separators=(',', ':'))
    access_event_id = insert_access_event({
            'user_id': user_dict['id'],
            'username': user_dict['username'],
            'staff_id': user_dict['staff_id'],
            'role': user_dict['role'],
            'department': user_dict['department'],
            'record_id': record_id,
            'record_category': 'USB Monitoring',
            'sensitivity_level': 'Critical' if risk_level == 'Critical' else 'Low',
            'action_type': 'usb_monitor',
            'timestamp': now,
            'ip_address': None,
            'computer_name': computer_name or 'WORKSTATION',
            'is_after_hours': 0,
            'is_sensitive': 1 if risk_level == 'Critical' else 0,
            'department_match': 1,
            'rule_result': json.dumps(rule_result, separators=(',', ':')),
            'ml_score': 0,
            'rule_score': rule_score,
            'anomaly_score': None,
            'hybrid_score': rule_score,
            'baseline_source': 'not_applicable_usb_policy',
            'anomaly_method': 'rules_only',
            'model_version': None,
            'model_raw_score': None,
            'model_confidence': 'not_applicable',
            'minimum_risk_override': None,
            'human_review_required': 1 if human_review else 0,
            'explanation_json': explanation_json,
            'browser_info': browser_info,
            'final_risk_level': risk_level,
            'alert_created': 0,
    })
    conn = get_db()
    conn.execute(
        'UPDATE usb_events SET access_event_id = ? WHERE id = ?',
        (access_event_id, usb_event_id),
    )
    conn.commit()
    conn.close()

    if create_alert or human_review:
        reason = _build_usb_reason(
            user_dict, event_type, usb_info, risk_level, computer_name, record_id,
        )
        insert_alert({
            'event_id': access_event_id,
            'user_id': user_dict['id'],
            'username': user_dict['username'],
            'role': user_dict['role'],
            'department': user_dict['department'],
            'record_id': record_id,
            'severity': risk_level,
            'reason': reason,
            'triggered_rules': '["USB_MONITOR"]',
            'ml_score': 0,
            'rule_score': rule_score,
            'anomaly_score': None,
            'hybrid_score': rule_score,
            'baseline_source': 'not_applicable_usb_policy',
            'anomaly_method': 'rules_only',
            'model_version': None,
            'model_confidence': 'not_applicable',
            'minimum_risk_override': None,
            'human_review_required': 1,
            'explanation_json': explanation_json,
            'created_at': now,
        })
        alert_created = 1
        conn = get_db()
        conn.execute(
            'UPDATE usb_events SET alert_created = 1 WHERE id = ?',
            (usb_event_id,),
        )
        conn.execute(
            'UPDATE access_events SET alert_created = 1 WHERE id = ?',
            (access_event_id,),
        )
        conn.commit()
        conn.close()

    return usb_event_id, alert_created


def _build_usb_reason(user, event_type, usb_info, risk_level, computer_name=None, record_id=None):
    record_part = f' while accessing patient record #{record_id}' if record_id else ''
    return (
        f"USB security event: {event_type}{record_part}. "
        f"User {user['username']} ({user['staff_id']}) from {user['department']} "
        f"on {computer_name or 'WORKSTATION'}. "
        f"USB: {usb_info['usb_name']} serial {usb_info['usb_serial']} "
        f"({usb_info['usb_size']}, drive {usb_info.get('drive_letter', 'N/A')}). "
        f"Risk: {risk_level}. Requires human admin review."
    )


def _build_popup_payload(usb_info, device_status, event_type, risk_level, alert_created, record=None):
    whitelisted = device_status == 'whitelisted'
    return {
        'show_popup': True,
        'usb_name': usb_info['usb_name'],
        'usb_serial': usb_info['usb_serial'],
        'usb_size': usb_info.get('usb_size', ''),
        'drive_letter': usb_info.get('drive_letter', ''),
        'is_whitelisted': bool(whitelisted),
        'device_status': device_status,
        'export_allowed': event_type != 'blocked_export',
        'event_type': event_type,
        'risk_level': risk_level,
        'alert_created': bool(alert_created),
        'record_code': record.get('patient_code') if record else None,
        'message': _popup_message(usb_info, device_status, event_type, record),
    }


def _popup_message(usb_info, device_status, event_type, record):
    record_ref = f" ({record['patient_code']})" if record else ''
    if event_type == 'blocked_export':
        status_label = 'blocked' if device_status == 'blocked' else 'pending administrator review'
        return (
            f'Patient-record export was denied because USB drive "{usb_info["usb_name"]}" '
            f'is {status_label}{record_ref}. The attempt was logged and administrators were alerted.'
        )
    if event_type == 'export_to_usb':
        return (
            f"Patient data export detected while USB drive "
            f'"{usb_info["usb_name"]}" ({usb_info["drive_letter"]}) is connected{record_ref}. '
            'Critical alert sent to administrators.'
        )
    if device_status != 'whitelisted':
        return (
            f'Unknown USB device detected: "{usb_info["usb_name"]}" '
            f'on {usb_info.get("drive_letter", "drive")}{record_ref}. '
            'Patient data access is being monitored. Administrators have been alerted.'
        )
    return (
        f'Approved USB connected: "{usb_info["usb_name"]}" '
        f'on {usb_info.get("drive_letter", "drive")}{record_ref}. Access logged.'
    )


def on_patient_data_access(user, record, action_type, computer_name=None, session=None,
                           browser_info=None):
    """
    Auto-monitor USB when patient data is accessed, exported, or copied.
    Returns popup payload dict or None.
    """
    user_id = user.id if hasattr(user, 'id') else user['id']
    record_id = record['id'] if record else None
    devices = detect_usb_for_session(
        session, user, computer_name=computer_name, browser_info=browser_info,
    )

    if not devices:
        return None

    popup = None
    for usb_info in devices:
        device_status = usb_info.get('status') or get_usb_device_status(usb_info['usb_serial'])
        whitelisted = device_status == 'whitelisted'
        active = get_active_usb_connection(user_id)

        if action_type == 'export':
            event_type = 'export_to_usb' if whitelisted else 'blocked_export'
            _, alert_created = record_usb_event(
                user, event_type, usb_info, computer_name,
                risk_level='Critical', create_alert=True, record_id=record_id,
                browser_info=browser_info,
            )
            popup = _build_popup_payload(
                usb_info, device_status, event_type, 'Critical', alert_created, record,
            )
            continue

        if active and active['usb_serial'] == usb_info['usb_serial']:
            if action_type in ('view', 'search') and not whitelisted:
                _, alert_created = record_usb_event(
                    user, 'patient_access_usb', usb_info, computer_name,
                    risk_level='Critical', create_alert=True, record_id=record_id,
                    browser_info=browser_info,
                )
                popup = _build_popup_payload(
                    usb_info, device_status, 'patient_access_usb', 'Critical', alert_created, record,
                )
            continue

        event_type = 'whitelisted_insert' if whitelisted else 'auto_detected'
        risk = 'Normal' if whitelisted else 'Critical'
        _, alert_created = record_usb_event(
            user, event_type, usb_info, computer_name,
            risk_level=risk, create_alert=not whitelisted, record_id=record_id,
            browser_info=browser_info,
        )
        if action_type in ('view', 'search'):
            popup = _build_popup_payload(
                usb_info, device_status, event_type, risk, alert_created, record,
            )

    return popup


def set_session_simulated_usb(session, usb_info):
    """Store simulated USB in session for demo when hardware detection unavailable."""
    if session is not None:
        session['connected_usb_devices'] = [usb_info]
        session.modified = True


def clear_session_usb(session):
    if session is not None:
        session.pop('connected_usb_devices', None)
        session.modified = True


# --- Manual simulation helpers (admin demo page) ---

def simulate_unknown_insert(user, computer_name='SIM-PC', session=None, browser_info=None):
    set_session_simulated_usb(session, UNKNOWN_USB.copy())
    status = get_usb_device_status(UNKNOWN_USB['usb_serial'])
    whitelisted = status == 'whitelisted'
    return record_usb_event(
        user, 'whitelisted_insert' if whitelisted else 'inserted',
        UNKNOWN_USB.copy(), computer_name,
        risk_level='Normal' if whitelisted else 'Critical',
        create_alert=not whitelisted, browser_info=browser_info,
    )


def simulate_whitelisted_insert(user, computer_name='SIM-PC', session=None, browser_info=None):
    set_session_simulated_usb(session, WHITELISTED_USB.copy())
    status = get_usb_device_status(WHITELISTED_USB['usb_serial'])
    event_type = 'whitelisted_insert' if status == 'whitelisted' else 'inserted'
    risk_level = 'Normal' if status == 'whitelisted' else 'Critical'
    return record_usb_event(
        user, event_type, WHITELISTED_USB.copy(), computer_name,
        risk_level=risk_level, create_alert=status != 'whitelisted',
        browser_info=browser_info,
    )


def simulate_usb_removed(user, usb_serial=None, computer_name='SIM-PC', session=None,
                         browser_info=None):
    clear_session_usb(session)
    serial = usb_serial or UNKNOWN_USB['usb_serial']
    conn = get_db()
    dev = conn.execute(
        'SELECT * FROM usb_devices WHERE usb_serial = ?', (serial,)
    ).fetchone()
    conn.close()
    if dev:
        info = dict(dev)
        usb_info = {
            'usb_name': info['usb_name'],
            'usb_serial': info['usb_serial'],
            'usb_size': info['usb_size'],
            'drive_letter': 'F:',
        }
    else:
        usb_info = UNKNOWN_USB.copy()
        usb_info['usb_serial'] = serial
    return record_usb_event(
        user, 'removed', usb_info, computer_name, risk_level='Normal',
        create_alert=False, browser_info=browser_info,
    )


def simulate_export_to_usb(user, computer_name='SIM-PC', session=None, browser_info=None):
    active = get_active_usb_connection(user.id if hasattr(user, 'id') else user['id'])
    usb_info = UNKNOWN_USB.copy()
    if active:
        usb_info = {
            'usb_name': active['usb_name'],
            'usb_serial': active['usb_serial'],
            'usb_size': active['usb_size'],
            'drive_letter': active['drive_letter'],
        }
    elif session and session.get('connected_usb_devices'):
        usb_info = session['connected_usb_devices'][0]
    status = get_usb_device_status(usb_info['usb_serial'])
    event_type = 'export_to_usb' if status == 'whitelisted' else 'blocked_export'
    event_id, alert_created = record_usb_event(
        user, event_type, usb_info, computer_name,
        risk_level='Critical', create_alert=True, browser_info=browser_info,
    )
    return {
        'event_id': event_id,
        'alert_created': bool(alert_created),
        'device_status': status,
        'export_allowed': status == 'whitelisted',
    }


def check_sensitive_access_with_unknown_usb(user, record, computer_name=None, session=None):
    """Legacy hook — delegates to on_patient_data_access."""
    return on_patient_data_access(user, record, 'view', computer_name, session)
