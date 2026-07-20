"""Patient-record access pipeline: rules, behaviour, hybrid risk and alerts."""
import json
import logging
from datetime import datetime

from flask import has_request_context, request, session

import ai_engine
import risk_engine
import rule_engine
from models import (
    build_access_context, get_user_by_id, insert_access_event, insert_alert,
    is_after_hours, is_sensitive_record,
)

logger = logging.getLogger(__name__)


def _request_metadata():
    if not has_request_context():
        return '127.0.0.1', 'SeedData', ''
    ip_address = request.remote_addr or '127.0.0.1'
    browser_info = request.headers.get('User-Agent', 'Unknown')[:500]
    computer_name = (
        request.headers.get('X-Computer-Name')
        or session.get('access_computer_name')
        or 'Web session'
    ).strip()[:120]
    return ip_address, computer_name, browser_info


def process_access(
        user, record, action_type, *, authorized=True, policy_reason=None,
        monitor_usb=True):
    """Evaluate and persist one explainable access decision."""
    user_dict = user._raw if hasattr(user, '_raw') else user
    if hasattr(user, 'id'):
        user_dict = get_user_by_id(user.id)

    timestamp = datetime.utcnow()
    ip_address, computer_name, browser_info = _request_metadata()
    context = build_access_context(
        user_dict['id'], record, timestamp, computer_name=computer_name,
    )
    context['timestamp'] = timestamp
    context['after_hours'] = is_after_hours(user_dict, timestamp)
    if record:
        context['is_sensitive'] = is_sensitive_record(record['sensitivity_level'])
        context['department_match'] = int(user_dict['department'] == record['department'])
    else:
        context['is_sensitive'] = False
        context['department_match'] = 1

    rule_result = rule_engine.evaluate_access(user_dict, record, action_type, context)
    anomaly = ai_engine.assess_event(user_dict, record, action_type, context)
    hybrid = risk_engine.calculate_hybrid(rule_result, anomaly)
    final_risk = hybrid['final_risk_level']
    anomaly_score = anomaly.get('anomaly_score')

    # Authorization evidence is appended only after risk calculation so this
    # audit upgrade cannot change rules, weights, thresholds, or ML scoring.
    rule_result['authorization_allowed'] = bool(authorized)
    rule_result['policy_reason_code'] = policy_reason

    explanation = {
        'schema_version': 2,
        'scoring_method': anomaly.get('anomaly_method'),
        'triggered_rules': rule_result.get('triggered_rules', []),
        'rule_score': hybrid['rule_score'],
        'rule_score_uncapped': rule_result.get('rule_score_uncapped', hybrid['rule_score']),
        'rule_score_cap_applied': rule_result.get('rule_score_cap_applied', False),
        'rule_contributions': rule_result.get('rule_contributions', []),
        'behavioural_anomaly_score': anomaly_score,
        'behavioural_deviations': anomaly.get('behavioural_deviations', []),
        'baseline': anomaly.get('baseline', {}),
        'baseline_source': anomaly.get('baseline_source'),
        'model': {
            'available': anomaly.get('model_available'),
            'type': 'IsolationForest' if anomaly.get('anomaly_method') == 'isolation_forest' else None,
            'version': anomaly.get('model_version'),
            'raw_decision_function': anomaly.get('model_raw_score'),
            'prediction': anomaly.get('model_prediction'),
            'confidence': anomaly.get('model_confidence'),
            'error': anomaly.get('model_error'),
            'interpretation': anomaly.get('score_interpretation'),
        },
        'cybersecurity_features': anomaly.get('features', {}),
        'hybrid': hybrid,
        'final_hybrid_score': hybrid['final_hybrid_score'],
        'final_risk_level': final_risk,
        'authorization': {
            'allowed': bool(authorized),
            'policy_reason_code': policy_reason,
            'record_department': record.get('department') if record else None,
        },
        'minimum_risk_override': hybrid.get('minimum_risk_override'),
        'human_review_required': hybrid['human_review_required'],
        'privacy_note': (
            'No diagnosis, patient demographics, vital signs, medication or clinical text '
            'was used in behavioural scoring.'
        ),
    }
    explanation_json = json.dumps(explanation, separators=(',', ':'), ensure_ascii=False)
    override_json = json.dumps(hybrid['minimum_risk_override']) if hybrid.get('minimum_risk_override') else None

    event_data = {
        'user_id': user_dict['id'], 'username': user_dict['username'],
        'staff_id': user_dict['staff_id'], 'role': user_dict['role'],
        'department': user_dict['department'],
        'record_id': record['id'] if record else None,
        'record_category': record['record_category'] if record else None,
        'sensitivity_level': record['sensitivity_level'] if record else None,
        'action_type': action_type, 'timestamp': timestamp.isoformat(),
        'ip_address': ip_address, 'computer_name': computer_name,
        'browser_info': browser_info,
        'is_after_hours': int(bool(rule_result.get('after_hours'))),
        'is_sensitive': int(bool(rule_result.get('is_sensitive'))),
        'department_match': int(bool(rule_result.get('department_match'))),
        'rule_result': json.dumps(rule_result, separators=(',', ':')),
        'ml_score': anomaly_score or 0,
        'rule_score': hybrid['rule_score'], 'anomaly_score': anomaly_score,
        'hybrid_score': hybrid['final_hybrid_score'],
        'baseline_source': anomaly.get('baseline_source'),
        'anomaly_method': anomaly.get('anomaly_method'),
        'model_version': anomaly.get('model_version'),
        'model_raw_score': anomaly.get('model_raw_score'),
        'model_confidence': anomaly.get('model_confidence'),
        'minimum_risk_override': override_json,
        'human_review_required': int(hybrid['human_review_required']),
        'explanation_json': explanation_json,
        'final_risk_level': final_risk, 'alert_created': 0,
    }
    event_id = insert_access_event(event_data)

    alert_created = 0
    if risk_engine.should_create_alert(final_risk):
        reason = risk_engine.build_alert_reason(
            user_dict, record, rule_result, anomaly, hybrid,
        )
        insert_alert({
            'event_id': event_id, 'user_id': user_dict['id'],
            'username': user_dict['username'], 'role': user_dict['role'],
            'department': user_dict['department'],
            'record_id': record['id'] if record else None,
            'severity': final_risk, 'reason': reason,
            'triggered_rules': json.dumps(rule_result.get('triggered_rules', [])),
            'ml_score': anomaly_score or 0,
            'rule_score': hybrid['rule_score'], 'anomaly_score': anomaly_score,
            'hybrid_score': hybrid['final_hybrid_score'],
            'baseline_source': anomaly.get('baseline_source'),
            'anomaly_method': anomaly.get('anomaly_method'),
            'model_version': anomaly.get('model_version'),
            'model_confidence': anomaly.get('model_confidence'),
            'minimum_risk_override': override_json,
            'human_review_required': 1, 'explanation_json': explanation_json,
            'created_at': timestamp.isoformat(),
        })
        alert_created = 1
        from database import get_db
        conn = get_db()
        conn.execute('UPDATE access_events SET alert_created = 1 WHERE id = ?', (event_id,))
        conn.commit()
        conn.close()

    usb_warning = None
    usb_monitoring_error = None
    if monitor_usb:
        try:
            import usb_engine
            usb_warning = usb_engine.on_patient_data_access(
                user_dict, record, action_type, computer_name,
                session if has_request_context() else None,
                browser_info=browser_info,
            )
        except Exception as exc:
            usb_monitoring_error = str(exc)
            logger.exception('USB monitoring failed after access event %s', event_id)

    return {
        'event_id': event_id, 'timestamp': event_data['timestamp'],
        'ip_address': ip_address, 'computer_name': computer_name,
        'final_risk_level': final_risk,
        'final_hybrid_score': hybrid['final_hybrid_score'],
        'rule_score': hybrid['rule_score'], 'anomaly_score': anomaly_score,
        'ml_score': anomaly_score or 0,
        'alert_created': alert_created, 'rule_result': rule_result,
        'anomaly_assessment': anomaly, 'hybrid_result': hybrid,
        'explanation': explanation, 'human_review_required': hybrid['human_review_required'],
        'usb_warning': usb_warning, 'usb_monitoring_error': usb_monitoring_error,
        'usb_export_allowed': not usb_warning or usb_warning.get('export_allowed', True),
        'authorization_allowed': bool(authorized),
        'policy_reason_code': policy_reason,
    }
