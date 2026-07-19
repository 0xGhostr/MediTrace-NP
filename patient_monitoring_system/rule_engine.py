"""Deterministic suspicious-access rules with exact score contributions."""
from models import category_mismatch, is_after_hours, is_sensitive_record

SEVERITY_ORDER = {'Normal': 0, 'Medium': 1, 'High': 2, 'Critical': 3}


def _max_severity(severities):
    return max(severities, key=lambda value: SEVERITY_ORDER.get(value, 0)) if severities else 'Normal'


def evaluate_access(user, record, action_type, context):
    triggered = []
    severities = []
    reasons = []
    contributions = []
    timestamp = context.get('timestamp')
    after_hours = is_after_hours(user, timestamp)
    department_match = bool(context.get('department_match', 1))
    sensitivity = record.get('sensitivity_level', 'Low') if record else 'Low'
    sensitive = is_sensitive_record(sensitivity) if record else False
    role_mismatch = bool(
        record and category_mismatch(user['role'], record['record_category'])
    )

    def trigger(rule, severity, points, reason):
        triggered.append(rule)
        severities.append(severity)
        reasons.append(reason)
        contributions.append({
            'rule': rule, 'severity': severity, 'points': points,
            'reason': reason,
        })

    if after_hours and action_type in ('view', 'export', 'search'):
        trigger('RULE_1_AFTER_HOURS', 'High', 30, 'Access occurred outside scheduled work hours.')

    if record and sensitive:
        severity = 'High' if role_mismatch else 'Medium'
        trigger(
            'RULE_2_SENSITIVE_RECORD', severity, 30 if role_mismatch else 20,
            f'Access to a {sensitivity} sensitivity record.',
        )

    if record and not department_match:
        severity = 'High' if sensitive else 'Medium'
        trigger(
            'RULE_3_CROSS_DEPARTMENT', severity, 30 if sensitive else 20,
            f"User department ({user['department']}) differs from record department ({record['department']}).",
        )

    if context.get('records_last_10_min', 0) >= 10:
        trigger('RULE_4_BULK_ACCESS', 'High', 35, 'Ten or more record views occurred within ten minutes.')

    if context.get('high_critical_last_30_min', 0) >= 3:
        trigger('RULE_5_REPEATED_SENSITIVE', 'High', 35, 'Three or more High/Critical records were viewed within thirty minutes.')

    if action_type == 'delete_attempt' and user['role'] not in ('Admin', 'Super Admin'):
        trigger('RULE_6_DELETE_ATTEMPT', 'Critical', 100, 'A non-administrator attempted to delete a patient record.')

    if record and role_mismatch and 'RULE_2_SENSITIVE_RECORD' not in triggered:
        trigger(
            'RULE_ROLE_MISMATCH', 'Medium', 25,
            f"Role {user['role']} accessed a {record['record_category']} category outside assigned permissions.",
        )

    base_severity = _max_severity(severities)
    if len(triggered) >= 2:
        if base_severity != 'Critical':
            base_severity = 'High'
        trigger('RULE_7_COMBINED', 'High', 10, 'Multiple suspicious rules triggered together.')

    if all(rule in triggered for rule in (
        'RULE_1_AFTER_HOURS', 'RULE_2_SENSITIVE_RECORD', 'RULE_3_CROSS_DEPARTMENT'
    )):
        base_severity = 'Critical'
        trigger(
            'RULE_7_CRITICAL_COMBO', 'Critical', 15,
            'Critical combination: after-hours, sensitive record and department mismatch.',
        )

    uncapped_rule_score = sum(item['points'] for item in contributions)
    return {
        'severity': base_severity,
        'rule_score': min(100, uncapped_rule_score),
        'rule_score_uncapped': uncapped_rule_score,
        'rule_score_cap_applied': uncapped_rule_score > 100,
        'rule_contributions': contributions,
        'reason': ' '.join(reasons) if reasons else 'No suspicious deterministic rules triggered.',
        'triggered_rules': triggered,
        'after_hours': after_hours,
        'is_sensitive': sensitive,
        'department_match': department_match,
        'role_mismatch': role_mismatch,
    }
