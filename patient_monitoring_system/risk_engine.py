"""Explainable numeric hybrid risk scoring."""

RISK_THRESHOLDS = {
    'Normal': 0,
    'Medium': 40,
    'High': 60,
    'Critical': 80,
}


def score_to_risk(score):
    score = int(max(0, min(100, score)))
    if score >= RISK_THRESHOLDS['Critical']:
        return 'Critical'
    if score >= RISK_THRESHOLDS['High']:
        return 'High'
    if score >= RISK_THRESHOLDS['Medium']:
        return 'Medium'
    return 'Normal'


def ml_score_to_risk(ml_score):
    """Backward-compatible alias for historical callers."""
    return score_to_risk(ml_score or 0)


def calculate_hybrid(rule_result, anomaly_assessment):
    """Calculate rule, anomaly and final scores with explicit weighting."""
    rule_score = int(max(0, min(100, rule_result.get('rule_score', 0))))
    anomaly_score = anomaly_assessment.get('anomaly_score')
    confidence = anomaly_assessment.get('model_confidence', 'insufficient')
    method = anomaly_assessment.get('anomaly_method', 'rules_only')

    weights = {
        'high': (0.65, 0.35),
        'medium': (0.75, 0.25),
        'low': (0.85, 0.15),
        'insufficient': (1.0, 0.0),
        'unverified': (1.0, 0.0),
    }
    rule_weight, anomaly_weight = weights.get(confidence, (0.85, 0.15))
    if anomaly_score is None or method == 'rules_only':
        anomaly_weight = 0.0
        rule_weight = 1.0
    weighted_score = round(
        rule_score * rule_weight + (anomaly_score or 0) * anomaly_weight
    )

    minimum_score = RISK_THRESHOLDS.get(rule_result.get('severity', 'Normal'), 0)
    override = None
    final_score = weighted_score
    if final_score < minimum_score:
        override = {
            'applied': True,
            'reason': (
                f"Triggered deterministic rules require at least "
                f"{rule_result.get('severity', 'Normal')} risk."
            ),
            'minimum_score': minimum_score,
            'score_before_override': weighted_score,
        }
        final_score = minimum_score

    final_score = int(max(0, min(100, final_score)))
    final_risk = score_to_risk(final_score)
    return {
        'rule_score': rule_score,
        'anomaly_score': anomaly_score,
        'rule_weight': rule_weight,
        'anomaly_weight': anomaly_weight,
        'weighted_score_before_override': weighted_score,
        'final_hybrid_score': final_score,
        'final_risk_level': final_risk,
        'minimum_risk_override': override,
        'human_review_required': final_risk in ('Medium', 'High', 'Critical'),
        'calculation': (
            f"round({rule_score} × {rule_weight:.2f} + "
            f"{anomaly_score if anomaly_score is not None else 0} × {anomaly_weight:.2f})"
            + (f"; minimum override → {minimum_score}" if override else '')
            + f" = {final_score}"
        ),
    }


def combine(rule_severity, ml_score):
    """Legacy risk-level API retained for external callers."""
    minimum = RISK_THRESHOLDS.get(rule_severity, 0)
    return score_to_risk(max(minimum, int(ml_score or 0)))


def should_create_alert(final_risk_level):
    return final_risk_level in ('Medium', 'High', 'Critical')


def build_alert_reason(user, record, rule_result, anomaly_assessment, hybrid_result):
    rules = rule_result.get('triggered_rules', [])
    rules_str = ', '.join(rules) if rules else 'none'
    record_info = ''
    if record:
        record_info = (
            f"accessed {record.get('record_category', 'unknown')} "
            f"({record.get('sensitivity_level', 'unknown')} sensitivity) record "
            f"(ID: {record.get('id', 'N/A')})"
        )
    anomaly = anomaly_assessment.get('anomaly_score')
    anomaly_text = (
        f'{anomaly}/100 via {anomaly_assessment.get("anomaly_method")}'
        if anomaly is not None else 'not available; rules-only assessment'
    )
    return (
        f"{user['role']} ({user['username']}) from {user['department']} department "
        f"{record_info}. Rule triggers: {rules_str}. "
        f"Rule score: {hybrid_result['rule_score']}/100. "
        f"Behavioural anomaly score: {anomaly_text}. "
        f"Hybrid calculation: {hybrid_result['calculation']}. "
        f"Final risk: {hybrid_result['final_risk_level']}. "
        'Human administrator review is required; scores do not determine malicious intent.'
    )
