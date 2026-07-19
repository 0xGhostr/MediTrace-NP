"""Reproducible behavioural anomaly assessment for staff access events.

Only cybersecurity access metadata is used. Patient diagnoses, demographics,
vitals, medication and clinical text are deliberately excluded.
"""
import bisect
import json
import math
import os
import pickle
import shutil
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from statistics import mean, median, pstdev
from zoneinfo import ZoneInfo

import numpy as np
from sklearn.ensemble import IsolationForest

from config import Config
from database import get_db

MODEL_TYPE = 'IsolationForest'
MODEL_VERSION = 'iforest-behaviour-v2'
RANDOM_SEED = 42
MIN_TRAINING_EVENTS = 50
USER_BASELINE_MIN = 8
GROUP_BASELINE_MIN = 20
GLOBAL_BASELINE_MIN = 30

ROLE_ENCODING = {
    'Super Admin': 0, 'Admin': 0, 'Doctor': 1, 'Nurse': 2,
    'Receptionist': 3, 'Billing Staff': 4, 'Laboratory Staff': 5,
}
ACTION_ENCODING = {'view': 0, 'search': 1, 'export': 2, 'delete_attempt': 3}
SENSITIVITY_ENCODING = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}

FEATURE_NAMES = [
    'hour_sin', 'hour_cos', 'day_of_week', 'role_encoded',
    'department_match', 'is_sensitive', 'recent_access_count',
    'after_hours', 'action_type_encoded', 'sensitivity_level_encoded',
    'records_accessed_today', 'repeated_record_30m',
    'sensitive_accesses_today', 'time_since_previous_log',
    'device_familiarity',
]

_model = None
_load_error = None


def _parse_timestamp(value):
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace('Z', ''))


def _local_timestamp(value):
    timestamp = _parse_timestamp(value)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(ZoneInfo(Config.LOCAL_TIMEZONE))


def _bounded_number(value, default=0.0, low=0.0, high=10000.0):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return float(default)
    if not math.isfinite(number):
        return float(default)
    return min(max(number, low), high)


def _feature_dict(user, record, action_type, context):
    timestamp = _local_timestamp(context.get('timestamp') or datetime.utcnow())
    hour_angle = 2 * math.pi * timestamp.hour / 24.0
    sensitivity = record.get('sensitivity_level', 'Low') if record else 'Low'
    interval = _bounded_number(
        context.get('time_since_previous_minutes', 1440), 1440, 0, 10080,
    )
    return {
        'hour_sin': math.sin(hour_angle),
        'hour_cos': math.cos(hour_angle),
        'day_of_week': timestamp.weekday(),
        'role_encoded': ROLE_ENCODING.get(user.get('role'), -1),
        'department_match': 1 if context.get('department_match', 1) else 0,
        'is_sensitive': 1 if context.get('is_sensitive') else 0,
        'recent_access_count': _bounded_number(context.get('records_last_10_min', 0), high=500),
        'after_hours': 1 if context.get('after_hours') else 0,
        'action_type_encoded': ACTION_ENCODING.get(action_type, -1),
        'sensitivity_level_encoded': SENSITIVITY_ENCODING.get(sensitivity, 0),
        'records_accessed_today': _bounded_number(context.get('records_accessed_today', 0), high=5000),
        'repeated_record_30m': _bounded_number(context.get('repeated_record_30m', 0), high=500),
        'sensitive_accesses_today': _bounded_number(context.get('sensitive_accesses_today', 0), high=5000),
        'time_since_previous_log': math.log1p(interval),
        'device_familiarity': 1 if context.get('device_familiarity') else 0,
    }


def build_feature_vector(user, record, action_type, context):
    """Return the fixed, validated feature vector used for inference."""
    features = _feature_dict(user, record, action_type, context)
    vector = np.asarray([[features[name] for name in FEATURE_NAMES]], dtype=float)
    if vector.shape != (1, len(FEATURE_NAMES)) or not np.isfinite(vector).all():
        raise ValueError('Behavioural feature vector contains invalid values.')
    return vector, features


def _scope_rows(user, timestamp):
    """Choose a historical baseline without including the current event."""
    cutoff = _parse_timestamp(timestamp).isoformat()
    conn = get_db()
    base_sql = '''
        SELECT user_id, role, department, record_id, sensitivity_level,
               action_type, timestamp, computer_name, is_after_hours,
               department_match
        FROM access_events
        WHERE timestamp < ? AND action_type != 'usb_monitor'
    '''
    candidates = [
        ('user', base_sql + ' AND user_id = ? ORDER BY timestamp', (cutoff, user['id']), USER_BASELINE_MIN),
        ('role', base_sql + ' AND role = ? ORDER BY timestamp', (cutoff, user['role']), GROUP_BASELINE_MIN),
        ('department', base_sql + ' AND department = ? ORDER BY timestamp', (cutoff, user['department']), GROUP_BASELINE_MIN),
        ('global', base_sql + ' ORDER BY timestamp', (cutoff,), GLOBAL_BASELINE_MIN),
    ]
    selected_source = 'insufficient_data'
    selected_rows = []
    for source, query, params, minimum in candidates:
        rows = conn.execute(query, params).fetchall()
        if len(rows) >= minimum:
            selected_source = source
            selected_rows = [dict(row) for row in rows]
            break
    conn.close()
    return selected_source, selected_rows


def build_behavioral_baseline(user, action_type, context):
    """Build an explainable user/group baseline from events before this event."""
    source, rows = _scope_rows(user, context.get('timestamp'))
    timestamps = [_local_timestamp(row['timestamp']) for row in rows]
    daily_counts = Counter(
        (row['user_id'], ts.date().isoformat()) for row, ts in zip(rows, timestamps)
    )
    hours = [ts.hour for ts in timestamps]
    days = [ts.weekday() for ts in timestamps]
    actions = Counter(row['action_type'] for row in rows)
    devices = Counter(
        row.get('computer_name') for row in rows
        if row.get('computer_name') and row.get('computer_name') != 'Web session'
    )
    sensitive_daily = Counter()
    for row, ts in zip(rows, timestamps):
        if row.get('sensitivity_level') in ('High', 'Critical'):
            sensitive_daily[(row['user_id'], ts.date().isoformat())] += 1
    timestamps_by_user = defaultdict(list)
    for row, ts in zip(rows, timestamps):
        timestamps_by_user[row['user_id']].append(ts)
    intervals = []
    for user_timestamps in timestamps_by_user.values():
        intervals.extend(
            max((user_timestamps[index] - user_timestamps[index - 1]).total_seconds() / 60.0, 0)
            for index in range(1, len(user_timestamps))
            if user_timestamps[index] >= user_timestamps[index - 1]
        )
    baseline = {
        'source': source,
        'sample_count': len(rows),
        'typical_hour': round(median(hours), 1) if hours else None,
        'hour_std': round(pstdev(hours), 1) if len(hours) > 1 else None,
        'normal_days': [day for day, _ in Counter(days).most_common(5)],
        'typical_daily_access_count': round(mean(daily_counts.values()), 1) if daily_counts else None,
        'typical_sensitive_daily_count': round(mean(sensitive_daily.values()), 1) if sensitive_daily else 0,
        'common_actions': [name for name, _ in actions.most_common(3)],
        'familiar_devices': [name for name, _ in devices.most_common(5)],
        'average_interval_minutes': round(mean(intervals), 1) if intervals else None,
        'assigned_work_schedule': f"{user.get('work_start', 'N/A')}–{user.get('work_end', 'N/A')}",
        'assigned_department': user.get('department'),
    }
    baseline['confidence'] = {
        'user': 'high', 'role': 'medium', 'department': 'medium',
        'global': 'low', 'insufficient_data': 'insufficient',
    }[source]
    baseline['deviations'] = _describe_deviations(
        user, action_type, context, baseline,
    )
    return baseline


def _add_deviation(output, feature, observed, expected, points, description):
    output.append({
        'feature': feature,
        'observed': observed,
        'expected': expected,
        'deviation_points': points,
        'description': description,
    })


def _describe_deviations(user, action_type, context, baseline):
    deviations = []
    timestamp = _local_timestamp(context.get('timestamp'))
    if context.get('after_hours'):
        _add_deviation(
            deviations, 'working_hours', timestamp.strftime('%H:%M'),
            baseline['assigned_work_schedule'], 25,
            'Access occurred outside the staff member’s assigned work schedule.',
        )
    if not context.get('department_match', 1):
        _add_deviation(
            deviations, 'department_match', 'cross-department',
            baseline['assigned_department'], 20,
            'The record department differs from the staff member’s assigned department.',
        )
    if baseline['typical_hour'] is not None:
        distance = abs(timestamp.hour - baseline['typical_hour'])
        distance = min(distance, 24 - distance)
        tolerance = max((baseline['hour_std'] or 1.5) * 2, 3)
        if distance > tolerance:
            _add_deviation(
                deviations, 'access_hour', timestamp.hour, baseline['typical_hour'], 10,
                'Access time is outside the usual historical hour range.',
            )
    if baseline['normal_days'] and timestamp.weekday() not in baseline['normal_days']:
        _add_deviation(
            deviations, 'day_of_week', timestamp.strftime('%A'),
            baseline['normal_days'], 8, 'This weekday is uncommon in the selected baseline.',
        )
    typical_daily = baseline['typical_daily_access_count']
    today = int(context.get('records_accessed_today', 0))
    if typical_daily is not None and today + 1 > max(5, typical_daily * 2):
        points = min(20, 8 + int((today + 1 - typical_daily) / max(typical_daily, 1) * 6))
        _add_deviation(
            deviations, 'daily_access_volume', today + 1, typical_daily, points,
            'Current daily access volume is substantially above the selected baseline.',
        )
    if baseline['common_actions'] and action_type not in baseline['common_actions']:
        _add_deviation(
            deviations, 'action_type', action_type, baseline['common_actions'], 10,
            'This action is uncommon for the selected baseline.',
        )
    if baseline['familiar_devices'] and not context.get('device_familiarity'):
        _add_deviation(
            deviations, 'device_familiarity', context.get('computer_name', 'Web session'),
            baseline['familiar_devices'], 10, 'The PC or session label has not appeared in the baseline.',
        )
    expected_sensitive = baseline['typical_sensitive_daily_count'] or 0
    observed_sensitive = int(context.get('sensitive_accesses_today', 0)) + (1 if context.get('is_sensitive') else 0)
    if observed_sensitive > expected_sensitive + 2:
        _add_deviation(
            deviations, 'sensitive_access_volume', observed_sensitive,
            expected_sensitive, 12,
            'Sensitive-record access volume exceeds the historical baseline.',
        )
    average_interval = baseline['average_interval_minutes']
    observed_interval = context.get('time_since_previous_minutes')
    if average_interval and observed_interval is not None and observed_interval < max(1, average_interval / 4):
        _add_deviation(
            deviations, 'access_interval_minutes', round(observed_interval, 1),
            average_interval, 10, 'Events are occurring much faster than the selected baseline.',
        )
    return deviations


def _validate_bundle(bundle):
    required = {'model', 'feature_names', 'calibration_scores', 'metadata'}
    if not isinstance(bundle, dict) or not required.issubset(bundle):
        raise ValueError('Model artifact is missing required metadata.')
    if bundle['metadata'].get('model_version') != MODEL_VERSION:
        raise ValueError('Model artifact version is not compatible with this scoring pipeline.')
    if bundle['feature_names'] != FEATURE_NAMES:
        raise ValueError('Saved model feature order does not match inference feature order.')
    calibration = np.asarray(bundle['calibration_scores'], dtype=float)
    if not len(calibration) or not np.isfinite(calibration).all():
        raise ValueError('Model calibration scores are invalid.')
    return bundle


def load_model(path=None):
    """Load a compatible model. Missing/invalid artifacts never auto-train."""
    global _model, _load_error
    path = path or Config.ML_MODEL_PATH
    if not os.path.exists(path):
        _model = None
        _load_error = 'No trained behavioural model artifact is available.'
        return None
    try:
        with open(path, 'rb') as handle:
            bundle = _validate_bundle(pickle.load(handle))
    except Exception as exc:
        _model = None
        _load_error = str(exc)
        return None
    _model = bundle
    _load_error = None
    return bundle


def _historical_training_matrix():
    conn = get_db()
    rows = [dict(row) for row in conn.execute(
        '''
        SELECT user_id, role, department, record_id, sensitivity_level,
               action_type, timestamp, computer_name, is_after_hours,
               is_sensitive, department_match
        FROM access_events
        WHERE action_type != 'usb_monitor'
        ORDER BY timestamp, id
        '''
    ).fetchall()]
    conn.close()
    histories = defaultdict(list)
    vectors = []
    for row in rows:
        timestamp = _parse_timestamp(row['timestamp'])
        history = histories[row['user_id']]
        recent = [item for item in history if item['timestamp'] >= timestamp - timedelta(minutes=10)]
        recent_record = [
            item for item in history
            if item['timestamp'] >= timestamp - timedelta(minutes=30)
            and item.get('record_id') == row.get('record_id')
        ]
        local_date = _local_timestamp(timestamp).date()
        today = [
            item for item in history
            if _local_timestamp(item['timestamp']).date() == local_date
        ]
        previous = history[-1]['timestamp'] if history else None
        device_seen = any(
            item.get('computer_name') == row.get('computer_name')
            for item in history if row.get('computer_name')
        )
        context = {
            'timestamp': timestamp,
            'department_match': row.get('department_match', 1),
            'is_sensitive': row.get('is_sensitive', 0),
            'after_hours': row.get('is_after_hours', 0),
            'records_last_10_min': len(recent),
            'records_accessed_today': len(today),
            'repeated_record_30m': len(recent_record),
            'sensitive_accesses_today': sum(item.get('is_sensitive', 0) for item in today),
            'time_since_previous_minutes': (
                (timestamp - previous).total_seconds() / 60.0 if previous else 1440
            ),
            'device_familiarity': device_seen,
        }
        user = {'role': row.get('role')}
        record = {'sensitivity_level': row.get('sensitivity_level') or 'Low'}
        features = _feature_dict(user, record, row.get('action_type'), context)
        vectors.append([features[name] for name in FEATURE_NAMES])
        historical = dict(row)
        historical['timestamp'] = timestamp
        history.append(historical)
    matrix = np.asarray(vectors, dtype=float)
    if matrix.ndim != 2 or matrix.shape[1] != len(FEATURE_NAMES) or not np.isfinite(matrix).all():
        raise ValueError('Historical training features are invalid or non-finite.')
    return matrix


def _record_model_run(metadata, trained_by, status, error_message=None):
    conn = get_db()
    conn.execute(
        '''
        INSERT INTO model_runs (
            model_type, model_version, trained_at, training_events,
            feature_names, parameters, random_seed, baseline_scope,
            validation_summary, artifact_path, trained_by, status, error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            metadata.get('model_type', MODEL_TYPE),
            metadata.get('model_version', MODEL_VERSION),
            metadata.get('trained_at', datetime.utcnow().isoformat()),
            metadata.get('training_events', 0), json.dumps(FEATURE_NAMES),
            json.dumps(metadata.get('parameters', {}), sort_keys=True), RANDOM_SEED,
            metadata.get('baseline_scope', 'global historical access events'),
            json.dumps(metadata.get('validation_summary', {}), sort_keys=True),
            metadata.get('artifact_path', Config.ML_MODEL_PATH), trained_by,
            status, str(error_message)[:1000] if error_message else None,
        ),
    )
    conn.commit()
    conn.close()


def train_and_save_model(path=None, trained_by=None):
    """Train once on historical behaviour and atomically replace the artifact."""
    global _model, _load_error
    path = path or Config.ML_MODEL_PATH
    trained_at = datetime.utcnow().isoformat()
    metadata = {
        'model_type': MODEL_TYPE,
        'model_version': MODEL_VERSION,
        'trained_at': trained_at,
        'training_events': 0,
        'parameters': {
            'n_estimators': 200, 'contamination': 0.08,
            'random_state': RANDOM_SEED,
        },
        'baseline_scope': 'global historical access events; current event excluded',
        'artifact_path': path,
    }
    previous_model = _model
    temporary_path = None
    try:
        matrix = _historical_training_matrix()
        metadata['training_events'] = int(matrix.shape[0])
        if matrix.shape[0] < MIN_TRAINING_EVENTS:
            raise ValueError(
                f'At least {MIN_TRAINING_EVENTS} historical access events are required; '
                f'found {matrix.shape[0]}.'
            )
        model = IsolationForest(
            n_estimators=200, contamination=0.08,
            random_state=RANDOM_SEED, n_jobs=1,
        )
        model.fit(matrix)
        raw_anomaly = -model.decision_function(matrix)
        predictions = model.predict(matrix)
        if not np.isfinite(raw_anomaly).all():
            raise ValueError('Model produced non-finite calibration scores.')
        calibration = sorted(float(value) for value in raw_anomaly)
        metadata['validation_summary'] = {
            'finite_features': True,
            'feature_count': len(FEATURE_NAMES),
            'training_outlier_rate': round(float(np.mean(predictions == -1)), 4),
            'raw_anomaly_min': round(float(np.min(raw_anomaly)), 8),
            'raw_anomaly_median': round(float(np.median(raw_anomaly)), 8),
            'raw_anomaly_max': round(float(np.max(raw_anomaly)), 8),
            'normalization': 'empirical percentile of training anomaly outputs',
        }
        bundle = {
            'model': model,
            'feature_names': list(FEATURE_NAMES),
            'calibration_scores': calibration,
            'metadata': metadata,
            'encodings': {
                'role': ROLE_ENCODING, 'action': ACTION_ENCODING,
                'sensitivity': SENSITIVITY_ENCODING,
            },
        }
        _validate_bundle(bundle)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        descriptor, temporary_path = tempfile.mkstemp(
            prefix='behaviour-model-', suffix='.pkl', dir=os.path.dirname(path),
        )
        os.close(descriptor)
        with open(temporary_path, 'wb') as handle:
            pickle.dump(bundle, handle)
        with open(temporary_path, 'rb') as handle:
            _validate_bundle(pickle.load(handle))
        if os.path.exists(path):
            shutil.copy2(path, f'{path}.previous')
        os.replace(temporary_path, path)
        temporary_path = None
        _model = bundle
        _load_error = None
        _record_model_run(metadata, trained_by, 'success')
        return metadata
    except Exception as exc:
        _model = previous_model
        _load_error = str(exc) if previous_model is None else _load_error
        try:
            _record_model_run(metadata, trained_by, 'failed', exc)
        except Exception:
            pass
        raise
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.remove(temporary_path)


def _percentile_score(raw_anomaly, calibration_scores):
    position = bisect.bisect_right(calibration_scores, raw_anomaly)
    return int(round(100 * position / len(calibration_scores)))


def assess_event(user, record, action_type, context):
    """Return actual model output plus baseline deviations and confidence."""
    global _model
    baseline = build_behavioral_baseline(user, action_type, context)
    vector, features = build_feature_vector(user, record, action_type, context)
    bundle = _model if _model is not None else load_model()
    result = {
        'anomaly_score': None,
        'anomaly_method': 'rules_only',
        'model_version': None,
        'model_raw_score': None,
        'model_prediction': None,
        'model_confidence': baseline['confidence'],
        'baseline_source': baseline['source'],
        'baseline': baseline,
        'behavioural_deviations': baseline['deviations'],
        'features': features,
        'model_available': False,
        'model_error': _load_error,
        'score_interpretation': (
            'No compatible model was available; deterministic rules remain authoritative.'
        ),
    }
    if bundle is not None:
        raw_decision = float(bundle['model'].decision_function(vector)[0])
        raw_anomaly = -raw_decision
        prediction = int(bundle['model'].predict(vector)[0])
        result.update({
            'anomaly_score': _percentile_score(raw_anomaly, bundle['calibration_scores']),
            'anomaly_method': 'isolation_forest',
            'model_version': bundle['metadata']['model_version'],
            'model_raw_score': round(raw_decision, 8),
            'model_prediction': prediction,
            'model_available': True,
            'model_error': None,
            'score_interpretation': (
                'Relative anomaly percentile against model training outputs; '
                'it is not a probability of malicious intent.'
            ),
        })
    elif baseline['source'] != 'insufficient_data':
        result.update({
            'anomaly_score': min(100, sum(
                item['deviation_points'] for item in baseline['deviations']
            )),
            'anomaly_method': 'statistical_baseline',
            'score_interpretation': (
                'Transparent sum of documented baseline-deviation points; no ML model was used.'
            ),
        })
    return result


def score_event(user, record, action_type, context):
    """Backward-compatible numeric accessor; prefer :func:`assess_event`."""
    assessment = assess_event(user, record, action_type, context)
    return assessment['anomaly_score'] or 0


def get_model_status():
    bundle = _model if _model is not None else load_model()
    conn = get_db()
    latest = conn.execute(
        'SELECT * FROM model_runs ORDER BY trained_at DESC, id DESC LIMIT 1'
    ).fetchone()
    conn.close()
    return {
        'available': bundle is not None,
        'load_error': _load_error,
        'metadata': bundle.get('metadata') if bundle else None,
        'latest_run': dict(latest) if latest else None,
        'minimum_training_events': MIN_TRAINING_EVENTS,
        'artifact_path': Config.ML_MODEL_PATH,
    }
