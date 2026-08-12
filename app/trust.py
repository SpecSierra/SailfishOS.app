"""
Discourse-style trust levels.

Regular ("user" role) accounts gain additional abilities as they mature:
both account age *and* contribution (number of submitted reports) are
required to reach each level. Moderators and admins are unaffected — their
role already grants their permissions.

    Level          Requirement (age + reports)   Unlocks (in addition to lower)
    -------------   ---------------------------   ------------------------------
    0  New          day 0                         submit reports (base role)
    1  Basic        2 days   + 1 report           submit new apps
    2  Member       15 days  + 5 reports          edit apps, refresh app info
    3  Regular      60 days  + 20 reports          edit/delete others' reports

Legacy accounts with no recorded signup date (``created_at is None``) are
grandfathered straight to the top level.
"""
from datetime import datetime

from flask import has_app_context

from app.permissions import (
    CAN_ADD_APP, CAN_EDIT_APP, CAN_REFRESH_PLAYSTORE, CAN_DELETE_REPORT,
)

# Trust level identifiers
TRUST_LEVEL_NEW = 0
TRUST_LEVEL_BASIC = 1
TRUST_LEVEL_MEMBER = 2
TRUST_LEVEL_REGULAR = 3
MAX_TRUST_LEVEL = TRUST_LEVEL_REGULAR

TRUST_LEVEL_NAMES = {
    TRUST_LEVEL_NEW: 'New',
    TRUST_LEVEL_BASIC: 'Basic',
    TRUST_LEVEL_MEMBER: 'Member',
    TRUST_LEVEL_REGULAR: 'Regular',
}

# Requirements to REACH each level. Must be monotonically increasing so the
# ladder can stop at the first unmet level.
TRUST_LEVEL_REQUIREMENTS = {
    TRUST_LEVEL_BASIC: {'age_days': 2, 'reports': 1},
    TRUST_LEVEL_MEMBER: {'age_days': 15, 'reports': 5},
    TRUST_LEVEL_REGULAR: {'age_days': 60, 'reports': 20},
}

# Permissions granted AT each level (in addition to all lower levels). The
# base "user" role already grants CAN_ADD_REPORT, so level 0 adds nothing.
TRUST_LEVEL_PERMISSIONS = {
    TRUST_LEVEL_NEW: frozenset(),
    TRUST_LEVEL_BASIC: frozenset({CAN_ADD_APP}),
    TRUST_LEVEL_MEMBER: frozenset({CAN_EDIT_APP, CAN_REFRESH_PLAYSTORE}),
    TRUST_LEVEL_REGULAR: frozenset({CAN_DELETE_REPORT}),
}


def _parse_dt(value):
    """Parse an ISO-8601 timestamp; return None if unparseable."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def account_age_days(created_at):
    """
    Age of an account in whole days from its ISO signup timestamp.

    Returns None when the timestamp is missing/invalid (grandfathered).
    """
    dt = _parse_dt(created_at)
    if dt is None:
        return None
    return max(0, (datetime.utcnow() - dt).days)


def compute_trust_level(created_at, reports_count):
    """
    Compute a trust level from account age and report count.

    A missing signup date is treated as grandfathered -> top level.
    """
    age = account_age_days(created_at)
    if age is None:
        return MAX_TRUST_LEVEL

    level = TRUST_LEVEL_NEW
    for candidate in (TRUST_LEVEL_BASIC, TRUST_LEVEL_MEMBER, TRUST_LEVEL_REGULAR):
        req = TRUST_LEVEL_REQUIREMENTS[candidate]
        if age >= req['age_days'] and reports_count >= req['reports']:
            level = candidate
        else:
            break
    return level


def _user_reports_count(user):
    """Number of reports submitted by a user (0 outside an app context)."""
    if not has_app_context():
        return 0
    try:
        from app.models import DataManager
        return len(DataManager.get_reports_for_user(user.id))
    except Exception:
        return 0


def get_user_trust_level(user):
    """
    Effective trust level for a user, cached on the user object per request.

    Only the plain "user" role progresses; other roles return MAX_TRUST_LEVEL
    (their role already grants their permissions).
    """
    if user is None or not getattr(user, 'is_authenticated', False):
        return TRUST_LEVEL_NEW

    if getattr(user, 'role', None) != 'user':
        return MAX_TRUST_LEVEL

    cached = getattr(user, '_trust_level', None)
    if cached is not None:
        return cached

    created_at = getattr(user, 'created_at', None)
    if created_at is None:
        level = MAX_TRUST_LEVEL  # grandfathered legacy account
    else:
        level = compute_trust_level(created_at, _user_reports_count(user))

    try:
        user._trust_level = level
    except (AttributeError, TypeError):
        pass
    return level


def get_trust_permissions_up_to(level):
    """Union of all trust permissions granted up to and including ``level``."""
    perms = set()
    for lvl in range(TRUST_LEVEL_NEW, level + 1):
        perms |= TRUST_LEVEL_PERMISSIONS.get(lvl, frozenset())
    return perms


def get_user_trust_permissions(user):
    """Extra permissions a user has earned through trust progression."""
    return get_trust_permissions_up_to(get_user_trust_level(user))


def trust_level_from_count(user, reports_count):
    """
    Trust level for a user given a pre-computed report count.

    Avoids a per-user data lookup (use when scoring many users at once, e.g.
    the admin user list). Returns None for roles that don't use trust
    progression (moderator/admin).
    """
    if getattr(user, 'role', None) != 'user':
        return None
    created_at = getattr(user, 'created_at', None)
    if created_at is None:
        return MAX_TRUST_LEVEL  # grandfathered legacy account
    return compute_trust_level(created_at, reports_count)


def get_trust_level_name(level):
    """Human-readable name for a trust level."""
    return TRUST_LEVEL_NAMES.get(level, str(level))


def get_next_level_progress(user):
    """
    Progress toward the next trust level, for display on the profile page.

    Returns None if the user is already at the top level or does not use the
    trust system, otherwise a dict describing current standing and the
    requirements for the next level.
    """
    if getattr(user, 'role', None) != 'user':
        return None

    level = get_user_trust_level(user)
    if level >= MAX_TRUST_LEVEL:
        return None

    next_level = level + 1
    req = TRUST_LEVEL_REQUIREMENTS[next_level]
    age = account_age_days(getattr(user, 'created_at', None)) or 0
    reports = _user_reports_count(user)

    return {
        'current_level': level,
        'current_level_name': get_trust_level_name(level),
        'next_level': next_level,
        'next_level_name': get_trust_level_name(next_level),
        'age_days': age,
        'age_required': req['age_days'],
        'reports': reports,
        'reports_required': req['reports'],
    }
