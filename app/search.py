"""
Relevance-ranked, typo-tolerant search for the app catalogue.

The public homepage search used to be a plain case-sensitive-ish substring
match on name + description. This module upgrades it to:

- diacritic-insensitive matching ("cesko" matches "Česko")
- multiple searchable fields (name, package, native app names, category,
  description)
- multi-word queries with AND semantics (every term must match somewhere)
- fuzzy / typo tolerance ("whatsap" matches "WhatsApp", "signl" -> "Signal")
- relevance scoring so the best matches float to the top (an exact name
  match outranks a stray word buried in a description, which outranks a
  fuzzy near-miss)

It is deliberately dependency-free (stdlib ``difflib`` only): the catalogue
is small enough that scoring in Python per request is fine.
"""
import re
from difflib import SequenceMatcher

from app.utils import normalize_for_sort

# Split normalized text into alphanumeric word tokens (package dots become
# word boundaries, so "com.whatsapp" yields ["com", "whatsapp"]).
_WORD_RE = re.compile(r'[a-z0-9]+')

# Similarity (0..1) required to accept a fuzzy word match. 0.82 accepts a
# single typo in a medium-length word while rejecting unrelated words.
FUZZY_THRESHOLD = 0.82

# Only attempt fuzzy matching for tokens at least this long; short tokens
# produce too many spurious near-matches.
FUZZY_MIN_LEN = 4


def _words(text):
    return _WORD_RE.findall(text)


def _searchable_fields(app, category_map=None):
    """Build the normalized, searchable text (and word lists) for an app."""
    native_names = []
    if app.get('native_name'):
        native_names.append(app['native_name'])
    for na in app.get('additional_native_apps', []) or []:
        name = na.get('name') if isinstance(na, dict) else None
        if name:
            native_names.append(name)

    category_name = ''
    if category_map:
        category = category_map.get(app.get('category'))
        if category:
            category_name = category.get('name', '')

    name = normalize_for_sort(app.get('android_name', ''))
    # Package names are ASCII; lowercase is enough and keeps dots intact
    package = (app.get('android_package', '') or '').lower()
    native = normalize_for_sort(' '.join(native_names))
    category = normalize_for_sort(category_name)
    description = normalize_for_sort(app.get('android_description', ''))

    name_words = _words(name)
    return {
        'name': name,
        'package': package,
        'native': native,
        'category': category,
        'description': description,
        'name_words': name_words,
        # Words we allow fuzzy matching against: the visible identity of the
        # app (name + native app names + package segments). Descriptions are
        # excluded to avoid fuzzy noise from long marketing copy.
        'fuzzy_words': name_words + _words(native) + _words(package),
    }


def _best_ratio(token, words):
    """Best fuzzy similarity of ``token`` against a list of words."""
    best = 0.0
    tlen = len(token)
    for word in words:
        # Length gate: a match within threshold can't differ by many chars
        if abs(len(word) - tlen) > 2:
            continue
        ratio = SequenceMatcher(None, token, word).ratio()
        if ratio > best:
            best = ratio
            if best == 1.0:
                break
    return best


def score_app(fields, tokens, norm_query):
    """
    Score a single app's fields against the query.

    Returns 0 when the app does not match (i.e. some query term is satisfied
    by neither a substring nor a close fuzzy match), otherwise a positive
    relevance score where higher is better.
    """
    name = fields['name']
    package = fields['package']
    native = fields['native']
    category = fields['category']
    description = fields['description']
    name_words = fields['name_words']

    haystack = ' '.join((name, package, native, category, description))

    score = 0

    # Whole-query bonuses, strongest signal first (name matches dominate)
    if norm_query:
        if name == norm_query:
            score += 100          # exact name match
        elif name.startswith(norm_query):
            score += 60           # name starts with the query
        elif norm_query in name:
            score += 40           # query appears anywhere in the name
        if norm_query in package:
            score += 25
        if norm_query in native:
            score += 20
        if norm_query in category:
            score += 10

    # Per-term scoring. Every term must be satisfied (AND) by an exact
    # substring hit or, failing that, a close fuzzy word match.
    for token in tokens:
        satisfied = False

        if token in name:
            score += 12
            satisfied = True
            if token in name_words:
                score += 8        # whole-word match in the name
        if token in package:
            score += 6
            satisfied = True
        if token in native:
            score += 5
            satisfied = True
        if token in category:
            score += 4
            satisfied = True
        if token in description:
            score += 2
            satisfied = True

        if not satisfied and len(token) >= FUZZY_MIN_LEN:
            ratio = _best_ratio(token, fields['fuzzy_words'])
            if ratio >= FUZZY_THRESHOLD:
                # Fuzzy hits score below any exact hit and scale with closeness
                score += int(10 * ratio)
                satisfied = True

        if not satisfied:
            return 0

    return score


def search_apps(apps, query, category_map=None):
    """
    Score a list of apps against a query string.

    Args:
        apps: iterable of app dicts
        query: the raw search string
        category_map: optional {slug: category} for matching category names

    Returns:
        dict of {app_id: score} containing only apps that matched (score > 0).
        An empty/whitespace query returns an empty dict (caller decides how to
        treat "no query").
    """
    norm_query = normalize_for_sort(query or '').strip()
    tokens = [t for t in norm_query.split() if t]
    if not tokens:
        return {}

    scores = {}
    for app in apps:
        fields = _searchable_fields(app, category_map)
        score = score_app(fields, tokens, norm_query)
        if score > 0:
            scores[app['id']] = score
    return scores
