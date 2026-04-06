import math

COMMON_PASSWORDS = [
    "123456", "password", "admin", "qwerty",
    "12345678", "abc123", "letmein"
]

# -----------------------------
# Risk Checks
# -----------------------------

def dictionary_risk(password):
    pw = password.lower()
    return any(common in pw for common in COMMON_PASSWORDS)


def pattern_risk(password):
    patterns = ["1234", "abcd", "qwerty", "1111", "0000"]
    pw = password.lower()
    return any(p in pw for p in patterns)


# -----------------------------
# Entropy Calculation
# -----------------------------

def calculate_entropy(password):
    pool = 0

    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32

    if pool == 0:
        return 0

    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)


def brute_force_level(entropy):
    if entropy < 28:
        return "Very Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        return "Moderate"
    else:
        return "Strong"


# -----------------------------
# Recommendations (SHORT + CLEAN)
# -----------------------------

def get_recommendations(password, dict_flag, pattern_flag):
    recs = []

    if len(password) < 12:
        recs.append("Use 12+ characters")

    if not any(c.isupper() for c in password):
        recs.append("Add uppercase")

    if not any(c.islower() for c in password):
        recs.append("Add lowercase")

    if not any(c.isdigit() for c in password):
        recs.append("Add numbers")

    if not any(not c.isalnum() for c in password):
        recs.append("Add symbols")

    if len(set(password)) < len(password) / 2:
        recs.append("Avoid repetition")

    if dict_flag:
        recs.append("Avoid common words")

    if pattern_flag:
        recs.append("Avoid patterns")

    if not recs:
        recs.append("Strong password 👍")

    return recs


# -----------------------------
# Main Analyzer
# -----------------------------

def analyze_password(password):
    dict_flag = dictionary_risk(password)
    pattern_flag = pattern_risk(password)
    entropy = calculate_entropy(password)
    brute_force = brute_force_level(entropy)

    recommendations = get_recommendations(password, dict_flag, pattern_flag)

    return {
        "dictionary_risk": dict_flag,
        "pattern_risk": pattern_flag,
        "entropy": entropy,
        "brute_force_level": brute_force,
        "recommendations": recommendations
    }