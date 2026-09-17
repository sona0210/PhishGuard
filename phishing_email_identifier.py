# PhishGuard - Phishing Email Identifier


def analyze_email(email_text):
    suspicious_keywords = [
        "urgent",
        "verify your account",
        "click here",
        "password",
        "otp",
        "account suspended",
        "winner",
        "claim now",
        "limited time",
        "confirm your identity"
    ]

    suspicious_signs = []
    risk_score = 0

    email_lower = email_text.lower()

    # Check suspicious keywords
    for keyword in suspicious_keywords:
        if keyword in email_lower:
            suspicious_signs.append(
                f"Suspicious keyword found: {keyword}"
            )
            risk_score += 10

    # Check for links
    if "http://" in email_lower or "https://" in email_lower:
        suspicious_signs.append("Email contains a link.")
        risk_score += 15

    # Check for urgent language
    urgent_words = ["immediately", "asap", "within 24 hours", "urgent"]

    for word in urgent_words:
        if word in email_lower:
            suspicious_signs.append(
                f"Urgent language detected: {word}"
            )
            risk_score += 10
            break

    # Check for sensitive information requests
    sensitive_words = [
        "password",
        "otp",
        "credit card",
        "bank details",
        "login details"
    ]

    for word in sensitive_words:
        if word in email_lower:
            suspicious_signs.append(
                f"Sensitive information requested: {word}"
            )
            risk_score += 20
            break

    # Limit score to 100
    risk_score = min(risk_score, 100)

    return suspicious_signs, risk_score


print("=" * 55)
print("                 🛡 PHISHGUARD")
print("=" * 55)
print("Phishing Email Identifier")
print("-" * 55)

email_text = input("Paste the email content: ")

signs, score = analyze_email(email_text)

print("\n--- Security Analysis ---")

if signs:
    for sign in signs:
        print("⚠", sign)
else:
    print("✓ No obvious suspicious signs detected.")

print("\n--- Risk Assessment ---")
print("Risk Score:", score, "/ 100")

if score >= 70:
    risk_level = "HIGH RISK"
elif score >= 40:
    risk_level = "MEDIUM RISK"
else:
    risk_level = "LOW RISK"

print("Risk Level:", risk_level)

print("\n--- Safety Advice ---")

if score >= 40:
    print("→ Do not click unknown links.")
    print("→ Do not share passwords or OTPs.")
    print("→ Verify the sender through an official website.")
else:
    print("→ Still verify the sender before taking action.")
    print("→ Avoid sharing sensitive information.")

print("\n" + "=" * 55)
print("             ANALYSIS COMPLETED")
print("=" * 55)