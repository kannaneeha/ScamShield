import app_core

def check(text, expected):
    result = app_core.analyze_message_core(text)
    assert expected in [f["id"] for f in result["red_flags"]], result
    print("PASS:", expected, "|", [f["label"] for f in result["red_flags"]])

check(
    "URGENT: Your SBI account will be blocked today. Verify your KYC immediately and send OTP.",
    "urgency"
)
check(
    "Congratulations! You won a prize. Pay a processing fee now to claim your reward.",
    "financial_request"
)

u = app_core.analyze_one_url("http://sbi-kyc-update.xyz/login")
assert u["score"] > 0 and u["findings"]
print("PASS: URL analysis |", u)

print("Deterministic ScamShield checks passed.")
