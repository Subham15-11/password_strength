import re
import math
import hashlib
import requests

# import random
import secrets  # for cryptographically secure password generation
import string
import streamlit as st


# some common passwords for basic checking
COMMON_PASSWORDS = {"password", "123456", "qwerty", "admin", "password123"}


# ---------- Password Strength Checker ----------
class PasswordChecker:
    def __init__(self, password):
        self.password = password

    def entropy_score(self):
        pool = 0
        if re.search(r"[a-z]", self.password):
            pool += 26  # English alphabet has 26 lowercase letters

        if re.search(r"[A-Z]", self.password):
            pool += 26  # English alphabet has 26 uppercase letters

        if re.search(r"\d", self.password):
            pool += 10  # Digits 0-9 totla 10 characters

        if re.search(r"""[!@#$%^&*(),.?\":{}|<>]""", self.password):
            pool += 32  # Common special characters totla 32 characters

        if pool == 0:
            return 0

        return round(len(self.password) * math.log2(pool), 2)

    def crack_time_estimate(self):
        guesses_per_sec = 1e9  # 1 billion guesses/sec
        entropy = self.entropy_score()
        seconds = 2**entropy / guesses_per_sec

        if seconds < 60:
            return "Seconds"
        elif seconds < 3600:
            return "Minutes"
        elif seconds < 86400:
            return "Hours"
        elif seconds < 31536000:
            return "Days"
        else:
            return "Years+"

    # Check password against HIBP database using k-Anonymity model.
    # It is part of the Have I Been Pwned (HIBP) Passwords API, created by Troy Hunt.
    def hibp_check(self):
        sha1 = hashlib.sha1(self.password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)

        for line in res.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return True, int(count)

        return False, 0

    def check_strength(self):
        score = 0
        checks = {
            "At least 8 characters": len(self.password) >= 8,
            "Uppercase letter": bool(re.search(r"[A-Z]", self.password)),
            "Lowercase letter": bool(re.search(r"[a-z]", self.password)),
            "Digit": bool(re.search(r"\d", self.password)),
            "Special character": bool(
                re.search(r"[!@#$%^&*(),.?\":{}|<>]", self.password)
            ),
            "Not a common password": self.password.lower() not in COMMON_PASSWORDS,
        }

        score = sum(checks.values())  # each passed check adds 1 to score

        breached, count = self.hibp_check()
        if breached:
            checks["Not found in data breaches"] = False
        else:
            checks["Not found in data breaches"] = True
            score += 1

        if score <= 3:
            strength, color = "Weak", "red"
        elif score <= 6:
            strength, color = "Medium", "orange"
        else:
            strength, color = "Strong", "green"

        return strength, color, checks, breached, count


# ---------- Password Generator ----------
def generate_password(length=14):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(chars) for _ in range(length))


# ---------- Streamlit UI ----------
st.set_page_config(page_title="Password Security Analyzer", page_icon="🔐")
st.title("🔐 Password Security Analyzer")


# ---- Input ----
def on_password_change():
    st.session_state.live_password = st.session_state.password


st.text_input(
    "Enter Password",
    type="password",
    key="password",
    on_change=on_password_change,  # REAL-TIME
)

password = st.session_state.get("live_password", "")


st.caption("🔒 Your password is never stored & sent directly.")


# ---- Password Generation ----
col1, col2 = st.columns(2)
with col1:
    if st.button("Generate Strong Password"):
        st.session_state.generated = generate_password()

with col2:
    if "generated" in st.session_state:
        st.code(st.session_state.generated)

# ⚠ Reuse Warning (NEW)
if "generated" in st.session_state and password:
    if password == st.session_state.generated:
        st.warning("⚠ You are reusing the generated password")


# ---- Strength Check ----
if password:
    checker = PasswordChecker(password)
    strength, color, checks, breached, count = checker.check_strength()
    entropy = checker.entropy_score()
    crack_time = checker.crack_time_estimate()

    st.markdown(
        f"## Strength: <span style='color:{color}'>{strength}</span>",
        unsafe_allow_html=True,
    )

    # Progress Bar (Improved)
    progress = sum(checks.values()) / len(checks)
    st.progress(progress)

    # ✔ Security Checklist
    st.subheader("✔ Security Checklist")
    for rule, passed in checks.items():
        st.write(("✅" if passed else "❌"), rule)

    # ⏱ Crack Time
    st.subheader("⏱ Estimated Crack Time")
    st.write(f"**{crack_time}**")

    # Strength Explanation
    strength_desc = {
        "Weak": "❌ Easily guessable. Do NOT use.",
        "Medium": "⚠️ Acceptable but can be improved.",
        "Strong": "✅ Secure and recommended.",
    }
    st.info(strength_desc[strength])

    # 🔢 Entropy Score
    st.subheader("🔢 Entropy Score")
    st.write(f"**{entropy} bits** (Higher = harder to crack)")

    # 🔓 HIBP Breach Check
    if breached:
        st.error(f"⚠ Found in data breaches **{count} times**")
    else:
        st.success("✅ No breach record found")

# ---------- Footer ----------
st.divider()
st.caption("Built with ❤️ using Python & Streamlit")

# End of file
# https://passwords-strength.streamlit.app/