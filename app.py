import streamlit as st
from analyzer import analyze_password

st.set_page_config(page_title="Password Analyzer", layout="centered")

st.title(" Password Security Analyzer")

password = st.text_input("Enter your password:", type="password")

if st.button("Analyze"):

    if password:
        result = analyze_password(password)

        # -----------------------------
        # SCORE CALCULATION (OUT OF 100)
        # -----------------------------
        score = min(int(result["entropy"] * 1.5), 100)

        # -----------------------------
        # STRENGTH BAR
        # -----------------------------
        st.subheader(" Strength Score")

        st.progress(score / 100)

        if score < 40:
            st.error(f"Weak ({score}/100)")
        elif score < 70:
            st.warning(f"Moderate ({score}/100)")
        else:
            st.success(f"Strong ({score}/100)")

        # -----------------------------
        # DETAILS
        # -----------------------------
        st.subheader(" Analysis")

        if result["dictionary_risk"]:
            st.error("⚠ Dictionary Risk")

        if result["pattern_risk"]:
            st.warning("⚠ Pattern Risk")

        st.write(f"Entropy: **{result['entropy']} bits**")
        st.write(f"Brute Force Resistance: **{result['brute_force_level']}**")

        # -----------------------------
        # RECOMMENDATIONS
        # -----------------------------
        st.subheader(" Suggestions")

        for rec in result["recommendations"]:
            st.markdown(f"• {rec}")

    else:
        st.warning("Enter a password first.")