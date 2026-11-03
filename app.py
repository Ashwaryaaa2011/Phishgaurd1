
import streamlit as st
from scanner import scan_url

# Page settings
st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered"
)

# Initialize history
if "history" not in st.session_state:
    st.session_state.history = []

# Custom design
st.markdown("""
<style>
.stApp {
    background-color: #101827;
    color: white;
}

h1 {
    color: #60A5FA;
}

div.stButton > button {
    background-color: #2563EB;
    color: white;
    border-radius: 10px;
    height: 45px;
    border: none;
}

</style>
""", unsafe_allow_html=True)

# Sidebar
st.sidebar.title("🛡️ PhishGuard")

page = st.sidebar.radio(
    "Choose a page",
    ["Home", "Scan History", "About"]
)

# HOME PAGE
if page == "Home":

    st.title("🛡️ PhishGuard")

    st.subheader("Mini Phishing Link Detector")

    st.write(
        "Check website URLs for suspicious characteristics."
    )

    st.divider()

    url = st.text_input(
        "Enter a website URL",
        placeholder="https://example.com"
    )

    if st.button("🔍 Scan URL", use_container_width=True):

        if not url.strip():
            st.warning("Please enter a URL.")

        else:

            result = scan_url(url)

            if not result["valid"]:

                st.error(result["findings"][0])

            else:

                # Save scan history
                st.session_state.history.append({
                    "url": url,
                    "score": result["score"],
                    "risk": result["risk"]
                })

                st.divider()

                st.subheader("Scan Results")

                col1, col2 = st.columns(2)

                with col1:
                    st.metric(
                        "Risk Score",
                        f'{result["score"]}/100'
                    )

                with col2:
                    st.metric(
                        "Risk Level",
                        result["risk"]
                    )

                st.progress(result["score"] / 100)

                if result["risk"] == "High Risk":
                    st.error("🚨 High Risk URL")

                elif result["risk"] == "Medium Risk":
                    st.warning("⚠️ Medium Risk URL")

                else:
                    st.success("✅ Low Risk URL")

                st.subheader("Security Findings")

                for finding in result["findings"]:
                    st.write("⚠️", finding)


# HISTORY PAGE
elif page == "Scan History":

    st.title("📋 Scan History")

    if st.session_state.history:

        for item in reversed(st.session_state.history):

            st.write("Website:", item["url"])
            st.write("Risk:", item["risk"])
            st.write("Score:", item["score"])
            st.divider()

        if st.button("Clear History"):
            st.session_state.history = []
            st.rerun()

    else:
        st.info("No scans have been performed yet.")


# ABOUT PAGE
elif page == "About":

    st.title("About PhishGuard")

    st.write("""
    PhishGuard is a beginner-level cybersecurity
    project created using Python and Streamlit.

    It analyses website URLs and identifies
    potentially suspicious characteristics.
    """)

    st.subheader("Features")

    st.write("- HTTPS checking")
    st.write("- Suspicious keyword detection")
    st.write("- URL length checking")
    st.write("- IP address detection")
    st.write("- Risk score calculation")
    st.write("- Scan history")

    st.warning(
        "This is an educational tool. It cannot "
        "guarantee that a website is safe."
    )
