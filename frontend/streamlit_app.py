import streamlit as st
import requests
import json

# Page config
st.set_page_config(
    page_title="AegisAI - Scam Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state for gamification
if 'total_scans' not in st.session_state:
    st.session_state.total_scans = 0
if 'threats_blocked' not in st.session_state:
    st.session_state.threats_blocked = 0
if 'xp_points' not in st.session_state:
    st.session_state.xp_points = 0
if 'quiz_score' not in st.session_state:
    st.session_state.quiz_score = 0
if 'current_question' not in st.session_state:
    st.session_state.current_question = 0
if 'quiz_completed' not in st.session_state:
    st.session_state.quiz_completed = False

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3.5rem;
        font-weight: bold;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.3rem;
        color: #6B7280;
        text-align: center;
        margin-bottom: 2rem;
    }
    .stButton>button {
        width: 100%;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        font-weight: bold;
        padding: 0.75rem;
        border-radius: 0.5rem;
        border: none;
        font-size: 1.1rem;
        transition: transform 0.2s;
    }
    .stButton>button:hover {
        transform: scale(1.05);
        box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
    }
    .risk-high {
        background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
        border-left: 5px solid #DC2626;
        padding: 1.5rem;
        border-radius: 0.75rem;
        margin: 1rem 0;
    }
    .risk-medium {
        background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
        border-left: 5px solid #F59E0B;
        padding: 1.5rem;
        border-radius: 0.75rem;
        margin: 1rem 0;
    }
    .risk-low {
        background: linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%);
        border-left: 5px solid #10B981;
        padding: 1.5rem;
        border-radius: 0.75rem;
        margin: 1rem 0;
    }
    .xp-badge {
        background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 2rem;
        font-weight: bold;
        display: inline-block;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<div class="main-header">🛡️ AegisAI</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Your AI-Powered Shield Against Online Scams</div>', unsafe_allow_html=True)

# Backend health check
try:
    response = requests.get("http://localhost:5000/api/health", timeout=2)
    if response.status_code == 200:
        health_data = response.json()
        if not health_data.get('api_key_present'):
            st.warning("⚠️ Google API key not detected. Some features may be limited.")
except:
    st.error("❌ Cannot connect to backend! Make sure Flask is running on port 5000")
    st.info("💡 In another terminal, run: `python app.py`")
    st.stop()

st.markdown("---")


# DISPLAY FUNCTION
def display_results(result):
    """Display analysis results in a beautiful format"""
    st.markdown("---")
    st.markdown("## 📋 Analysis Results")
    
    risk_level = result.get('risk_level', 'UNKNOWN')
    risk_score = result.get('risk_score', 0)
    status = result.get('status', 'UNKNOWN')
    
    # Update gamification stats
    st.session_state.total_scans += 1
    if risk_level in ["HIGH", "MEDIUM"]:
        st.session_state.threats_blocked += 1
        st.session_state.xp_points += 20
        st.balloons()
    else:
        st.session_state.xp_points += 10
    
    # Display metrics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("🎯 Risk Level", risk_level)
    with col2:
        st.metric("📊 Risk Score", f"{risk_score}%")
    with col3:
        st.metric("Status", status)
    
    # XP Reward
    xp_earned = 20 if risk_level in ["HIGH", "MEDIUM"] else 10
    st.markdown(f'<div class="xp-badge">+{xp_earned} XP Earned! 🌟</div>', unsafe_allow_html=True)
    
    # Risk explanation card
    risk_class = "risk-high" if risk_level == "HIGH" else "risk-medium" if risk_level == "MEDIUM" else "risk-low"
    
    st.markdown(f'<div class="{risk_class}">', unsafe_allow_html=True)
    st.markdown("### 🧠 AI Analysis")
    st.markdown(result.get('explanation', 'No explanation available.'))
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Warning signs
    if 'warning_signs' in result and result['warning_signs']:
        st.markdown("### ⚠️ Red Flags Detected")
        for warning in result['warning_signs']:
            st.write(f"• {warning}")
    
    # Safety tips
    if 'safety_tips' in result and result['safety_tips']:
        st.markdown("### 💡 How to Stay Safe")
        for tip in result['safety_tips']:
            st.write(f"✓ {tip}")
    
    # Google threat info
    if result.get('google_threat'):
        st.error(f"🚨 **Google Safe Browsing Alert:** This URL is flagged as **{result['google_threat']}**")


# Create tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🔗 Check URL", "✉️ Check Message", "📧 Check Email", "🎮 Quiz", "📊 Dashboard"])

# TAB 1: URL Checker
with tab1:
    st.markdown("### Enter a Suspicious Link")
    st.write("Paste any URL you're unsure about - we'll analyze it for threats")
    
    url_input = st.text_input(
        "URL to check:",
        placeholder="https://example.com/suspicious-link",
        key="url_input",
        label_visibility="collapsed"
    )
    
    if st.button("🔍 Analyze URL", key="url_button", use_container_width=True):
        if url_input:
            with st.spinner("🔎 Scanning URL for threats..."):
                try:
                    response = requests.post(
                        "http://localhost:5000/api/check-url",
                        json={"url": url_input},
                        timeout=20
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        display_results(result)
                    else:
                        st.error(f"❌ Error: {response.status_code}")
                except requests.exceptions.Timeout:
                    st.error("⏱️ Request timed out. Try again!")
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")
        else:
            st.warning("⚠️ Please enter a URL to analyze")
    
    with st.expander("💡 Try these example URLs"):
        col1, col2 = st.columns(2)
        with col1:
            if st.button("✅ Test Safe URL", key="safe_url"):
                st.code("https://www.google.com")
        with col2:
            if st.button("⚠️ Test Suspicious Pattern", key="sus_url"):
                st.code("http://192.168.1.1/verify-account-urgent")

# TAB 2: Message Checker
with tab2:
    st.markdown("### Paste a Suspicious Message or Text")
    st.write("Copy and paste any message you think might be a scam")
    
    text_input = st.text_area(
        "Message text:",
        height=200,
        placeholder="URGENT! Your account will be suspended unless you verify immediately...",
        key="text_input",
        label_visibility="collapsed"
    )
    
    if st.button("🔍 Analyze Message", key="text_button", use_container_width=True):
        if text_input:
            with st.spinner("🔎 Analyzing message..."):
                try:
                    response = requests.post(
                        "http://localhost:5000/api/check-text",
                        json={"text": text_input},
                        timeout=15
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        display_results(result)
                    else:
                        st.error(f"❌ Error: {response.status_code}")
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")
        else:
            st.warning("⚠️ Please enter message text")

# TAB 3: Email Checker
with tab3:
    st.markdown("### 📨 Verify Email Legitimacy")
    st.write("Check if an email is a phishing attempt or scam")
    
    col1, col2 = st.columns(2)
    
    with col1:
        sender_email = st.text_input(
            "Sender Email Address:",
            placeholder="support@paypal.com",
            help="Who sent this email?"
        )
    
    with col2:
        subject_line = st.text_input(
            "Email Subject:",
            placeholder="Verify your account immediately",
            help="What's the subject line?"
        )
    
    email_body = st.text_area(
        "Email Body:",
        height=250,
        placeholder="Dear customer,\n\nYour account requires immediate verification. Click here to confirm your login...",
        help="Paste the full email content here"
    )
    
    if st.button("🔍 Analyze Email", key="email_button", use_container_width=True):
        if sender_email or email_body:
            with st.spinner("🔎 Checking email authenticity..."):
                try:
                    payload = {
                        "email": sender_email,
                        "subject": subject_line,
                        "body": email_body
                    }
                    response = requests.post(
                        "http://localhost:5000/api/check-email",
                        json=payload,
                        timeout=25
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        display_results(result)
                    else:
                        st.error(f"❌ Error: {response.status_code}")
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")
        else:
            st.warning("⚠️ Please enter at least sender email or email body")
    
    with st.expander("💡 Email Safety Tips"):
        st.markdown("""
        **Common Phishing Email Signs:**
        - Sender uses free email (gmail/yahoo) for business
        - Generic greetings ("Dear Customer")
        - Urgent language ("Act now!", "Account suspended!")
        - Requests for passwords or personal info
        - Suspicious links or attachments
        - Poor grammar or spelling errors
        - Misspelled company names in email address
        """)

# TAB 4: Quiz
with tab4:
    st.markdown("### 🎮 Cybersecurity Awareness Quiz")
    st.write("Test your knowledge and earn bonus XP!")
    
    # Load questions once and cache them in session state
    if 'quiz_questions' not in st.session_state:
        try:
            quiz_response = requests.get("http://localhost:5000/api/quiz", timeout=5)
            if quiz_response.status_code == 200:
                st.session_state.quiz_questions = quiz_response.json()
            else:
                st.error("Unable to load quiz. Check backend connection.")
                st.session_state.quiz_questions = None
        except Exception as e:
            st.error(f"Unable to connect to backend: {str(e)}")
            st.info("Make sure Flask is running: `python app.py`")
            st.session_state.quiz_questions = None
    
    # Only proceed if questions loaded successfully
    if st.session_state.quiz_questions:
        questions = st.session_state.quiz_questions
        
        if not st.session_state.quiz_completed:
            current_q = st.session_state.current_question
            
            if current_q < len(questions):
                q = questions[current_q]
                
                st.markdown(f"### Question {current_q + 1} of {len(questions)}")
                st.markdown(f"**{q['question']}**")
                
                answer = st.radio(
                    "Select your answer:",
                    q['options'],
                    key=f"q_{current_q}"
                )
                
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    if st.button("Submit Answer", key=f"submit_{current_q}", use_container_width=True):
                        selected_index = q['options'].index(answer)
                        
                        # Show result
                        if selected_index == q['correct']:
                            st.success("✅ Correct! " + q['explanation'])
                            st.session_state.quiz_score += 1
                            st.session_state.xp_points += 15
                            st.balloons()
                        else:
                            st.error("❌ Incorrect. " + q['explanation'])
                            st.session_state.xp_points += 5
                        
                        # ALWAYS move to next question (whether correct or wrong)
                        st.session_state.current_question += 1
                        
                        # Check if quiz is complete
                        if st.session_state.current_question >= len(questions):
                            st.session_state.quiz_completed = True
                        
                        # Wait a moment before rerun to show the message
                        import time
                        time.sleep(1.5)
                        st.rerun()
                
                with col2:
                    st.metric("Progress", f"{current_q + 1}/{len(questions)}")
            
            else:
                st.session_state.quiz_completed = True
                st.rerun()
                
        else:
            # Quiz completed
            score = st.session_state.quiz_score
            total = len(questions)
            percentage = (score / total) * 100
            
            st.markdown("## 🎉 Quiz Complete!")
            st.markdown(f"### Your Score: {score}/{total} ({percentage:.0f}%)")
            
            # Award bonus XP based on performance (only once)
            if 'quiz_bonus_awarded' not in st.session_state:
                if percentage >= 80:
                    st.success("🏆 Excellent! You're a cybersecurity expert!")
                    bonus_xp = 50
                elif percentage >= 60:
                    st.info("👍 Good job! Keep learning!")
                    bonus_xp = 30
                else:
                    st.warning("📚 Keep studying! Review the tips in other tabs.")
                    bonus_xp = 10
                
                st.markdown(f'<div class="xp-badge">+{bonus_xp} Bonus XP! 🌟</div>', unsafe_allow_html=True)
                st.session_state.xp_points += bonus_xp
                st.session_state.quiz_bonus_awarded = True
            
            # Show review
            st.markdown("---")
            st.markdown("### 📝 Review Your Answers")
            for i, q in enumerate(questions):
                with st.expander(f"Question {i + 1}: {q['question']}"):
                    st.write(f"**Correct Answer:** {q['options'][q['correct']]}")
                    st.write(f"**Explanation:** {q['explanation']}")
            
            st.markdown("---")
            if st.button("🔄 Retake Quiz", use_container_width=True):
                st.session_state.quiz_completed = False
                st.session_state.current_question = 0
                st.session_state.quiz_score = 0
                st.session_state.quiz_bonus_awarded = False
                del st.session_state.quiz_questions  # Force reload
                st.rerun()
    else:
        st.warning("Quiz is currently unavailable. Please check the backend connection.")
        if st.button("🔄 Retry Loading Quiz"):
            if 'quiz_questions' in st.session_state:
                del st.session_state.quiz_questions
            st.rerun()
# TAB 5: Dashboard
with tab5:
    st.markdown("### 📊 Your AegisAI Stats")
    
    col1, col2, col3, col4 = st.columns(4)
    
    # Get real stats from backend
    try:
        stats_response = requests.get("http://localhost:5000/api/stats", timeout=2)
        if stats_response.status_code == 200:
            real_stats = stats_response.json()
            
            with col1:
                st.metric("🔍 Total Scans", real_stats.get('total_scans', 0))
            with col2:
                st.metric("🛡️ Threats Blocked", real_stats.get('threats_blocked', 0))
            with col3:
                st.metric("⭐ XP Points", st.session_state.xp_points)
            with col4:
                level = st.session_state.xp_points // 50 + 1
                st.metric("🏆 Level", level)
        else:
            with col1:
                st.metric("🔍 Total Scans", st.session_state.total_scans)
            with col2:
                st.metric("🛡️ Threats Blocked", st.session_state.threats_blocked)
            with col3:
                st.metric("⭐ XP Points", st.session_state.xp_points)
            with col4:
                level = st.session_state.xp_points // 50 + 1
                st.metric("🏆 Level", level)
    except:
        with col1:
            st.metric("🔍 Total Scans", st.session_state.total_scans)
        with col2:
            st.metric("🛡️ Threats Blocked", st.session_state.threats_blocked)
        with col3:
            st.metric("⭐ XP Points", st.session_state.xp_points)
        with col4:
            level = st.session_state.xp_points // 50 + 1
            st.metric("🏆 Level", level)
    
    st.markdown("---")
    
    # XP Progress Bar
    level = st.session_state.xp_points // 50 + 1
    next_level_xp = (level * 50)
    current_xp = st.session_state.xp_points % 50
    progress = current_xp / 50
    
    st.markdown(f"### 🌟 Progress to Level {level + 1}")
    st.progress(progress)
    st.caption(f"{current_xp}/50 XP")
    
    st.markdown("---")
    st.markdown("### 🎯 Common Scam Types We Detect")
    
    col1, col2 = st.columns(2)
    
    with col1:
        with st.expander("🎣 Phishing Emails"):
            st.write("Fake emails from banks or companies trying to steal your credentials.")
        with st.expander("💸 Prize Scams"):
            st.write("Messages claiming you won money or prizes you never entered.")
        with st.expander("🔒 Account Suspension"):
            st.write("Threats about closing your account to create urgency.")
    
    with col2:
        with st.expander("💳 Payment Fraud"):
            st.write("Requests for credit card info or wire transfers.")
        with st.expander("📦 Fake Delivery"):
            st.write("Phony package notifications with malicious links.")
        with st.expander("👨‍💼 Impersonation"):
            st.write("Pretending to be trusted brands or government agencies.")
    
    st.markdown("---")
    st.markdown("### 🏆 Achievements")
    
    achievements = []
    if st.session_state.total_scans >= 1:
        achievements.append("🔰 First Scan - You're getting started!")
    if st.session_state.total_scans >= 5:
        achievements.append("🔍 Detective - Scanned 5 items")
    if st.session_state.total_scans >= 10:
        achievements.append("🕵️ Investigator - Scanned 10 items")
    if st.session_state.threats_blocked >= 1:
        achievements.append("🛡️ Guardian - Blocked your first threat!")
    if st.session_state.threats_blocked >= 5:
        achievements.append("⚔️ Defender - Blocked 5 threats")
    if st.session_state.xp_points >= 50:
        achievements.append("⭐ Rising Star - Reached Level 2")
    if st.session_state.xp_points >= 100:
        achievements.append("💫 Pro Scanner - Reached Level 3")
    if st.session_state.quiz_score >= 3:
        achievements.append("🎓 Scholar - Passed the quiz")
    
    if achievements:
        for achievement in achievements:
            st.success(achievement)
    else:
        st.info("Start scanning to unlock achievements! 🎮")

# Sidebar
with st.sidebar:
    st.markdown("### 🎮 Quick Stats")
    st.markdown(f"**Level:** {st.session_state.xp_points // 50 + 1}")
    st.markdown(f"**XP:** {st.session_state.xp_points}")
    st.markdown(f"**Scans:** {st.session_state.total_scans}")
    st.markdown(f"**Quiz Score:** {st.session_state.quiz_score}/5")
    
    st.markdown("---")
    st.markdown("### 📚 Learn More")
    st.markdown("• [FTC Scam Alerts](https://consumer.ftc.gov/scams)")
    st.markdown("• [FBI IC3](https://www.ic3.gov/)")
    st.markdown("• [Stay Safe Online](https://staysafeonline.org/)")
    
    st.markdown("---")
    st.markdown("### 💥 Team Foresight Furies")
    st.write("🔥 Riya (CSE)")
    st.write("🔥 Dhyeya (AIML)")
    st.write("🔥 Anvi (ECE)")
    
    st.markdown("---")
    if st.button("🔄 Reset Stats", use_container_width=True):
        st.session_state.total_scans = 0
        st.session_state.threats_blocked = 0
        st.session_state.xp_points = 0
        st.session_state.quiz_score = 0
        st.session_state.current_question = 0
        st.session_state.quiz_completed = False
        st.rerun()

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #9CA3AF;'>
        🛡️ <b>AegisAI</b> - Protecting users from online threats since 2025<br>
        Built with ❤️ by Team Foresight Furies
    </div>
    """,
    unsafe_allow_html=True
)