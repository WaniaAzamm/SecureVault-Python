import streamlit as st
import re
import random
import string
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

def apply_custom_css():
    st.markdown("""
    <style>
    .stApp {
        background-color: #121212;
        color: #e0e0e0;
    }
    
    .main-header {
        font-size: 2.5rem;
        background: linear-gradient(90deg, #8e2de2, #4a00e0);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
        text-align: center;
        margin: 1rem 0;
    }
     
    .stTabs [data-baseweb="tab"] {
        border-radius: 6px;
        padding: 8px 16px;
    }
    
    .stTabs [data-baseweb="tab-list"] button[aria-selected="true"] {
        background-color: #8e2de2;
    }
    
    .quiz-container {
        background-color: #1e1e1e;
        border-radius: 10px;
        padding: 1.5rem;
        margin: 1rem 0;
        border-left: 3px solid #8e2de2;
        position: relative;
    }
    
    .quiz-nav-buttons {
        display: flex;
        justify-content: flex-end;
        margin-top: 1rem;
    }
    
    .quiz-results {
        text-align: center;
        padding: 1rem;
        background-color: #2d2d2d;
        border-radius: 8px;
        margin: 1rem 0;
        border-left: 3px solid #8e2de2;
    }
    
    .glow-text {
        text-shadow: 0 0 5px #4a00e0, 0 0 10px #8e2de2;
        color: #e0e0e0;
    }
    
    .dark-card {
        background-color: #1e1e1e;
        border-radius: 10px;
        padding: 1.5rem;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        margin: 1rem 0;
        border-left: 3px solid #8e2de2;
    }
    
    .stButton > button {
        background: linear-gradient(90deg, #8e2de2, #4a00e0);
        color: white;
        border: none;
        border-radius: 6px;
        padding: 0.5rem 1rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 0 15px rgba(138, 43, 226, 0.5);
    }
    
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #ff4757, #ffa502, #2ed573);
    }
    
    .password-display {
        font-family: 'Courier New', monospace;
        background-color: #2d2d2d;
        border-radius: 6px;
        padding: 1rem;
        border-left: 3px solid #8e2de2;
        color: #7bed9f;
        letter-spacing: 1px;
    }
    
    div[data-baseweb="input"] {
        background-color: #2d2d2d;
        border: 1px solid #4a4a4a;
        border-radius: 6px;
    }
    
    div[data-baseweb="input"]:focus-within {
        border-color: #8e2de2;
        box-shadow: 0 0 0 2px rgba(138, 43, 226, 0.3);
    }
    
    p, label, li {
        color: #e0e0e0;
    }
    
    h1, h2, h3, h4 {
        color: #e0e0e0;
    }
    
    div[data-testid="stThumbValue"] {
        color: #8e2de2 !important;
    }
    
    .streamlit-expanderHeader {
        background-color: #2d2d2d;
        border-radius: 6px;
    }
    
    .footer {
        text-align: center;
        color: #6c757d;
        font-size: 0.9rem;
        margin-top: 2rem;
        padding-top: 1rem;
        border-top: 1px solid #2d2d2d;
    }
    
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
        background-color: #1e1e1e;
        border-radius: 6px;
        padding: 5px;
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: 6px;
        padding: 8px 16px;
    }
    
    .stTabs [data-baseweb="tab-list"] button[aria-selected="true"] {
        background-color: #8e2de2;
    }
    </style>
    """, unsafe_allow_html=True)

def check_password_strength(password):
    score = 0
    max_score = 5
    feedback = []
    
    if len(password) >= 8:
        score += 1
        feedback.append("✅ Minimum length requirement met (8+ characters)")
    else:
        feedback.append("❌ Password should be at least 8 characters long")
    
    if re.search(r"[A-Z]", password):
        score += 1
        feedback.append("✅ Contains uppercase letters")
    else:
        feedback.append("❌ Missing uppercase letters")
        
    if re.search(r"[a-z]", password):
        score += 1
        feedback.append("✅ Contains lowercase letters")
    else:
        feedback.append("❌ Missing lowercase letters")
    
    if re.search(r"\d", password):
        score += 1
        feedback.append("✅ Contains numbers")
    else:
        feedback.append("❌ Add at least one number (0-9)")
    
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        score += 1
        feedback.append("✅ Contains special characters")
    else:
        feedback.append("❌ Include at least one special character (!@#$%^&*)")
    
    common_passwords = ['password', 'admin', '123456', 'qwerty', 'welcome', 'letmein', 'password123']
    if password.lower() in common_passwords:
        score = 0
        feedback.append("❌ This is a commonly used password! Very insecure!")
    
    percentage = min(100, round((score / max_score) * 100))
    
    return score, max_score, percentage, feedback

def analyze_password_strength(password):
    if password:
        score, max_score, percentage, feedback = check_password_strength(password)
        
        update_password_history(score, max_score)
        
        st.markdown("<h3 class='glow-text'>Password Strength:</h3>", unsafe_allow_html=True)
        strength_chart = create_strength_chart(percentage)
        st.pyplot(strength_chart)
        
        if percentage >= 80:
            st.success(f"✅ STRONG PASSWORD: Your password meets most security requirements!")
        elif percentage >= 60:
            st.warning(f"⚠️ MODERATE PASSWORD: Your password is acceptable but could be improved.")
        else:
            st.error(f"❌ WEAK PASSWORD: Your password needs significant improvement!")
        
        crack_time = estimate_crack_time(score, len(password), password)
        st.info(f"⏱️ Estimated time to crack: {crack_time}")
        
        st.markdown("<h3 class='glow-text'>Security Analysis:</h3>", unsafe_allow_html=True)
        for msg in feedback:
            if "✅" in msg:
                st.success(msg)
            elif "⚠️" in msg:
                st.warning(msg)
            else:
                st.error(msg)
        
        if score < 3:
            st.markdown("<h3 class='glow-text'>Suggested Improvements:</h3>", unsafe_allow_html=True)
            improvement_suggestions = []
            
            if len(password) < 8:
                improvement_suggestions.append("• Increase password length to at least 8 characters")
            if not re.search(r"[A-Z]", password):
                improvement_suggestions.append("• Add uppercase letters (A-Z)")
            if not re.search(r"[a-z]", password):
                improvement_suggestions.append("• Add lowercase letters (a-z)")
            if not re.search(r"\d", password):
                improvement_suggestions.append("• Add numbers (0-9)")
            if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
                improvement_suggestions.append("• Add special characters (!@#$%^&*)")
                
            for suggestion in improvement_suggestions:
                st.info(suggestion)
        
        st.markdown("<h3 class='glow-text'>Password Comparison:</h3>", unsafe_allow_html=True)
        history_chart = create_history_chart()
        if history_chart:
            st.pyplot(history_chart)
        else:
            st.info("Check multiple passwords to see a comparison chart.")
    else:
        st.warning("Please enter a password to check.")

def generate_strong_password(length=12, include_uppercase=True, include_lowercase=True, 
                            include_numbers=True, include_special=True, avoid_similar=False):
    uppercase_chars = string.ascii_uppercase
    lowercase_chars = string.ascii_lowercase
    number_chars = string.digits
    special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    if avoid_similar:
        similar_chars = "Il1O0"
        uppercase_chars = ''.join([c for c in uppercase_chars if c not in similar_chars])
        lowercase_chars = ''.join([c for c in lowercase_chars if c not in similar_chars])
        number_chars = ''.join([c for c in number_chars if c not in similar_chars])
    
    char_pool = ""
    if include_uppercase:
        char_pool += uppercase_chars
    if include_lowercase:
        char_pool += lowercase_chars
    if include_numbers:
        char_pool += number_chars
    if include_special:
        char_pool += special_chars
        
    if not char_pool:
        char_pool = lowercase_chars + number_chars
    
    password = ''.join(random.choice(char_pool) for _ in range(length))
    
    if length >= 4 and include_uppercase and include_lowercase and include_numbers and include_special:
        has_upper = any(c in uppercase_chars for c in password)
        has_lower = any(c in lowercase_chars for c in password)
        has_number = any(c in number_chars for c in password)
        has_special = any(c in special_chars for c in password)
        
        char_list = list(password)
        if not has_upper and include_uppercase:
            char_list[0] = random.choice(uppercase_chars)
        if not has_lower and include_lowercase:
            char_list[1] = random.choice(lowercase_chars)
        if not has_number and include_numbers:
            char_list[2] = random.choice(number_chars)
        if not has_special and include_special:
            char_list[3] = random.choice(special_chars)
            
        random.shuffle(char_list)
        password = ''.join(char_list)
    
    return password

def estimate_crack_time(score, password_length, password):
    attempts_per_second = 1_000_000_000
    
    char_space = 0
    if re.search(r"[a-z]", password):
        char_space += 26
    if re.search(r"[A-Z]", password):
        char_space += 26
    if re.search(r"[0-9]", password):
        char_space += 10
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        char_space += 33
        
    if char_space == 0:
        char_space = 26
        
    combinations = char_space ** password_length
    
    seconds = combinations / attempts_per_second
    
    if seconds < 60:
        return f"About {round(seconds, 1)} seconds"
    elif seconds < 3600:
        return f"About {round(seconds/60, 1)} minutes"
    elif seconds < 86400:
        return f"About {round(seconds/3600, 1)} hours"
    elif seconds < 31536000:
        return f"About {round(seconds/86400, 1)} days"
    elif seconds < 31536000 * 100:
        return f"About {round(seconds/31536000, 1)} years"
    else:
        return f"Over {round(seconds/31536000)} years"

def create_strength_chart(percentage):
    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(8, 1))
    
    color_map = plt.cm.RdYlGn_r
    norm = plt.Normalize(0, 100)
    
    ax.barh([0], [100], color='#2d2d2d', height=0.6)
    ax.barh([0], [percentage], color=color_map(1 - (percentage/100)), height=0.6)
    ax.text(50, 0, f"{percentage}%", ha='center', va='center', fontsize=12, fontweight='bold', color='white')
    
    ax.set_ylim(-0.5, 0.5)
    ax.set_xlim(0, 100)
    ax.set_yticks([])
    ax.set_xticks([])
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['bottom'].set_visible(False)
    ax.spines['left'].set_visible(False)
    
    fig.patch.set_alpha(0)
    
    return fig

def update_password_history(score, max_score):
    if 'password_history' not in st.session_state:
        st.session_state['password_history'] = []
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    percentage = (score / max_score) * 100
    st.session_state['password_history'].append((timestamp, percentage))
    
    if len(st.session_state['password_history']) > 5:
        st.session_state['password_history'] = st.session_state['password_history'][-5:]

def create_history_chart():
    if 'password_history' not in st.session_state or len(st.session_state['password_history']) < 2:
        return None
        
    history = st.session_state['password_history']
    
    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(8, 3))
    
    timestamps = [h[0] for h in history]
    percentages = [h[1] for h in history]
    
    color_map = plt.cm.RdYlGn_r
    norm = plt.Normalize(0, 100)
    colors = [color_map(1 - (p/100)) for p in percentages]
    
    ax.bar(timestamps, percentages, color=colors)
    ax.set_ylim(0, 100)
    ax.set_ylabel('Strength (%)', color='white')
    ax.set_title('Password Strength History', color='white')
    
    plt.xticks(rotation=45, color='white')
    plt.yticks(color='white')
    
    ax.set_facecolor('#1e1e1e')
    fig.patch.set_alpha(0)
    
    plt.tight_layout()
    return fig

def password_checker_tab():
    st.markdown("<h2 class='glow-text'>Password Strength Analysis</h2>", unsafe_allow_html=True)
    password_to_check = st.text_input("Enter your password to check its strength:", type="password", key="tab_password_input")
    
    if st.button("🔍 CHECK PASSWORD STRENGTH", key="tab_check_button"):
        analyze_password_strength(password_to_check)

def password_generator_tab():
    st.markdown("<h2 class='glow-text'>Generate Strong Password</h2>", unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        password_length = st.slider("Password Length", min_value=8, max_value=32, value=16, step=1)
        include_uppercase = st.checkbox("Include Uppercase Letters", value=True)
        include_lowercase = st.checkbox("Include Lowercase Letters", value=True)
    
    with col2:
        include_numbers = st.checkbox("Include Numbers", value=True)
        include_special = st.checkbox("Include Special Characters", value=True)
        avoid_similar = st.checkbox("Avoid Similar Characters (I, l, 1, O, 0)", value=True)
    
    if 'generated_password' not in st.session_state:
        st.session_state.generated_password = ""
    
    if st.button("✨ Generate Strong Password", key="generate_button"):
        st.session_state.generated_password = generate_strong_password(
            length=password_length,
            include_uppercase=include_uppercase,
            include_lowercase=include_lowercase,
            include_numbers=include_numbers,
            include_special=include_special,
            avoid_similar=avoid_similar
        )
    
    if st.session_state.generated_password:
        st.success("Password Generated Successfully! 🔐")
        
        st.code(st.session_state.generated_password, language="")
        
        score, max_score, percentage, _ = check_password_strength(st.session_state.generated_password)
        st.markdown(f"This password has a strength score of **{percentage}%**")
        
        st.info("💡 Tip: Select the password above and copy it to use")
        
        if st.button("🔍 Analyze This Password", key="analyze_generated_button"):
            analyze_password_strength(st.session_state.generated_password)
        
        with st.expander("Show additional formats"):
            st.json({"password": st.session_state.generated_password})
            
            chunk_size = min(4, len(st.session_state.generated_password))
            chunks = [st.session_state.generated_password[i:i+chunk_size] for i in range(0, len(st.session_state.generated_password), chunk_size)]
            st.write("Chunked for memorization:", " - ".join(chunks))

def security_tips_tab():
    st.markdown("<h2 class='glow-text'>Password Security Tips</h2>", unsafe_allow_html=True)
    
    with st.expander("🔑 How to Create Strong Passwords"):
        st.markdown("""
        ### Creating Strong Passwords
        
        1. **Use at least 12-16 characters** - Length is one of the most important factors
        2. **Mix character types** - Include uppercase, lowercase, numbers, and symbols
        3. **Avoid personal information** - Don't use names, birthdates, or other personal details
        4. **Don't use dictionary words** - Especially avoid common passwords like "password123"
        5. **Create a passphrase** - A sequence of random words can be both secure and memorable
        """)
        
    with st.expander("🛡️ Best Practices for Password Security"):
        st.markdown("""
        ### Password Security Best Practices
        
        1. **Use a password manager** - Store complex passwords securely
        2. **Enable two-factor authentication (2FA)** - Add an extra layer of protection
        3. **Use different passwords for different accounts** - Never reuse passwords
        4. **Change passwords periodically** - Especially for critical accounts
        5. **Check for data breaches** - Services like HaveIBeenPwned can alert you if your credentials are compromised
        """)
    
    st.markdown("<h3 class='glow-text'>Test Your Password Knowledge</h3>", unsafe_allow_html=True)
    
    if 'quiz_initialized' not in st.session_state:
        st.session_state.quiz_initialized = True
        st.session_state.quiz_score = 0
        st.session_state.question_index = 0
        st.session_state.show_result = False
        st.session_state.display_answer = False
        st.session_state.current_answer = None
        st.session_state.answer_submitted = False
    
    questions = [
        {"question": "Changing one letter to a symbol (e.g., 'a' to '@') makes a weak password strong", "answer": False, "explanation": "Simply substituting characters isn't enough. Password strength depends on length, complexity, and unpredictability."},
        {"question": "A password manager is more secure than memorizing passwords", "answer": True, "explanation": "Password managers allow you to use unique, complex passwords for each site without having to memorize them all."},
        {"question": "A random series of words can be more secure and memorable than a shorter complex password", "answer": True, "explanation": "Long passphrases like 'correct-horse-battery-staple' have more entropy and can be easier to remember than shorter complex passwords."},
        {"question": "Using your birthday in your password is safe as long as you add special characters", "answer": False, "explanation": "Personal information like birthdays can be easily discovered and are common targets in password cracking attempts."},
        {"question": "It's better to have one complex password you use everywhere than different simple passwords", "answer": False, "explanation": "Using different passwords for each site limits the damage if one site is compromised."},
        {"question": "Adding 'UwU' at the end of your password makes it significantly more secure", "answer": False, "explanation": "Adding predictable patterns or common phrases doesn't significantly improve security. Password strength comes from randomness and length."}
    ]
    
    def handle_submit():
        is_correct = (st.session_state.current_answer == "True") == questions[st.session_state.question_index]["answer"]
        if is_correct:
            st.session_state.quiz_score += 1
        st.session_state.display_answer = True
        st.session_state.answer_submitted = True
    
    def next_question():
        st.session_state.question_index += 1
        st.session_state.display_answer = False
        st.session_state.answer_submitted = False
        st.session_state.current_answer = None
        if st.session_state.question_index >= len(questions):
            st.session_state.show_result = True
    
    def restart_quiz():
        st.session_state.quiz_score = 0
        st.session_state.question_index = 0
        st.session_state.show_result = False
        st.session_state.display_answer = False
        st.session_state.answer_submitted = False
        st.session_state.current_answer = None
    
    quiz_container = st.container()
    
    with quiz_container:
        if not st.session_state.show_result:
            if st.session_state.question_index < len(questions):
                q = questions[st.session_state.question_index]
                
                st.markdown(f"**Question {st.session_state.question_index + 1}/{len(questions)}:**")
                st.progress((st.session_state.question_index) / len(questions))
                
                st.markdown(f"### {q['question']}?")
                
                selected_answer = st.radio(
                    "Select your answer:", 
                    ["True", "False"],
                    key=f"quiz_q{st.session_state.question_index}_{st.session_state.answer_submitted}"
                )
                
                st.session_state.current_answer = selected_answer
                
                if st.session_state.display_answer:
                    is_correct = (st.session_state.current_answer == "True") == q["answer"]
                    
                    if is_correct:
                        st.success("Correct! ✅")
                    else:
                        st.error("Incorrect! ❌")
                    
                    st.info(f"**Explanation:** {q['explanation']}")
                
                if not st.session_state.answer_submitted:
                    submit_button = st.button("📝 Submit Answer", 
                                             key=f"submit_{st.session_state.question_index}", 
                                             on_click=handle_submit)
                elif st.session_state.question_index < len(questions) - 1:
                    next_button = st.button("➡️ Next Question", 
                                           key=f"next_{st.session_state.question_index}", 
                                           on_click=next_question)
                else:
                    finish_button = st.button("🏁 Finish Quiz", 
                                             key="finish_quiz", 
                                             on_click=next_question)
        
        if st.session_state.show_result:
            st.markdown(f"### Quiz Complete! 🎉")
            st.markdown(f"Your score: **{st.session_state.quiz_score}/{len(questions)}**")
            
            score_percentage = (st.session_state.quiz_score / len(questions)) * 100
            
            if score_percentage == 100:
                st.balloons()
                st.success("Perfect score! You're a password security expert! 🏆")
            elif score_percentage >= 70:
                st.success("Great job! You have good password security knowledge! 👍")
            else:
                st.info("Review the security tips to improve your password knowledge.")
            
            fig, ax = plt.subplots(figsize=(8, 1))
            ax.barh([0], [100], color='#2d2d2d', height=0.6)
            ax.barh([0], [score_percentage], color=plt.cm.RdYlGn_r(1 - (score_percentage/100)), height=0.6)
            ax.text(50, 0, f"{int(score_percentage)}%", ha='center', va='center', fontsize=12, 
                    fontweight='bold', color='white')
            ax.set_ylim(-0.5, 0.5)
            ax.set_xlim(0, 100)
            ax.set_yticks([])
            ax.set_xticks([])
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.spines['bottom'].set_visible(False)
            ax.spines['left'].set_visible(False)
            fig.patch.set_alpha(0)
            st.pyplot(fig)
            
            st.markdown("---")
            st.markdown("**Thank you for taking the quiz! UwU**")
            st.markdown("Remember, cute passwords aren't always secure passwords! 🐱")
            
            st.button("🔄 Restart Quiz", on_click=restart_quiz)

def main():
    apply_custom_css()
    
    st.markdown("<h1 class='main-header'>Welcome to SecureVault </h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>Secure your digital life with powerful password tools</p>", unsafe_allow_html=True)
    
    tab1, tab2, tab3 = st.tabs(["🔍 Password Checker", "✨ Password Generator", "🛡️ Security Tips"])
    
    with tab1:
        password_checker_tab()
    
    with tab2:
        password_generator_tab()
    
    with tab3:
        security_tips_tab()
    
    st.markdown("<div class='footer'>© 2025 SecureVault Developed by Wania Azam</div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()