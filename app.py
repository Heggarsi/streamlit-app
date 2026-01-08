import streamlit as st
from auth import init_db, create_user, verify_user, generate_reset_token, reset_password, user_exists
import re

init_db()

st.set_page_config(page_title="Auth Demo", page_icon="🔒")

MENU = ["Login", "Register", "Forgot Password"]

choice = st.sidebar.selectbox("Choose page", MENU)

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid_email(e: str) -> bool:
    return bool(EMAIL_REGEX.match(e))


if "user" not in st.session_state:
    st.session_state.user = None


def login_page():
    st.title("Login")
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
    if submitted:
        if not email or not password:
            st.error("Please fill both fields")
            return
        if verify_user(email, password):
            st.session_state.user = email.lower()
            st.success("Logged in successfully")
        else:
            st.error("Invalid credentials")


def register_page():
    st.title("Register")
    with st.form("register_form"):
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        password2 = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Create account")

    if submitted:
        if not username or not email or not password or not password2:
            st.error("All fields are required")
            return
        if not valid_email(email):
            st.error("Enter a valid email address")
            return
        if password != password2:
            st.error("Passwords do not match")
            return
        if user_exists(email):
            st.error("A user with that email already exists")
            return
        ok = create_user(username, email, password)
        if ok:
            st.success("Account created — you can now log in")
        else:
            st.error("Failed to create account — try a different email")


def forgot_password_page():
    st.title("Forgot Password")
    st.write("Request a password reset token (for demo the token is shown; in production you'd email it)")
    with st.form("request_token"):
        email = st.text_input("Email for reset token")
        sent = st.form_submit_button("Generate token")
    if sent:
        if not valid_email(email):
            st.error("Enter a valid email")
            return
        token = generate_reset_token(email)
        if token:
            st.success("Reset token generated — token will expire in 1 hour")
            st.info(f"Reset token (demo only): {token}")
        else:
            st.error("No account with that email")

    st.write("---")
    st.write("Reset password using token")
    with st.form("reset_with_token"):
        email2 = st.text_input("Email")
        token_in = st.text_input("Token")
        new_pw = st.text_input("New password", type="password")
        new_pw2 = st.text_input("Confirm new password", type="password")
        reset_sub = st.form_submit_button("Reset password")
    if reset_sub:
        if not email2 or not token_in or not new_pw or not new_pw2:
            st.error("All fields are required")
            return
        if new_pw != new_pw2:
            st.error("Passwords do not match")
            return
        ok = reset_password(email2, token_in, new_pw)
        if ok:
            st.success("Password updated successfully — you can now log in")
        else:
            st.error("Invalid token or token expired")


def logged_in_view():
    st.title("Welcome")
    st.write(f"You're logged in as: **{st.session_state.user}**")
    if st.button("Logout"):
        st.session_state.user = None
        # st.experimental_rerun() was removed in newer Streamlit versions
        # Fallback: try to call it, otherwise change query params to force a rerun
        try:
            st.experimental_rerun()
        except AttributeError:
            import time
            st.experimental_set_query_params(_=int(time.time()))
            return


if choice == "Login":
    login_page()
elif choice == "Register":
    register_page()
elif choice == "Forgot Password":
    forgot_password_page()


if st.session_state.user:
    st.sidebar.success(f"Logged in: {st.session_state.user}")
    st.sidebar.button("Go to Dashboard", on_click=lambda: st.session_state.update({"page": "dashboard"}))
    logged_in_view()
