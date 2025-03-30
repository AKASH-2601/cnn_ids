import streamlit as st
import json
import os
import re
from datetime import datetime
import smtplib
import random
import string
import time
from threading import Thread
import keras

# File path for user data
FILE_PATH = "users.json"

def load_users():
    if not os.path.exists(FILE_PATH) or os.path.getsize(FILE_PATH) == 0:
        return []
    with open(FILE_PATH, 'r') as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            return []

def save_users(users):
    with open(FILE_PATH, 'w') as file:
        json.dump(users, file, indent=4)

def authenticate(username, password):
    users = load_users()
    for user in users:
        if user['username'] == username and user['password'] == password:
            return True
    return False

def is_valid_email(email):
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email) is not None

def register_user(username, email, password):
    users = load_users()
    for user in users:
        if user['username'] == username:
            return False  # Username already exists
    now = datetime.now()
    users.append({'username': username, 'email': email, 'password': password,
                  'date': now.strftime("%Y-%m-%d"), 'time': now.strftime("%H:%M:%S")})
    save_users(users)
    return True



def signup_page():
    st.subheader("Create a New Account")
    new_username = st.text_input(":blue[Username]", placeholder='Enter username')
    email = st.text_input(":blue[Email]", placeholder='Enter Your Email')
    new_password = st.text_input(":blue[Password]", type="password", placeholder='Enter password')
    confirm_password = st.text_input(":blue[Confirm Password]", type="password", placeholder='Re-enter password')
    
    if st.button("Sign Up",type='primary' ,use_container_width=True):
        if not new_username or not email or not new_password or not confirm_password:
            st.warning("All fields are required!")
        elif not is_valid_email(email):
            st.warning("Invalid email format! Please enter a valid email.")
        elif new_password != confirm_password:
            st.error("Passwords do not match!")
        elif register_user(new_username, email, new_password):
            st.success("Account created successfully! You can now login.")
            st.session_state.page = "Login"
            st.rerun()
        else:
            st.error("Username already exists!")
    
    if st.button("Already have an account? Login", type="tertiary"):
        st.session_state.page = "Login"
        st.rerun()

def login_page():
    st.subheader("Login Page")
    username = st.text_input(":blue[Username]", placeholder='Enter your username')
    password = st.text_input(":blue[Password]", type="password", placeholder='Enter your password')
    
    if st.button("Login",type='primary' ,use_container_width=True):
        if not username or not password:
            st.warning("All fields are required!")
        elif authenticate(username, password):
            st.success(f"Welcome {username}! Login Successful")
            st.session_state.username = username
            st.session_state.page = "Main"
        else:
            st.error("Invalid Username or Password")
    
    if st.button("Back to Sign Up", type="tertiary"):
        st.session_state.page = "Sign Up"
        st.rerun()

    if st.button("Forgot Password?", type="tertiary"):
        st.session_state.page = "Forgot Pwd"
        st.rerun()

def update_password(email, new_password):
    users = load_users()
    user_found = False
    
    for user in users:
        if user['email'] == email:
            user['password'] = new_password
            user_found = True
            break
    

    if user_found:

        save_users(users)
        return True
    return False


def forgot_password():

    @st.dialog("Reset Password")
    def reset(email):
        new_password = st.text_input(":blue[New Password]", type="password", placeholder='Enter new password')
        confirm_password = st.text_input(":blue[Confirm Password]", type="password", placeholder='Re-enter password')
        if st.button('Reset'):
            if not new_password or not confirm_password:
                st.warning("All fields are required!")
            elif new_password != confirm_password:
                st.error("Passwords do not match!")
            elif update_password(email, new_password):
                st.success("Password reset successfully")
                st.session_state.page = "Login"
                st.rerun()
            else:
                st.error("Email not found! Please check again.")

    st.subheader("Forgot Password")
    email = st.text_input(":blue[Email]", placeholder='Enter your eamil')
    generated_otp = None
    otp_timestamp = None
    if st.button("Get OTP"):
        if not email:
            st.error("Please enter an email!")
        else:
            generated_otp, otp_timestamp = send_otp(email)
            if generated_otp:
                st.success("OTP Sent! Check your email.")
                st.session_state["generated_otp"] = generated_otp
                st.session_state["otp_timestamp"] = otp_timestamp
                st.session_state["otp_requested"] = True

    if "otp_requested" in st.session_state:
        otp = st.text_input("Enter OTP:", max_chars=6)
        if st.button("Verify OTP"):
            if time.time() - st.session_state["otp_timestamp"] > 60:
                st.error("OTP has expired! Request a new one.")
            elif otp == st.session_state["generated_otp"]:
                st.success("OTP Verified Successfully! ✅")
                reset(email)
            else:
                st.error("Invalid OTP. ❌ Try again.")
        

    
    if st.button("Back to Login", type="tertiary"):
        st.session_state.page = "Login"
        st.rerun()

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Function to send OTP
def send_otp(receiver_email):
    sender_email = "akash26242931@gmail.com"
    sender_password = "tqzt azhm ktyh bpze"

    otp = generate_otp()
    subject = "Your OTP Code"
    body = f"Subject: {subject}\n\nYour OTP is: {otp}\nIt is valid for 1 minute."

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, body)
        server.quit()

        return otp, time.time()
    except Exception as e:
        st.error(f"Failed to send OTP: {e}")
        return None, None

def apply_custom_css():
    st.markdown(
        """
        <style>
.stFormSubmitButton st-emotion-cache-8atqhb e1mlolmg0,
.st-emotion-cache-1bd5s7o.em9zgd01,
.st-emotion-cache-b0y9n5.em9zgd02 {
    cursor: pointer;
    outline: 0;
    display: inline-block;
    font-weight: 400;
    line-height: 1.5;
    text-align: center;
    background-color: transparent;
    border: 1px solid transparent;
    padding: 6px 12px;
    font-size: 1rem;
    border-radius: 0.25rem;
    transition: color 0.15s ease-in-out, background-color 0.15s ease-in-out, border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
    color: #0d6efd;
    border-color: #0d6efd;
}
.stFormSubmitButton st-emotion-cache-8atqhb e1mlolmg0:hover,
.st-emotion-cache-1bd5s7o.em9zgd01:hover,
.st-emotion-cache-b0y9n5.em9zgd02:hover {
    color: #fff;
    background-color: #0d6efd;
    border-color: #0d6efd;
}


        </style>
        """,
        unsafe_allow_html=True
    )

def main_page():
    with st.sidebar:
        st.subheader(f"Welcome {st.session_state.username}!")
        st.write("You have successfully logged in.")
        if st.button("Logout"):
            st.session_state.page = "Login"
            st.session_state.username = ""
            st.rerun()
    def verify_input(data):
        for key, value in data.items():
            if value is None or value == "":
                return False
        return True

    # Load the trained model
    try:
        model = keras.models.load_model("my_cnn_model.keras")
    except Exception as e:
        st.error(f"Error loading model: {e}")
        st.stop()

    def preprocess_data(input_df):
        selected_columns = [
            'count', 'src_bytes', 'service', 'dst_bytes', 'dst_host_same_src_port_rate',
            'srv_count', 'logged_in', 'dst_host_count', 'protocol_type',
            'dst_host_srv_diff_host_rate', 'same_srv_rate', 'flag'
        ]
        input_df = pd.DataFrame([input_df])[selected_columns]

        st.write(input_df)
        
        categorical_columns = ['protocol_type', 'flag']
        all_categories = ['protocol_type_icmp', 'protocol_type_tcp', 'protocol_type_udp',
                        'flag_OTH', 'flag_REJ', 'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR',
                        'flag_S0', 'flag_S1', 'flag_S2', 'flag_S3', 'flag_SF', 'flag_SH']

        # Perform one-hot encoding for categorical features
        input_df = pd.get_dummies(input_df, columns=categorical_columns)

        # Ensure all one-hot encoded categories exist in the dataframe
        for col in all_categories:
            if col not in input_df.columns:
                input_df[col] = 0  # Add missing columns with value 0

        service_map = {
        'http': 22, 'smtp': 50, 'finger': 17, 'domain_u': 11, 'auth': 3, 'telnet': 56,
        'ftp': 18, 'eco_i': 13, 'ntp_u': 39, 'ecr_i': 14, 'other': 40, 'private': 45,
        'pop_3': 43, 'ftp_data': 19, 'rje': 48, 'time': 59, 'mtp': 31, 'link': 29,
        'remote_job': 47, 'gopher': 20, 'ssh': 52, 'name': 32, 'whois': 65, 'domain': 10,
        'login': 30, 'imap4': 24, 'daytime': 8, 'ctf': 7, 'nntp': 38, 'shell': 49,
        'IRC': 0, 'nnsp': 37, 'http_443': 23, 'exec': 16, 'printer': 44, 'efs': 15,
        'courier': 5, 'uucp': 62, 'klogin': 26, 'kshell': 27, 'echo': 12, 'discard': 9,
        'systat': 55, 'supdup': 54, 'iso_tsap': 25, 'hostnames': 21, 'csnet_ns': 6,
        'pop_2': 42, 'sunrpc': 53, 'uucp_path': 63, 'netbios_ns': 34, 'netbios_ssn': 35,
        'netbios_dgm': 33, 'sql_net': 51, 'vmnet': 64, 'bgp': 4, 'Z39_50': 2, 'ldap': 28,
        'netstat': 36, 'urh_i': 60, 'X11': 1, 'urp_i': 61, 'pm_dump': 41, 'tftp_u': 57,
        'tim_i': 58, 'red_i': 46
        }

        input_df['service'] = input_df['service'].map(service_map)

        scaler = joblib.load('scalar_model.joblib')
        num_cols = [
        "count", "src_bytes", "dst_bytes", "dst_host_same_src_port_rate",
        "srv_count", "dst_host_count", "dst_host_srv_diff_host_rate", "same_srv_rate"
        ]
        input_df[num_cols] = scaler.transform(input_df[num_cols])

        return input_df

    def reset_form():
        st.session_state.reset = True
        st.session_state.protocol = 'tcp'
        st.session_state.service = 'http'
        st.session_state.flag = 'SF'
        for key in ['count', 'src_bytes', 'dst_bytes', 'dst_host_same_src_port_rate', 
                    'srv_count', 'logged_in', 'dst_host_count', 'dst_host_srv_diff_host_rate', 'same_srv_rate']:
            st.session_state[key] = 0.00

    def predict_model(input_df):
        try:
            prediction = model.predict(input_df)[0]
            return "Anomaly" if prediction > 0.5 else "Normal"
        except Exception as e:
            return None

    def user_input_features():
        st.subheader("Enter Network Traffic Details")
        if "reset" not in st.session_state:
            st.session_state.reset = False
        with st.form(key="input_form"):
            col1, col2, col3 = st.columns(3)
            protocol_type = col1.selectbox("Protocol Type", ['tcp', 'udp', 'icmp'])
            service = col2.selectbox("Service", ['http', 'smtp', 'finger', 'domain_u', 'auth', 'telnet', 'ftp', 'eco_i', 'ntp_u',
                                                'ecr_i', 'other', 'private', 'pop_3', 'ftp_data', 'rje', 'time', 'mtp', 'link',
                                                'remote_job', 'gopher', 'ssh', 'name', 'whois', 'domain', 'login', 'imap4',
                                                'daytime', 'ctf', 'nntp', 'shell', 'IRC', 'nnsp', 'http_443', 'exec', 'printer',
                                                'efs', 'courier', 'uucp', 'klogin', 'kshell', 'echo', 'discard', 'systat',
                                                'supdup', 'iso_tsap', 'hostnames', 'csnet_ns', 'pop_2', 'sunrpc', 'uucp_path',
                                                'netbios_ns', 'netbios_ssn', 'netbios_dgm', 'sql_net', 'vmnet', 'bgp', 'Z39_50',
                                                'ldap', 'netstat', 'urh_i', 'X11', 'urp_i', 'pm_dump', 'tftp_u', 'tim_i', 'red_i'])
            flag = col3.selectbox("Flag", ['SF', 'S1', 'REJ', 'S2', 'S0', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'OTH', 'SH'])
            
            numerical_fields = ['count', 'src_bytes', 'dst_bytes', 'dst_host_same_src_port_rate',
                                'srv_count', 'logged_in', 'dst_host_count', 'dst_host_srv_diff_host_rate', 'same_srv_rate']
            
            input_data = {}

            for i, key in enumerate(numerical_fields):
                default_value = None if st.session_state.reset else 0.00
                input_data[key] = (
                    col1.number_input(key, value=default_value, key=key) if i % 3 == 0 else
                    col2.number_input(key, value=default_value, key=key) if i % 3 == 1 else
                    col3.number_input(key, value=default_value, key=key)
                )

            input_data['protocol_type'] = protocol_type
            input_data['service'] = service
            input_data['flag'] = flag

            submit_button = st.form_submit_button(label="Predict")
            reset_button = st.form_submit_button(label="Reset", on_click=reset_form)
            
        return input_data, submit_button

        input_data, submit = user_input_features()
        if submit:
            if verify_input(input_data):
                with st.spinner("Analyzing network traffic..."):
                    processed_data = preprocess_data(input_data)
                    result = predict_model(processed_data)
                    if result:
                        st.success(f"Prediction Result: **{result}**")
                        progress_bar = st.progress(0)
                        for i in range(100):
                            progress_bar.progress(i + 1)
            else:
                st.warning("⚠️ All fields are required.")

def main():
    st.title("Network Intrusion Detection System")
    apply_custom_css()
    if "page" not in st.session_state:
        st.session_state.page = "Sign Up"
    if "username" not in st.session_state:
        st.session_state.username = ""
    
    if st.session_state.page == "Sign Up":
        signup_page()
    elif st.session_state.page == "Login":
        login_page()
    elif st.session_state.page == "Main":
        main_page()
    elif st.session_state.page == "Forgot Pwd":
        forgot_password()

if __name__ == "__main__":
    main()
