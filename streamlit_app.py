import streamlit as st
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder

st.set_page_config(page_title="Network Intrusion Detection System", layout="wide")

st.markdown("""
    <style>
        .stButton>button {
            background-color: #1f77b4 !important;
            color: white !important;
            border-radius: 5px;
            padding: 10px 24px;
        }
        div[data-baseweb="input"] {
            border: 2px solid #1f77b4 !important;
            border-radius: 5px;
            padding: 5px;
        }
    </style>
""", unsafe_allow_html=True)

# Load trained model
try:
    model = joblib.load('my_model.joblib')
except Exception as e:
    st.error(f"Error loading model: {e}")
    st.stop()


def predict(data, model):
    try:
        prediction = model.predict(data)[0]  # Ensure scalar value
        return "Anomaly" if prediction > 0.5 else "Normal"
    except Exception as e:
        st.error(f"Prediction Error: {e}")
        return None


def user_input_features():
    st.subheader("Enter Network Traffic Details")

    with st.form(key="input_form"):
        col1, col2, col3 = st.columns(3)

        protocol_type = col1.selectbox("Protocol Type", ['tcp', 'udp', 'icmp'])
        service = col2.selectbox("Service", [
            'http', 'smtp', 'finger', 'domain_u', 'auth', 'telnet', 'ftp', 'eco_i', 'ntp_u',
            'ecr_i', 'other', 'private', 'pop_3', 'ftp_data', 'rje', 'time', 'mtp', 'link',
            'remote_job', 'gopher', 'ssh', 'name', 'whois', 'domain', 'login', 'imap4',
            'daytime', 'ctf', 'nntp', 'shell', 'IRC', 'nnsp', 'http_443', 'exec', 'printer',
            'efs', 'courier', 'uucp', 'klogin', 'kshell', 'echo', 'discard', 'systat',
            'supdup', 'iso_tsap', 'hostnames', 'csnet_ns', 'pop_2', 'sunrpc', 'uucp_path',
            'netbios_ns', 'netbios_ssn', 'netbios_dgm', 'sql_net', 'vmnet', 'bgp', 'Z39_50',
            'ldap', 'netstat', 'urh_i', 'X11', 'urp_i', 'pm_dump', 'tftp_u', 'tim_i', 'red_i'
        ])
        flag = col3.selectbox("Flag", ['SF', 'S1', 'REJ', 'S2', 'S0', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'OTH', 'SH'])

        numerical_fields = [
            'src_bytes', 'dst_bytes', 'num_failed_logins',
            'serror_rate', 'rerror_rate', 'dst_host_same_srv_rate'
        ]

        input_data = {}

        for i, key in enumerate(numerical_fields):
            if i % 3 == 0:
                input_data[key] = col1.number_input(key, value=0.00, key=key)
            elif i % 3 == 1:
                input_data[key] = col2.number_input(key, value=0.00, key=key)
            else:
                input_data[key] = col3.number_input(key, value=0.00, key=key)

        input_data['protocol_type'] = protocol_type
        input_data['service'] = service
        input_data['flag'] = flag

        submit_button = st.form_submit_button(label="Predict")
        clear_button = st.form_submit_button(label="Clear")

    if clear_button:
        st.experimental_rerun()

    return input_data, submit_button


def preprocess_data(input_data):
    df = pd.DataFrame([input_data])

    categorical_columns = ['protocol_type', 'flag']
    df = pd.get_dummies(df, columns=categorical_columns)

    service_encoder = LabelEncoder()
    service_list = [
        'http', 'smtp', 'finger', 'domain_u', 'auth', 'telnet', 'ftp', 'eco_i', 'ntp_u',
        'ecr_i', 'other', 'private', 'pop_3', 'ftp_data', 'rje', 'time', 'mtp', 'link',
        'remote_job', 'gopher', 'ssh', 'name', 'whois', 'domain', 'login', 'imap4',
        'daytime', 'ctf', 'nntp', 'shell', 'IRC', 'nnsp', 'http_443', 'exec', 'printer',
        'efs', 'courier', 'uucp', 'klogin', 'kshell', 'echo', 'discard', 'systat',
        'supdup', 'iso_tsap', 'hostnames', 'csnet_ns', 'pop_2', 'sunrpc', 'uucp_path',
        'netbios_ns', 'netbios_ssn', 'netbios_dgm', 'sql_net', 'vmnet', 'bgp', 'Z39_50',
        'ldap', 'netstat', 'urh_i', 'X11', 'urp_i', 'pm_dump', 'tftp_u', 'tim_i', 'red_i'
    ]

    service_encoder.fit(service_list)
    df['service'] = service_encoder.transform(df['service'])

    expected_columns = [
        'protocol_type_icmp', 'protocol_type_tcp', 'protocol_type_udp',
        'flag_OTH', 'flag_REJ', 'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR',
        'flag_S0', 'flag_S1', 'flag_S2', 'flag_S3', 'flag_SF', 'flag_SH'
    ]

    for col in expected_columns:
        if col not in df.columns:
            df[col] = 0

    return df

st.title("🔍 Network Intrusion Detection System")

input_data, submit = user_input_features()

if submit:
    with st.spinner("Analyzing network traffic..."):
        processed_data = preprocess_data(input_data)
        result = predict(processed_data, model)
        
        if result:
            st.success(f"Prediction Result: **{result}**")

            progress_bar = st.progress(0)
            for i in range(100):
                progress_bar.progress(i + 1)
