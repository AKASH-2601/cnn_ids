import streamlit as st
import numpy as np
import pandas as pd
import joblib

st.set_page_config(page_title="Network Intrusion Detection System", layout="wide")
st.markdown("""
    <style>
        .stButton>button {
            background-color: #1f77b4;
            color: white;
            border-radius: 5px;
            padding: 10px 24px;
        }
        div[data-baseweb="input"] {
            border: 5px solid #1f77b4 !important;
            border-radius: 5px;
            padding: 5px;
        }
    </style>
""", unsafe_allow_html=True)

def predict(data, model):
    st.json(data)
    prediction = model.predict(data)
    st.success("Prediction Completed!")
    return "Anomaly" if prediction > 0.5 else "Normal"
    

model = joblib.load('my_model.joblib')

# Streamlit UI
st.title("Network Intrusion Detection System")

def user_input_features():
    col1, col2, col3 = st.columns(3)
    
    protocol_type = st.selectbox("Protocol Type", ['tcp', 'udp', 'icmp'])
    service = st.selectbox("Service", [
        'http', 'smtp', 'finger', 'domain_u', 'auth', 'telnet', 'ftp', 'eco_i', 'ntp_u',
        'ecr_i', 'other', 'private', 'pop_3', 'ftp_data', 'rje', 'time', 'mtp', 'link',
        'remote_job', 'gopher', 'ssh', 'name', 'whois', 'domain', 'login', 'imap4',
        'daytime', 'ctf', 'nntp', 'shell', 'IRC', 'nnsp', 'http_443', 'exec', 'printer',
        'efs', 'courier', 'uucp', 'klogin', 'kshell', 'echo', 'discard', 'systat',
        'supdup', 'iso_tsap', 'hostnames', 'csnet_ns', 'pop_2', 'sunrpc', 'uucp_path',
        'netbios_ns', 'netbios_ssn', 'netbios_dgm', 'sql_net', 'vmnet', 'bgp', 'Z39_50',
        'ldap', 'netstat', 'urh_i', 'X11', 'urp_i', 'pm_dump', 'tftp_u', 'tim_i', 'red_i'
    ])
    flag = st.selectbox("Flag", ['SF', 'S1', 'REJ', 'S2', 'S0', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'OTH', 'SH'])
    
    numerical_values = {
        'duration': 0.00, 'src_bytes': 0.00, 'dst_bytes': 0.00, 'land': 0.00,
        'wrong_fragment': 0.00, 'urgent': 0.00, 'hot': 0.00, 'num_failed_logins': 0.00,
        'logged_in': 0.00, 'num_compromised': 0.00, 'root_shell': 0.00, 'su_attempted': 0.00,
        'num_root': 0.00, 'num_file_creations': 0.00, 'num_shells': 0.00, 'num_access_files': 0.00,
        'num_outbound_cmds': 0.00, 'is_host_login': 0.00, 'is_guest_login': 0.00,
        'count': 0.00, 'srv_count': 0.00, 'serror_rate': 0.00, 'srv_serror_rate': 0.00,
        'rerror_rate': 0.00, 'srv_rerror_rate': 1.00, 'same_srv_rate': 0.01, 'diff_srv_rate': 0.00,
        'srv_diff_host_rate': 0.00, 'dst_host_count': 0.00, 'dst_host_srv_count': 3.00,
        'dst_host_same_srv_rate': 0.01, 'dst_host_diff_srv_rate': 0.00, 'dst_host_same_src_port_rate': 0.00,
        'dst_host_srv_diff_host_rate': 0.00, 'dst_host_serror_rate': 0.00, 'dst_host_srv_serror_rate': 0.00,
        'dst_host_rerror_rate': 0.00, 'dst_host_srv_rerror_rate': 0.00
    }
    
    input_data = {}
    
    for i, (key, val) in enumerate(numerical_values.items()):
        if i % 3 == 0:
            input_data[key] = col1.number_input(key, value=val)
        elif i % 3 == 1:
            input_data[key] = col2.number_input(key, value=val)
        else:
            input_data[key] = col3.number_input(key, value=val)
    
    input_data['protocol_type'] = protocol_type
    input_data['service'] = service
    input_data['flag'] = flag
    
    return input_data

def preprocess_data(input_df):
    categorical_columns = ['protocol_type', 'flag']
    all_categories = ['protocol_type_icmp', 'protocol_type_tcp', 'protocol_type_udp',
                      'flag_OTH', 'flag_REJ', 'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR',
                      'flag_S0', 'flag_S1', 'flag_S2', 'flag_S3', 'flag_SF', 'flag_SH']
    
    input_df = pd.get_dummies(input_df, columns=categorical_columns)
    for col in all_categories:
        if col not in input_df.columns:
            input_df[col] = 0
    return input_df



col1, col2, col3 = st.columns([1,2,1])

input_data = user_input_features()
processed_data = preprocess_data(input_data)

with col2:
    if st.button("Predict", key="predict", help="Click to predict", use_container_width=True):
        result = predict(processed_data, model)
        st.write("### Prediction Result:")
        st.write(f"## {prediction}")
