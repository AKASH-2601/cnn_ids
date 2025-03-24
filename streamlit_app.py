import streamlit as st
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

st.set_page_config(page_title="Network Intrusion Detection System", layout="wide")

def verify_input(data):
    for key, value in data.items():
        if value is None or value == "":
            return False
    return True

# Load the trained model
try:
    model = joblib.load('my_cnn_model.joblib')
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

    categorical_columns = ['protocol_type', 'flag']
    all_categories = ['protocol_type_icmp', 'protocol_type_tcp', 'protocol_type_udp',
                      'flag_OTH', 'flag_REJ', 'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR',
                      'flag_S0', 'flag_S1', 'flag_S2', 'flag_S3', 'flag_SF', 'flag_SH']
    input_df = pd.get_dummies(input_df, columns=categorical_columns)

    for col in all_categories:
        if col not in input_df.columns:
            input_df[col] = 0

    service_list = ['http', 'smtp', 'finger', 'domain_u', 'auth', 'telnet', 'ftp', 'eco_i', 'ntp_u',
                    'ecr_i', 'other', 'private', 'pop_3', 'ftp_data', 'rje', 'time', 'mtp', 'link',
                    'remote_job', 'gopher', 'ssh', 'name', 'whois', 'domain', 'login', 'imap4',
                    'daytime', 'ctf', 'nntp', 'shell', 'IRC', 'nnsp', 'http_443', 'exec', 'printer',
                    'efs', 'courier', 'uucp', 'klogin', 'kshell', 'echo', 'discard', 'systat',
                    'supdup', 'iso_tsap', 'hostnames', 'csnet_ns', 'pop_2', 'sunrpc', 'uucp_path',
                    'netbios_ns', 'netbios_ssn', 'netbios_dgm', 'sql_net', 'vmnet', 'bgp', 'Z39_50',
                    'ldap', 'netstat', 'urh_i', 'X11', 'urp_i', 'pm_dump', 'tftp_u', 'tim_i', 'red_i']

    service_encoder = LabelEncoder()
    service_encoder.fit(service_list)
    input_df['service'] = service_encoder.transform([input_df['service'][0]])

    num_cols = ["count", "src_bytes", "dst_bytes", "dst_host_same_src_port_rate",
                "srv_count", "dst_host_count", "dst_host_srv_diff_host_rate", "same_srv_rate"]
    scaler = MinMaxScaler()
    input_df[num_cols] = scaler.fit_transform(input_df[num_cols])

    return input_df

def predict_model(input_df):
    try:
        prediction = model.predict(input_df)[0]
        return "Anomaly" if prediction > 0.5 else "Normal"
    except Exception as e:
        return None

def user_input_features():
    st.subheader("Enter Network Traffic Details")
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
        input_data = {key: col1.number_input(key, value=0.00) if i % 3 == 0 else
                          col2.number_input(key, value=0.00) if i % 3 == 1 else
                          col3.number_input(key, value=0.00) for i, key in enumerate(numerical_fields)}
        input_data['protocol_type'] = protocol_type
        input_data['service'] = service
        input_data['flag'] = flag
        submit_button = st.form_submit_button(label="Predict")
    return input_data, submit_button

st.title("🔍 Network Intrusion Detection System")
input_data, submit = user_input_features()
if submit:
    if verify_input(input_data):
        with st.spinner("Analyzing network traffic..."):
            processed_data = preprocess_data(input_data)
            result = predict_model(processed_data)
            if result:
                st.success(f"Prediction Result: **{result}**")
    else:
        st.warning("⚠️ All fields are required.")
