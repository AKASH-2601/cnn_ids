import streamlit as st
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import toml
from tensorflow import keras


    
st.set_page_config(page_title="Network Intrusion Detection System", layout="wide")

st.markdown(
    """
    <style>
    div.stFormSubmitButton button {
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
  border-radius: .25rem;
  transition: color .15s ease-in-out,background-color .15s ease-in-out,border-color .15s ease-in-out,box-shadow .15s ease-in-out;
  color: #0d6efd;
  border-color: #0d6efd;
    display: flex;
    justify-content: center;
    align-items: center;
    width: 300px;
    margin: auto;
    }

div.stFormSubmitButton button:hover {
      color: #fff;
      background-color: #0d6efd;
      border-color: #0d6efd;
  }
  

    </style>
    """,
    unsafe_allow_html=True
)

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

st.title("Network Intrusion Detection System")

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
