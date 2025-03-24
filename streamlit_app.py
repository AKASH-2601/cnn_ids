import streamlit as st
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

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
    model = joblib.load('my_cnn_model.joblib')
except Exception as e:
    st.error(f"Error loading model: {e}")
    st.stop() 


def reset_form():
    st.session_state.reset = True
    st.session_state.protocol = 'tcp'
    st.session_state.service = 'http'
    st.session_state.flag = 'SF'
    for key in ['count', 'src_bytes', 'dst_bytes', 'dst_host_same_src_port_rate', 
                'srv_count', 'logged_in', 'dst_host_count', 'dst_host_srv_diff_host_rate', 'same_srv_rate']:
        st.session_state[key] = 0.00

def user_input_features():
    st.subheader("Enter Network Traffic Details")

    if "reset" not in st.session_state:
        st.session_state.reset = False

    with st.form(key="input_form"):
        col1, col2, col3 = st.columns(3)

        protocol_type = col1.selectbox("Protocol Type", ['tcp', 'udp', 'icmp'], key="protocol")
        service = col2.selectbox("Service", [
            'http', 'smtp', 'finger', 'domain_u', 'auth', 'telnet', 'ftp', 'eco_i', 'ntp_u',
            'ecr_i', 'other', 'private', 'pop_3', 'ftp_data', 'rje', 'time', 'mtp', 'link',
            'remote_job', 'gopher', 'ssh', 'name', 'whois', 'domain', 'login', 'imap4',
            'daytime', 'ctf', 'nntp', 'shell', 'IRC', 'nnsp', 'http_443', 'exec', 'printer',
            'efs', 'courier', 'uucp', 'klogin', 'kshell', 'echo', 'discard', 'systat',
            'supdup', 'iso_tsap', 'hostnames', 'csnet_ns', 'pop_2', 'sunrpc', 'uucp_path',
            'netbios_ns', 'netbios_ssn', 'netbios_dgm', 'sql_net', 'vmnet', 'bgp', 'Z39_50',
            'ldap', 'netstat', 'urh_i', 'X11', 'urp_i', 'pm_dump', 'tftp_u', 'tim_i', 'red_i'
        ], key="service")
        flag = col3.selectbox("Flag", ['SF', 'S1', 'REJ', 'S2', 'S0', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'OTH', 'SH'], key="flag")

        numerical_fields = [
            'count', 'src_bytes', 'dst_bytes', 'dst_host_same_src_port_rate', 
            'srv_count', 'logged_in', 'dst_host_count', 'dst_host_srv_diff_host_rate', 'same_srv_rate'
        ]
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

def predict(data):
    try:
        # Ensure data has the correct shape
        if data.shape[1] != model.n_features_in_:
            st.error("Model input shape mismatch. Check preprocessing steps.")
            return None

        prediction = model.predict(data)
        predicted_label = prediction[0] if isinstance(prediction, np.ndarray) else prediction

        return "Anomaly" if predicted_label == 1 else "Normal"
    except Exception as e:
        st.error(f"Prediction Error: {e}")
        return None


def preprocess_data(input_data):
    df = pd.DataFrame([input_data])

    categorical_columns = ['protocol_type', 'flag']
    df = pd.get_dummies(df, columns=categorical_columns)

    service_encoder = joblib.load('service_encoder.joblib')  # Load pre-fitted encoder
    df['service'] = service_encoder.transform(df['service'])

    expected_columns = [
        'protocol_type_icmp', 'protocol_type_tcp', 'protocol_type_udp',
        'flag_OTH', 'flag_REJ', 'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR',
        'flag_S0', 'flag_S1', 'flag_S2', 'flag_S3', 'flag_SF', 'flag_SH'
    ]
    
    # Ensure all expected columns exist
    for col in expected_columns:
        if col not in df.columns:
            df[col] = 0

    num_cols = [
        "count", "src_bytes", "dst_bytes", "dst_host_same_src_port_rate",
        "srv_count", "dst_host_count", "dst_host_srv_diff_host_rate", "same_srv_rate"
    ]

    scaler = joblib.load('scaler.joblib')  # Load pre-fitted scaler
    df[num_cols] = scaler.transform(df[num_cols])

    return df


st.title("🔍 Network Intrusion Detection System")

input_data, submit = user_input_features()
st.write(input_data)
if submit:
    if verify_input(input_data):
        with st.spinner("Analyzing network traffic..."):
            processed_data = preprocess_data(input_data)
            result = predict(processed_data)
            
            if result:
                st.success(f"Prediction Result: **{result}**")
                
                progress_bar = st.progress(0)
                for i in range(100):
                    progress_bar.progress(i + 1)
    else:
        st.warning("⚠️ All fields are required. Please fill in all fields before submitting.")
