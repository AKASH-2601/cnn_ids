import streamlit as st
import pandas as pd
import joblib

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

def predict_model(input_df, model):
    prediction = model.predict(input_df)
    return "Anomaly" if prediction > 0.5 else "Normal"

# Load model
model = joblib.load('my_model.joblib')

st.title("Anomaly Detection System")

# User Input
st.sidebar.header("Input Features")

def user_input():
    duration = st.sidebar.number_input("Duration", value=0.00)
    service = st.sidebar.number_input("Service", value=45.00)
    src_bytes = st.sidebar.number_input("Source Bytes", value=0.00)
    dst_bytes = st.sidebar.number_input("Destination Bytes", value=0.00)
    protocol_type = st.sidebar.selectbox("Protocol Type", ['icmp', 'tcp', 'udp'])
    flag = st.sidebar.selectbox("Flag", ['OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3', 'SF', 'SH'])
    
    input_dict = {
        'duration': duration, 'service': service, 'src_bytes': src_bytes, 'dst_bytes': dst_bytes,
        'protocol_type': protocol_type, 'flag': flag
    }
    return pd.DataFrame([input_dict])

input_data = user_input()
processed_data = preprocess_data(input_data)

if st.sidebar.button("Predict"):
    prediction = predict_model(processed_data, model)
    st.write("### Prediction Result:")
    st.write(f"## {prediction}")
