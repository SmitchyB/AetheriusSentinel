import streamlit as st
from db import get_sample_items

st.set_page_config(page_title="Database-Backed AI Application", page_icon="🗄️", layout="wide")
st.title("Final Project Starter App")
st.write("This application is reading data from a local SQLite database.")

try:
    items = get_sample_items()
    st.dataframe(items, use_container_width=True)
except Exception as error:
    st.error("The application could not load database records.")
    st.exception(error)