import streamlit as st
from utils.auth import exigir_login, logout

exigir_login(tipos_permitidos=["marketing"])

st.set_page_config(page_title="marketing")
st.title("Painel de marketing")

st.write(f"Olá, **{st.session_state.usuario['nome']}")

if st.button("Sair"):
    logout()