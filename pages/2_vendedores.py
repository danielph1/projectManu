import streamlit as st
from utils.auth import exigir_login, logout

exigir_login(tipos_permitidos=["vendedores"])

st.set_page_config(page_title="leads")
st.title("Painel de leads")

st.write(f"Olá, **{st.session_state.usuario['nome']}")

if st.button("Sair"):
    logout()