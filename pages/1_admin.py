import streamlit as st
from utils.auth import exigir_login, logout

exigir_login(tipos_permitidos=["admin"])

st.set_page_config(page_title="admin")
st.title("Painel do Administrador")

st.write(f"Olá, **{st.session_state.usuario['nome']}")

if st.button("Sair"):
    logout()
