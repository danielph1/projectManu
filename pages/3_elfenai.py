import streamlit as st
from utils.auth import exigir_login, logout

exigir_login(tipos_permitidos=["elfenai"])

st.set_page_config(page_title="elfenai")
st.title("Painel de aprovação")

st.write(f"Olá, **{st.session_state.usuario['nome']}")

if st.button("Sair"):
    logout()