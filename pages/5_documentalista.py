import streamlit as st
from utils.auth import exigir_login, logout

exigir_login(tipos_permitidos=["documentalista"])

st.set_page_config(page_title="documentos")
st.title("Painel de documentos")

st.write(f"Olá, **{st.session_state.usuario['nome']}")

if st.button("Sair"):
    logout()