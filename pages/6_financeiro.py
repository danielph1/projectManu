import streamlit as st
from utils.auth import exigir_login, logout

exigir_login(tipos_permitidos=["financeiro"])

st.set_page_config(page_title="financeiro")
st.title("Painel de finanças")

st.write(f"Olá, **{st.session_state.usuario['nome']}")

if st.button("Sair"):
    logout()