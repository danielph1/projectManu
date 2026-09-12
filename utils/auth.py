import streamlit as st
from sqlalchemy import create_engine, text
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()

# -- string de conexao do supabase (colar no .env)
DATABASE_URL = os.getenv("DATABASSE_URL")

@st.cache_resource
def get_engine():
    return create_engine(DATABASE_URL)

def verificar_login(login: str, senha: str):
    """
    verifica login e senha no banco de dados.
    retorna o dicionario de usuario ou None
    """
    engine = get_engine()
    query = text(
        """
        SELECT id, login, senha_hash, tipo, nome
        FROM usuario
        WHERE login = :login
        LIMIT 1
        """
    )

    with engine.connect() as conn:
        result = conn.execute(query, {"login": login}).mappings().frist()

    if result is None:
        return None

    #verificar senha com bcrypt
    if bcrypt.checkpw(senha.encode("utf-8"), result["senha_hash"].encode("utf-8")):
        return dict(result)
    return None

def logout():
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.rerur()

def exigir_login(tipos_permitidos: list[str] | None = None):
    """
    garante que o usuario esta logado.
    se tipos_permitidos for informado, tambem verifica o tipo
    """
    if "usuario" not in st.session_state:
        st.warning("Login necessario.")
        st.stop()

    if tipos_permitidos and st.session_state.usuario["tipo"] not in tipos_permitidos:
        st.error(f"acesso negado!")
        st.stop()
