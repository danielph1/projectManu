import streamlit as st
from utils.auth import verificar_login, logout

st.set_page_config(
    page_title = "Sistema Perfil",
    layout = "centered"
)

#se ja estiver jogado redireciona para a pagina do perfil
if "usuario" in st.session_state:
    tipo = st.session_state.usuario["tipo"]

    #mapa das rotas - pages
    rotas = {
        "admin": "pages/1_admin.py",
        "vendedores": "pages/2_vendedores.py",
        "elfenai": "pages/3_elfenai.py",
        "marketing": "pages/4_marketing.py",
        "documentalista" : "pages/5_documentalista.py",
        "financeiro": "pages/6_financeiro.py"
    }

    pagina = rotas.get(tipo)
    if pagina:
        st.switch_page(pagina)
    else:
        st.error("Tipo de usuario nao reconhecido. entrar em contato com o Daniel")
        logout()

st.title("Login")

with st.form("login_form"):
    login = st.text_input("Login")
    senha = st.text_input("Senha", type="password")
    submit = st.form_submit_button("Entrar")

    if submit:
        if not login or not senha:
            st.error("Preencha login e senha.")
        else:
            usuario = verificar_login(login, senha)
            if usuario:
                st.session_state.usuario = usuario
                st.success(f"Bem-vindo, {usuario.get('nome', usuario['login'])}!")
                st.rerun()
            else:
                st.error("Login ou senha incorretos.")


# comentario para committtt