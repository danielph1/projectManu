import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from urllib.parse import quote_plus
import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from views import leads, elfenai, documentacao, financeiro

st.cache_data.clear()
st.set_page_config(page_title="Manu Automoveis", layout="wide")

# Configurações do Banco manuProject
@st.cache_resource
def get_engine():
    # Lê a URL do Supabase configurada nos Secrets do Streamlit Cloud
    db_url = st.secrets["postgres"]["url"]
    return create_engine(db_url)

engine = get_engine()

# --- INFRAESTRUTURA DE MENSAGENS (BANCO DE DADOS) ---
def inicializar_banco_chat():
    """Garante que a tabela de chat e a coluna 'lida' existam."""
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS public.chat_mensagens (
                    id SERIAL PRIMARY KEY,
                    remetente_id INT NOT NULL,
                    destinatario_id INT NOT NULL,
                    mensagem TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    lida BOOLEAN DEFAULT FALSE
                );
            """))
            conn.execute(text("""
                ALTER TABLE public.chat_mensagens 
                ADD COLUMN IF NOT EXISTS lida BOOLEAN DEFAULT FALSE;
            """))
    except Exception as e:
        st.error(f"Erro ao inicializar estrutura de chat no banco: {e}")

inicializar_banco_chat()

# --- FUNÇÕES DE CHAT / NOTIFICAÇÕES ---
def contar_mensagens_nao_lidas(vendedor_id, remetente_id=None):
    if not vendedor_id:
        return 0
    try:
        if remetente_id:
            query = text("""
                SELECT COUNT(*) FROM public.chat_mensagens 
                WHERE destinatario_id = :meu_id AND remetente_id = :remetente_id AND lida = FALSE
            """)
            params = {"meu_id": vendedor_id, "remetente_id": remetente_id}
        else:
            query = text("""
                SELECT COUNT(*) FROM public.chat_mensagens 
                WHERE destinatario_id = :meu_id AND lida = FALSE
            """)
            params = {"meu_id": vendedor_id}
            
        with engine.connect() as conn:
            return conn.execute(query, params).scalar() or 0
    except Exception:
        return 0

def marcar_mensagens_como_lidas(meu_id, outro_id):
    if not meu_id or not outro_id:
        return
    try:
        query = text("""
            UPDATE public.chat_mensagens 
            SET lida = TRUE 
            WHERE destinatario_id = :meu_id AND remetente_id = :outro_id AND lida = FALSE
        """)
        with engine.begin() as conn:
            conn.execute(query, {"meu_id": meu_id, "outro_id": outro_id})
    except Exception:
        pass

# --- GERENCIAMENTO DE SESSÃO / AUTENTICAÇÃO ---

if "usuario_logado" not in st.session_state:
    st.session_state["usuario_logado"] = None

if "filtro_categoria" not in st.session_state:
    st.session_state["filtro_categoria"] = "todos"

if "pagina_atual" not in st.session_state:
    st.session_state["pagina_atual"] = "leads"

if "chat_vendedor_selecionado" not in st.session_state:
    st.session_state["chat_vendedor_selecionado"] = None

def autenticar(login_input, senha_input):
    try:
        query = text("""
            SELECT id, nome, login, tipo, vendedor_id 
            FROM public.usuarios 
            WHERE LOWER(login) = LOWER(:usr) AND senha_hash = :pwd
        """)
        with engine.connect() as conn:
            result = conn.execute(query, {"usr": login_input.strip(), "pwd": senha_input.strip()}).fetchone()
            if result:
                is_admin = result.tipo in ["admin", "gerente"] 
                st.session_state["user"] = {
                    "id": result.id,
                    "nome": result.nome,
                    "login": result.login,
                    "tipo": result.tipo,
                    "vendedor_id": result.vendedor_id,
                    "is_admin": is_admin
                }
                st.session_state["usuario_logado"] = result.nome
                return True
    except Exception as e:
        st.error(f"Erro ao conectar para login: {e}")
    return False

def logout():
    st.session_state["usuario_logado"] = None
    st.session_state['abrir_formulario'] = False
    st.session_state["filtro_categoria"] = "todos"
    st.session_state["pagina_atual"] = "leads"
    st.session_state["chat_vendedor_selecionado"] = None
    st.rerun()

def obter_vendedores():
    try:
        with engine.connect() as conn:
            # Tenta buscar com a foto_url caso a coluna exista
            return pd.read_sql_query("SELECT id, nome, foto_url FROM public.vendedores ORDER BY nome", conn)
    except Exception:
        try:
            # Fallback caso a tabela só tenha id e nome
            with engine.connect() as conn:
                df = pd.read_sql_query("SELECT id, nome FROM public.vendedores ORDER BY nome", conn)
                df["foto_url"] = None
                return df
        except Exception:
            return pd.DataFrame(columns=["id", "nome", "foto_url"])

# ==========================================
# MODAIS / DIALOGS (ESCOPO GLOBAL)
# ==========================================


# ==========================================
# 1. TELA DE LOGIN (SE NÃO ESTIVER LOGADO)
# ==========================================
if st.session_state["usuario_logado"] is None:
    st.markdown("<br><br>", unsafe_allow_html=True)
    c1, col_login, c2 = st.columns([1, 1.5, 1])
    
    with col_login:
        with st.container(border=True):
            st.title("Acesso ao sistema")
            st.subheader("Entrar no Sistema")
            
            with st.form("form_login"):
                login_input = st.text_input("Usuário")
                senha_input = st.text_input("Senha", type="password")
                btn_entrar = st.form_submit_button("Entrar", use_container_width=True)
                
                if btn_entrar:
                    if autenticar(login_input, senha_input):
                        st.success("Login realizado com sucesso!")
                        st.rerun()
                    else:
                        st.error("Usuário ou senha incorretos.")
    st.stop()

# ==========================================
# 2. SISTEMA PRINCIPAL (APÓS LOGIN)
# ==========================================
user = st.session_state.get("user", {})
tipo_usuario = user.get("tipo", "vendedor")

# Roteador central para os arquivos da pasta views
if tipo_usuario == "elfenai":
    elfenai.renderizar(user)
elif tipo_usuario == "documentacao":
    documentacao.renderizar(user)
elif tipo_usuario == "financeiro":
    financeiro.renderizar(user)
else:
    leads.renderizar(user)