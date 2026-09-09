import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from urllib.parse import quote_plus
from views import leads, elfenai, documentos, financeiro
import os

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
@st.dialog("Editar Lead")
def editar_lead_modal(lead_data, df_vendedores):
    user = st.session_state["usuario_logado"]
    st.write(f"Editando informações de **{lead_data['nome_lead']}**")
    
    with st.form("form_edicao"):
        novo_nome = st.text_input("Nome do Lead", value=lead_data['nome_lead'])
        novo_tel = st.text_input("Telefone", value=lead_data['telefone'])
        
        vendedor_atual_id = lead_data['vendedor_id']
        opcoes_vendedores = df_vendedores["id"].tolist()
        index_vendedor = opcoes_vendedores.index(vendedor_atual_id) if vendedor_atual_id in opcoes_vendedores else 0
        
        novo_vendedor_id = st.selectbox(
            "Vendedor Responsável",
            options=opcoes_vendedores,
            index=index_vendedor,
            format_func=lambda x: df_vendedores[df_vendedores["id"] == x]["nome"].values[0],
            disabled=not user["is_admin"]
        )
        
        col_status1, col_status2, col_status3 = st.columns(3)
        with col_status1:
            gerou_ficha = st.checkbox("Gerou Ficha", value=bool(lead_data['gerou_ficha']))
        with col_status2:
            respondeu = st.checkbox("Respondeu", value=bool(lead_data.get('respondeu', False)))
        with col_status3:
            venda_concluida = st.checkbox("Venda Concluída", value=bool(lead_data.get('venda_concluida', False)))
            
        novo_cpf = st.text_input("CPF", value=lead_data['cpf'] if lead_data['cpf'] else "")
        nova_dt_nasc = st.text_input("Data de Nascimento", value=lead_data['data_nascimento'] if lead_data['data_nascimento'] else "")
        
        nova_obs = st.text_area("Observações / Anotações", value=lead_data['observacao'] if pd.notnull(lead_data['observacao']) else "", placeholder="Ex: Cliente prefere hatch automático, retornar ligação no sábado...")
        
        btn_salvar = st.form_submit_button("Salvar Alterações", use_container_width=True)

        def trata_vazio(valor):
            if not valor or str(valor).strip() == "":
                return None
            return valor
        
        if btn_salvar:
                try:
                    query_update = text("""
                        UPDATE public.leads
                        SET 
                            nome_lead = :nome_lead,
                            telefone = :telefone,
                            vendedor_id = :vendedor_id,
                            gerou_ficha = :gerou_ficha,
                            respondeu = :respondeu,
                            venda_concluida = :venda_concluida,
                            vendeu = :venda_concluida,
                            cpf = :cpf,
                            data_nascimento = :data_nascimento,
                            observacoes = :observacoes,
                            observacao = :observacoes,
                            updated_at = NOW()
                        WHERE id = :lead_id
                    """)
                    
                    with engine.connect() as conn:
                        conn.execute(query_update, {
                            "nome_lead": trata_vazio(novo_nome),
                            "telefone": trata_vazio(novo_tel),
                            "vendedor_id": novo_vendedor_id,
                            "gerou_ficha": gerou_ficha,
                            "respondeu": respondeu,
                            "venda_concluida": venda_concluida,
                            "cpf": trata_vazio(novo_cpf),
                            "data_nascimento": trata_vazio(nova_dt_nasc),
                            "observacoes": trata_vazio(nova_obs),
                            "lead_id": lead_data["id"]
                        })
                        conn.commit()
                        
                    st.success("Lead atualizado com sucesso!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Erro ao salvar alterações: {e}")
@st.dialog("⚠️ Excluir Lead")
def deletar_lead_modal(lead_id, nome_lead):
    st.warning(f"Tem certeza que deseja apagar o lead **{nome_lead}**?")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Sim, Excluir", type="primary", use_container_width=True):
            try:
                query_delete = text("DELETE FROM public.leads WHERE id = :id")
                with engine.begin() as conn:
                    conn.execute(query_delete, {"id": lead_id})
                st.success("Lead excluído!")
                st.rerun()
            except Exception as e:
                st.error(f"Erro ao excluir: {e}")
    with col2:
        if st.button("Cancelar", use_container_width=True):
            st.rerun()

@st.dialog("🖼️ Alterar Foto de Perfil")
def editar_foto_modal(vendedor_id, nome_vendedor, foto_atual):
    st.write(f"Atualizar foto de **{nome_vendedor}**")
    nova_foto = st.text_input("URL da Imagem (Link)", value=foto_atual if foto_atual else "")
    st.caption("Exemplo: https://sua-imagem.com/foto.jpg")
    
    if st.button("Salvar Foto", use_container_width=True, type="primary"):
        try:
            query_foto = text("UPDATE public.vendedores SET foto_url = :foto WHERE id = :id")
            with engine.begin() as conn:
                conn.execute(query_foto, {"foto": nova_foto, "id": vendedor_id})
            st.success("Foto atualizada!")
            st.rerun()
        except Exception as e:
            st.error(f"Erro ao salvar foto: {e}")

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


#========================================================================
# SESSAO ELFEN AI
#========================================================================
if st.session_state.get("tipo_usuatio") == "elfenai":
    if st.button("Botão exclusivo"):
        st.success("aaaaaaaaa")