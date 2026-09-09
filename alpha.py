import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from urllib.parse import quote_plus
import os

st.cache_data.clear()
st.set_page_config(page_title="CRM - Gestão de Leads", layout="wide")

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
                st.session_state["usuario_logado"] = {
                    "id": result.id,
                    "nome": result.nome,
                    "login": result.login,
                    "tipo": result.tipo,
                    "vendedor_id": result.vendedor_id,
                    "is_admin": is_admin
                }
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
user = st.session_state["usuario_logado"]

# --- SIDEBAR PRINCIPAL DO STREAMLIT ---
with st.sidebar:
    st.markdown(f"### 👤 Logado como:\n**{user['nome']}**")
    st.caption(f"Perfil: {user['tipo'].upper()}")
    
    if st.button("Sair (Logout)", use_container_width=True):
        logout()
        
    st.markdown("---")
    st.header("Navegação")
    
# --- PAGINA DE LEAD ---
    btn_p_leads = "primary" if st.session_state["pagina_atual"] == "leads" else "secondary"
    if st.button("Painel de Leads", use_container_width=True, type=btn_p_leads):
        st.session_state["pagina_atual"] = "leads"
        st.rerun()

# --- PAGINA DE VENDEDORES ---
    btn_p_vendedores = "primary" if st.session_state["pagina_atual"] == "vendedores" else "secondary"
    if st.button("Equipe de Vendedores", use_container_width=True, type=btn_p_vendedores):
        st.session_state["pagina_atual"] = "vendedores"
        st.rerun()


    # Botão de Chat com Notificação Geral
    total_nao_lidas = contar_mensagens_nao_lidas(user.get('vendedor_id'))
    label_chat = f"Central de Chat" + (f" 🔴 ({total_nao_lidas})" if total_nao_lidas > 0 else "")
    
    btn_p_chat = "primary" if st.session_state["pagina_atual"] == "chat" else "secondary"
    if st.button(label_chat, use_container_width=True, type=btn_p_chat):
        st.session_state["pagina_atual"] = "chat"
        st.rerun()
        
    st.markdown("---")
    if st.session_state["pagina_atual"] == "leads":
        st.header("Ações")
        if st.button("➕ Adicionar Novo Lead", use_container_width=True):
            st.session_state['abrir_formulario'] = True
            st.rerun()

# --- PAGINA DE FICHAS PENDENTE ---
    btn_p_ficha = "primary" if st.session_state["pagina_atual"] == "ficha_pendente" else "secondary"
    if st.button("fichas pendentes", use_container_width=True, type=btn_p_vendedores):
        st.session_state["pagina_atual"] = "ficha_pendente"
        st.rerun()

# --- PAGINA DE FICHA APROVADA ---
    btn_p_ficha = "primary" if st.session_state["pagina_atual"] == "ficha_aprovada" else "secondary"
    if st.button("fichas aprovada", use_container_width=True, type=btn_p_vendedores):
        st.session_state["pagina_atual"] = "ficha_aprovada"
        st.rerun()

# --- PAGINA DE FICHA NEGADA ---
    btn_p_ficha = "primary" if st.session_state["pagina_atual"] == "ficha_negada" else "secondary"
    if st.button("fichas negadas", use_container_width=True, type=btn_p_vendedores):
        st.session_state["pagina_atual"] = "ficha_negada"
        st.rerun()

# ==========================================
# PÁGINA 1: PAINEL DE LEADS
# ==========================================
if st.session_state["pagina_atual"] == "leads":
    total_leads, total_fichas, total_aprovados, total_vendidos = 0, 0, 0, 0
    try:
        query_vendedores_stats = text("""
                SELECT 
                    v.id,
                    v.nome,
                    COUNT(l.id) AS total_leads,
                    COUNT(l.id) FILTER (WHERE l.gerou_ficha = TRUE) AS total_fichas,
                    COUNT(l.id) FILTER (WHERE l.aprovou_credito = TRUE) AS total_aprovados,
                    COUNT(l.id) FILTER (WHERE l.vendeu = TRUE OR l.venda_concluida = TRUE) AS total_vendas
                FROM public.vendedores v
                LEFT JOIN public.leads l ON l.vendedor_id = v.id
                GROUP BY v.id, v.nome
                ORDER BY total_vendas DESC, total_aprovados DESC, total_leads DESC, v.nome ASC
            """)
        with engine.connect() as conn:
            m_result = conn.execute(query_metrics, {
                "is_admin": user["is_admin"],
                "vendedor_id": user["vendedor_id"]
            }).fetchone()
        if m_result:
                total_leads = m_result[0] if m_result[0] is not None else 0
                total_fichas = m_result[1] if m_result[1] is not None else 0
                total_aprovados = m_result[2] if m_result[2] is not None else 0
                total_vendidos = m_result[3] if m_result[3] is not None else 0
    except Exception as e:
        st.error(f"Erro nas métricas: {e}")
        pass

    # Layout de topo: Cabeçalho + 4 Métricas (dividido em 5 colunas)
    col_header, col_m1, col_m2, col_m3, col_m4 = st.columns([1.8, 1, 1, 1, 1])

    with col_header:
        st.title("Painel de Controle")

    with col_m1:
        st.metric(label="Total Leads", value=total_leads)
        tipo_btn = "primary" if st.session_state["filtro_categoria"] == "todos" else "secondary"
        if st.button("Ver Todos", key="btn_f_todos", use_container_width=True, type=tipo_btn):
            st.session_state["filtro_categoria"] = "todos"
            st.rerun()

    with col_m2:
        st.metric(label="Fichas Geradas", value=total_fichas)
        tipo_btn = "primary" if st.session_state["filtro_categoria"] == "fichas" else "secondary"
        if st.button("Filtrar Fichas", key="btn_f_fichas", use_container_width=True, type=tipo_btn):
            st.session_state["filtro_categoria"] = "fichas"
            st.rerun()

    with col_m3:
        st.metric(label="Aprovados", value=total_aprovados)
        tipo_btn = "primary" if st.session_state["filtro_categoria"] == "aprovados" else "secondary"
        if st.button("Filtrar Aprovados", key="btn_f_aprovados", use_container_width=True, type=tipo_btn):
            st.session_state["filtro_categoria"] = "aprovados"
            st.rerun()

    with col_m4:
        st.metric(label="Vendidos", value=total_vendidos)
        tipo_btn = "primary" if st.session_state["filtro_categoria"] == "vendidos" else "secondary"
        if st.button("Filtrar Vendidos", key="btn_f_vendidos", use_container_width=True, type=tipo_btn):
            st.session_state["filtro_categoria"] = "vendidos"
            st.rerun()

    # Formulário de Novo Lead
    if st.session_state.get('abrir_formulario', False):
        st.subheader("Novo Lead")
        df_vendedores = obter_vendedores()
        
        with st.form("form_lead", clear_on_submit=False):
            col_f1, col_f2 = st.columns(2)
            with col_f1:
                nome_lead = st.text_input("Nome do Lead*")
                telefone = st.text_input("Telefone*")
                
                if user["is_admin"]:
                    vendedor_selecionado = st.selectbox(
                        "Vendedor Responsável*", 
                        options=df_vendedores["id"].tolist(),
                        format_func=lambda x: df_vendedores[df_vendedores["id"] == x]["nome"].values[0]
                    )
                else:
                    st.info(f"Vendedor Atribuído: **{user['nome']}**")
                    vendedor_selecionado = user["vendedor_id"]

            with col_f2:
                data_lead = st.date_input("Data que o Lead Chegou*")
                venda_concluida = st.checkbox("Venda Concluída?")
            
            gerou_ficha = st.checkbox("Gerou Ficha")
            cpf, data_nascimento, habilitado, aprovou_credito = None, None, None, None

            if gerou_ficha:
                st.markdown("---")
                st.markdown("### 📝 Dados da Ficha")
                col1, col2 = st.columns(2)
                with col1:
                    cpf = st.text_input("CPF")
                    data_nascimento = st.text_input("Data de Nascimento (Texto ex: 10/04/1995)")
                with col2:
                    habilitado_opcao = st.radio("O cliente é habilitado", ["Não", "Sim"], horizontal=True)
                    habilitado = True if habilitado_opcao == "Sim" else False
                    status_credito = st.radio("Status do Crédito", ["Aprovado", "Recusado"], horizontal=True)
                    aprovou_credito = True if status_credito == "Aprovado" else (False if status_credito == "Recusado" else None)

            observacao_txt = st.text_area("📝 Observações Gerais", placeholder="Escreva aqui notas sobre a negociação ou cliente...")

            submitted = st.form_submit_button("Salvar Lead", use_container_width=True)
            
            if submitted:
                if not nome_lead or not telefone or not vendedor_selecionado:
                    st.warning("Preencha ao menos Nome, Telefone e Vendedor.")
                else:
                    try:
                        query_insert = text("""
                            INSERT INTO public.leads (
                                nome_lead, telefone, vendedor_id, data_lead, gerou_ficha, venda_concluida,
                                cpf, data_nascimento, habilitado, aprovou_credito, observacao, created_at, updated_at
                            ) VALUES (
                                :nome, :tel, :vendedor, :dt_lead, :ficha, :venda,
                                :cpf, :dt_nasc, :hab, :aprovado, :obs, NOW(), NOW()
                            )
                        """)
                        with engine.begin() as conn:
                            conn.execute(query_insert, {
                                "nome": nome_lead, "tel": telefone, "vendedor": vendedor_selecionado,
                                "dt_lead": data_lead, "ficha": gerou_ficha, "venda": venda_concluida,
                                "cpf": cpf if gerou_ficha else None, "dt_nasc": data_nascimento if gerou_ficha else None, 
                                "hab": habilitado if gerou_ficha else None, "aprovado": aprovou_credito if gerou_ficha else None,
                                "obs": observacao_txt.strip() if observacao_txt else None
                            })
                        st.success("Lead inserido com sucesso!")
                        st.session_state['abrir_formulario'] = False
                        st.rerun()
                    except Exception as e:
                        st.error("Por favor, preencha os dados corretamente!")

    # Barra de Busca e Cards
    st.markdown("---")
    termo_busca = st.text_input("Buscar Lead (Nome, CPF ou Telefone)", placeholder="Digite o nome, CPF ou número para filtrar...")
    if st.button("➕ Adicionar Novo Lead", key="btn_add_lead_busca", use_container_width=True, type="primary"):
        st.session_state['abrir_formulario'] = True
        st.rerun()

    st.subheader("Leads Cadastrados")

    try:
        df_vendedores = obter_vendedores()
        cat_filtro = st.session_state["filtro_categoria"]
        
        query_select = text("""
            SELECT 
                l.id, l.nome_lead, l.telefone, l.data_lead, l.gerou_ficha, l.venda_concluida,
                l.cpf, l.data_nascimento, l.habilitado, l.aprovou_credito, l.observacao,
                l.updated_at, l.vendedor_id, v.nome AS nome_vendedor
            FROM public.leads l
            LEFT JOIN public.vendedores v ON v.id = l.vendedor_id
            WHERE 
                (:is_admin = TRUE OR l.vendedor_id = :vendedor_id) AND
                (
                    :cat = 'todos' OR
                    (:cat = 'fichas' AND l.gerou_ficha = TRUE) OR
                    (:cat = 'aprovados' AND l.aprovou_credito = TRUE) OR
                    (:cat = 'vendidos' AND l.venda_concluida = TRUE)
                ) AND
                (
                    :busca = '' OR
                    l.nome_lead ILIKE :termo OR
                    l.cpf ILIKE :termo OR
                    l.telefone ILIKE :termo OR
                    l.observacao ILIKE :termo
                )
            ORDER BY l.updated_at DESC
        """)
        
        with engine.connect() as conn:
            df = pd.read_sql_query(query_select, conn, params={
                "is_admin": user["is_admin"],
                "vendedor_id": user["vendedor_id"],
                "cat": cat_filtro,
                "busca": termo_busca,
                "termo": f"%{termo_busca}%"
            })

        if df.empty:
            st.info("Nenhum lead encontrado para os filtros selecionados.")
        else:
            cols = st.columns(3)
            for idx, row in df.iterrows():
                with cols[idx % 3]:
                    with st.container(border=True):
                        st.markdown(f"### 👤 {row['nome_lead']}")
                        if row.get('venda_concluida'):
                            st.success("VENDA CONCLUÍDA")
                        
                        st.write(f"**Vendedor:** {row['nome_vendedor'] if row['nome_vendedor'] else 'Não atribuído'}")
                        st.write(f"**Telefone:** {row['telefone']}")
                        st.write(f"**Data do Lead:** {row['data_lead']}")
                        st.write(f"**Ficha Gerada:** {'Sim' if row['gerou_ficha'] else 'Não'}")
                        
                        if pd.notnull(row['observacao']) and row['observacao'] != "":
                            st.info(f"**Obs:** {row['observacao']}")

                        with st.expander("Gerenciar / Ver Ficha"):
                            if row['gerou_ficha']:
                                st.markdown("##### Dados da Ficha")
                                st.write(f"**CPF:** {row['cpf'] if row['cpf'] else 'Não informado'}")
                                st.write(f"**Data Nasc.:** {row['data_nascimento'] if row['data_nascimento'] else 'Não informada'}")
                                st.write(f"**Habilitado:** {'Sim' if row['habilitado'] else 'Não'}")
                                
                                if row['aprovou_credito'] is True:
                                    st.success("Crédito: Aprovado")
                                elif row['aprovou_credito'] is False:
                                    st.error("Crédito: Recusado")
                                else:
                                    st.warning("Crédito: Em Análise")
                            
                            st.markdown("---")
                            st.markdown("##### Ações")
                            col_edit, col_del = st.columns(2)
                            
                            with col_edit:
                                if st.button("Editar", key=f"btn_edit_{row['id']}", use_container_width=True):
                                    editar_lead_modal(row, df_vendedores)
                                    
                            with col_del:
                                pode_deletar = user["is_admin"] or (row['vendedor_id'] == user['vendedor_id'])
                                if pode_deletar:
                                    if st.button("Deletar", key=f"btn_del_{row['id']}", use_container_width=True):
                                        deletar_lead_modal(row['id'], row['nome_lead'])
                                else:
                                    st.caption("Exclusão não permitida")

                        st.caption(f"Atualizado em: {row['updated_at']}")

    except Exception as e:
        st.error(f"Erro ao carregar dados do banco: {e}")

# ==========================================
# PÁGINA 2: EQUIPE DE VENDEDORES
# ==========================================
elif st.session_state["pagina_atual"] == "vendedores":
    st.title("Equipe de Vendedores")
    st.markdown("Confira o desempenho geral e interaja com a equipe.")
    st.markdown("---")

    try:
        query_vendedores_stats = text("""
                SELECT 
                    v.id,
                    v.nome,
                    COUNT(l.id) AS total_leads,
                    COUNT(l.id) FILTER (WHERE l.gerou_ficha = TRUE) AS total_fichas,
                    COUNT(l.id) FILTER (WHERE l.aprovou_credito = TRUE) AS total_aprovados,
                    COUNT(l.id) FILTER (WHERE l.vendeu = TRUE OR l.venda_concluida = TRUE) AS total_vendas
                FROM public.vendedores v
                LEFT JOIN public.leads l ON l.vendedor_id = v.id
                GROUP BY v.id, v.nome
                ORDER BY total_vendas DESC, total_aprovados DESC, total_leads DESC, v.nome ASC
            """)
        
        with engine.connect() as conn:
            df_vend = pd.read_sql_query(query_vendedores_stats, conn)

        if df_vend.empty:
            st.info("Nenhum vendedor encontrado.")
        else:
            cols_v = st.columns(3)
            for idx, row_v in df_vend.iterrows():

                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Leads", int(row_v.get("total_leads", 0)))
                m2.metric("Fichas", int(row_v.get("total_fichas", 0)))
                m3.metric("Aprovados", int(row_v.get("total_aprovados", 0)))
                m4.metric("Vendas", int(row_v.get("total_vendas", 0)))

                with cols_v[idx % 3]:

                    with st.container(border=True):
                        foto = row_v.get('foto_url') if 'foto_url' in row_v and pd.notnull(row_v['foto_url']) and row_v['foto_url'] != "" else "https://cdn-icons-png.flaticon.com/512/149/149071.png"
                        
                        col_img, col_nome = st.columns([1, 2])
                        with col_img:
                            st.image(foto, width=80)
                        with col_nome:
                            st.markdown(f"### {row_v['nome']}")
                            
                            btn_f1, btn_f2 = st.columns(2)
                            with btn_f1:
                                if st.button("Foto", key=f"foto_btn_{row_v['id']}", use_container_width=True):
                                    editar_foto_modal(row_v['id'], row_v['nome'], row_v['foto_url'])
                            with btn_f2:
                                if row_v['id'] != user['vendedor_id']:
                                    nao_lidas_vendedor = contar_mensagens_nao_lidas(user.get('vendedor_id'), row_v['id'])
                                    btn_label = f"Chat ({nao_lidas_vendedor})" if nao_lidas_vendedor > 0 else "💬 Chat"
                                    
                                    if st.button(btn_label, key=f"chat_btn_{row_v['id']}", use_container_width=True):
                                        st.session_state["chat_vendedor_selecionado"] = row_v['id']
                                        st.session_state["pagina_atual"] = "chat"
                                        st.rerun()

                        st.markdown("---")
                        st.markdown("##### Desempenho")
                        
                        kpi1, kpi2, kpi3, kpi4 = st.columns(4)
                        kpi1.metric("Leads", row_v['total_leads'])
                        kpi2.metric("Fichas", row_v['total_fichas'])
                        kpi3.metric("Aprovados", row_v['total_aprovados'])
                        kpi4.metric("Vendas", row_v['total_vendas'])

    except Exception as e:
        st.error(f"Erro ao carregar vendedores: {e}")

# ==========================================
# PÁGINA 3: CENTRAL DE CHAT (LAYOUT CARD + CONVERSA)
# ==========================================
elif st.session_state["pagina_atual"] == "chat":
    st.title("Central de Mensagens")
    st.markdown("---")

    meu_vendedor_id = user.get("vendedor_id")

    if not meu_vendedor_id:
        st.warning("Seu usuário não tem um perfil de vendedor associado (`vendedor_id` é nulo). Vincule seu usuário a um vendedor para utilizar o chat.")
    else:
        df_outros = obter_vendedores()
        df_outros = df_outros[df_outros["id"] != meu_vendedor_id]

        if df_outros.empty:
            st.info("Não há outros vendedores no sistema para conversar.")
        else:
            # Garante uma seleção padrão caso não haja nenhuma ativa
            if st.session_state["chat_vendedor_selecionado"] not in df_outros["id"].values:
                st.session_state["chat_vendedor_selecionado"] = df_outros["id"].iloc[0]

            # Layout estilo WhatsApp Web: 1 Coluna Lateral de Cards (1.2) + 1 Área Principal de Conversa (3)
            col_lista, col_conversa = st.columns([1.2, 3])

            # --- LISTA LATERAL DE CARDS DOS VENDEDORES ---
            with col_lista:
                st.markdown("##### 👥 Contatos")
                for _, v_row in df_outros.iterrows():
                    vid = v_row['id']
                    vnome = v_row['nome']
                    vfoto = v_row['foto_url'] if pd.notnull(v_row['foto_url']) and v_row['foto_url'] != "" else "https://cdn-icons-png.flaticon.com/512/3135/3135715.png"
                    
                    nao_lidas = contar_mensagens_nao_lidas(meu_vendedor_id, vid)
                    
                    # Estilização visual do card ativo/inativo
                    eh_selecionado = (vid == st.session_state["chat_vendedor_selecionado"])
                    tipo_botao = "primary" if eh_selecionado else "secondary"
                    
                    # Label com indicação de mensagem pendente
                    btn_label = f"💬 {vnome}"
                    if nao_lidas > 0:
                        btn_label = f"🔴 {vnome} ({nao_lidas})"

                    with st.container(border=True):
                        c_img, c_info = st.columns([1, 2.5])
                        with c_img:
                            st.image(vfoto, width=45)
                        with c_info:
                            if st.button(btn_label, key=f"card_chat_v_{vid}", use_container_width=True, type=tipo_botao):
                                st.session_state["chat_vendedor_selecionado"] = vid
                                st.rerun()

            # --- ÁREA DE CHAT / CONVERSA PRINCIPAL ---
            with col_conversa:
                outro_vid = st.session_state["chat_vendedor_selecionado"]
                outro_vendedor = df_outros[df_outros["id"] == outro_vid].iloc[0]
                
                # Marca como lidas automaticamente
                marcar_mensagens_como_lidas(meu_vendedor_id, outro_vid)

                st.markdown(f"### Conversa com **{outro_vendedor['nome']}**")

                query_chat = text("""
                    SELECT 
                        c.id, c.remetente_id, c.destinatario_id, c.mensagem, c.created_at,
                        v.nome AS nome_remetente
                    FROM public.chat_mensagens c
                    JOIN public.vendedores v ON v.id = c.remetente_id
                    WHERE 
                        (c.remetente_id = :meu_id AND c.destinatario_id = :outro_id) OR
                        (c.remetente_id = :outro_id AND c.destinatario_id = :meu_id)
                    ORDER BY c.created_at ASC
                """)

                with engine.connect() as conn:
                    df_chat = pd.read_sql_query(query_chat, conn, params={"meu_id": meu_vendedor_id, "outro_id": outro_vid})

                chat_container = st.container(height=450)
                with chat_container:
                    if df_chat.empty:
                        st.caption("Sem histórico de mensagens. Comece a conversa digitando abaixo!")
                    else:
                        for _, msg in df_chat.iterrows():
                            is_me = (msg["remetente_id"] == meu_vendedor_id)
                            hora_str = pd.to_datetime(msg["created_at"]).strftime("%H:%M - %d/%m")
                            with st.chat_message("user" if is_me else "assistant", avatar="👤" if is_me else "💬"):
                                st.caption(f"**{msg['nome_remetente']}** • {hora_str}")
                                st.write(msg["mensagem"])

                if novo_texto := st.chat_input("Digite sua mensagem..."):
                    query_envio = text("""
                        INSERT INTO public.chat_mensagens (remetente_id, destinatario_id, mensagem, created_at, lida)
                        VALUES (:meu_id, :outro_id, :msg, NOW(), FALSE)
                    """)
                    with engine.begin() as conn:
                        conn.execute(query_envio, {
                            "meu_id": meu_vendedor_id,
                            "outro_id": outro_vid,
                            "msg": novo_texto.strip()
                        })
                    st.rerun()