import streamlit as st
import pandas as pd
from sqlalchemy import text
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from alpha import contar_mensagens_nao_lidas

def renderizar(user, engine, contar_mensagens_nao_lidas):
    tipo_usuario = user.get("tipo", "vendedor")
    with st.sidebar:
        st.markdown(f"### 👤 Logado como:\n**{user.get('nome', '')}**")
        st.caption(f"Perfil: {tipo_usuario.upper()}")
        
        if st.button("Sair (Logout)", use_container_width=True):
            logout()
            
        st.markdown("---")
        st.header("Navegação")
        
        # --- NAVEGAÇÃO ---
        btn_p_leads = "primary" if st.session_state["pagina_atual"] == "leads" else "secondary"
        if st.button("Painel de Leads", use_container_width=True, type=btn_p_leads):
            st.session_state["pagina_atual"] = "leads"
            st.rerun()

        btn_p_vendedores = "primary" if st.session_state["pagina_atual"] == "vendedores" else "secondary"
        if st.button("Equipe de Vendedores", use_container_width=True, type=btn_p_vendedores):
            st.session_state["pagina_atual"] = "vendedores"
            st.rerun()

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

        # --- FICHAS ---
        btn_p_fp = "primary" if st.session_state["pagina_atual"] == "ficha_pendente" else "secondary"
        if st.button("Fichas Pendentes", use_container_width=True, type=btn_p_fp):
            st.session_state["pagina_atual"] = "ficha_pendente"
            st.rerun()

        btn_p_fa = "primary" if st.session_state["pagina_atual"] == "ficha_aprovada" else "secondary"
        if st.button("Fichas Aprovadas", use_container_width=True, type=btn_p_fa):
            st.session_state["pagina_atual"] = "ficha_aprovada"
            st.rerun()

        btn_p_fn = "primary" if st.session_state["pagina_atual"] == "ficha_negada" else "secondary"
        if st.button("Fichas Negadas", use_container_width=True, type=btn_p_fn):
            st.session_state["pagina_atual"] = "ficha_negada"
            st.rerun()

    # ==========================================
    # PÁGINA 1: PAINEL DE LEADS
    # ==========================================
    if st.session_state["pagina_atual"] == "leads":
        # Buscar métricas reais do banco
        try:
            query_metrics = text("""
                SELECT 
                    COUNT(*) AS total_leads,
                    COUNT(*) FILTER (WHERE gerou_ficha = TRUE) AS total_fichas,
                    COUNT(*) FILTER (WHERE aprovou_credito = TRUE) AS total_aprovados,
                    COUNT(*) FILTER (WHERE venda_concluida = TRUE) AS total_vendidos
                FROM public.leads
                WHERE (:is_admin = TRUE OR vendedor_id = :vendedor_id)
            """)
            with engine.connect() as conn:
                res_metrics = conn.execute(query_metrics, {
                    "is_admin": user["is_admin"],
                    "vendedor_id": user["vendedor_id"]
                }).fetchone()
                
                total_leads = res_metrics[0] if res_metrics else 0
                total_fichas = res_metrics[1] if res_metrics else 0
                total_aprovados = res_metrics[2] if res_metrics else 0
                total_vendidos = res_metrics[3] if res_metrics else 0
        except Exception:
            total_leads, total_fichas, total_aprovados, total_vendidos = 0, 0, 0, 0

        col_header, col_m1, col_m2, col_m3, col_m4 = st.columns([1.8, 1, 1, 1, 1])

        with col_header:
            st.title("Painel de Controle")

        with col_m1:
            st.metric(label="Total Leads", value=total_leads)
            tipo_btn = "primary" if st.session_state.get("filtro_categoria") == "todos" else "secondary"
            if st.button("Ver Todos", key="btn_f_todos", use_container_width=True, type=tipo_btn):
                st.session_state["filtro_categoria"] = "todos"
                st.rerun()

        with col_m2:
            st.metric(label="Fichas Geradas", value=total_fichas)
            tipo_btn = "primary" if st.session_state.get("filtro_categoria") == "fichas" else "secondary"
            if st.button("Filtrar Fichas", key="btn_f_fichas", use_container_width=True, type=tipo_btn):
                st.session_state["filtro_categoria"] = "fichas"
                st.rerun()

        with col_m3:
            st.metric(label="Aprovados", value=total_aprovados)
            tipo_btn = "primary" if st.session_state.get("filtro_categoria") == "aprovados" else "secondary"
            if st.button("Filtrar Aprovados", key="btn_f_aprovados", use_container_width=True, type=tipo_btn):
                st.session_state["filtro_categoria"] = "aprovados"
                st.rerun()

        with col_m4:
            st.metric(label="Vendidos", value=total_vendidos)
            tipo_btn = "primary" if st.session_state.get("filtro_categoria") == "vendidos" else "secondary"
            if st.button("Filtrar Vendidos", key="btn_f_vendidos", use_container_width=True, type=tipo_btn):
                st.session_state["filtro_categoria"] = "vendidos"
                st.rerun()

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
                            st.error(f"Erro ao inserir lead: {e}")

        st.markdown("---")
        termo_busca = st.text_input("Buscar Lead (Nome, CPF ou Telefone)", placeholder="Digite o nome, CPF ou número para filtrar...")
        if st.button("➕ Adicionar Novo Lead", key="btn_add_lead_busca", use_container_width=True, type="primary"):
            st.session_state['abrir_formulario'] = True
            st.rerun()

        st.subheader("Leads Cadastrados")

        try:
            df_vendedores = obter_vendedores()
            cat_filtro = st.session_state.get("filtro_categoria", "todos")
            
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