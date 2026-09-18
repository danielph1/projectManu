import hashlib
import hmac
import secrets
from datetime import date
from typing import Any, Dict, Optional, Set

import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text


# ============================================================
# CONFIGURAÇÃO
# ============================================================

st.set_page_config(
    page_title="CRM - Gestão de Leads",
    page_icon="📊",
    layout="wide",
)


# ============================================================
# PERFIS E PERMISSÕES
# ============================================================
#
# Os valores abaixo aceitam tanto os nomes novos quanto os nomes
# que aparecem nas suas tabelas atuais:
#
# vendedor, admin, elfenai, documento
#
# Internamente, o programa normaliza:
# admin       -> gerente
# elfenai     -> elfen_ai
# documento   -> documentista
#

ROLE_ALIASES = {
    "admin": "gerente",
    "administrador": "gerente",
    "gerente": "gerente",
    "dono": "gerente",
    "proprietario": "gerente",
    "proprietário": "gerente",
    "owner": "gerente",
    "vendedor": "vendedor",
    "elfenai": "elfen_ai",
    "elfen ai": "elfen_ai",
    "elfen_ai": "elfen_ai",
    "documento": "documentista",
    "documentista": "documentista",
    "financeiro": "financeiro",
}


PERMISSIONS: Dict[str, Set[str]] = {
    "vendedor": {
        "view_leads",
        "create_lead",
        "edit_own_lead",
        "delete_own_lead",
        "use_chat",
        "view_own_metrics",
        "view_documents",
        "view_tasks",
        "respond_tasks",
        "view_goals",
        "view_credit_fichas",
        "edit_own_credit_data",
    },
    "gerente": {
        # O gerente é o superadministrador operacional da loja.
        # A função usuario_tem() trata "*" como acesso total.
        "*",
    },
    "elfen_ai": {
        "view_leads",
        "use_elfen_ai",
        "view_tasks",
        "respond_tasks",
        "view_goals",
        "view_credit_fichas",
        "edit_bank_results",
    },
    "financeiro": {
        "view_leads",
        "view_financial",
        "view_tasks",
        "respond_tasks",
        "view_goals",
        "view_credit_fichas",
        "edit_sales_boleto",
        "view_credit_metrics",
    },
    "documentista": {
        "view_leads",
        "view_documents",
        "view_tasks",
        "respond_tasks",
        "view_goals",
        "view_credit_fichas",
    },
}


def normalizar_tipo(tipo: Any) -> str:
    """Converte os nomes gravados no banco para um nome interno único."""
    valor = str(tipo or "").strip().lower().replace("-", "_")
    return ROLE_ALIASES.get(valor, valor)


def usuario_tem(permissao: str) -> bool:
    usuario = st.session_state.get("usuario_logado")
    if not usuario:
        return False
    permissoes_usuario = PERMISSIONS.get(usuario["tipo"], set())
    return "*" in permissoes_usuario or permissao in permissoes_usuario


def usuario_e_gerente() -> bool:
    return st.session_state.get("usuario_logado", {}).get("tipo") == "gerente"


# ============================================================
# BANCO DE DADOS
# ============================================================

@st.cache_resource
def get_engine():
    """
    A URL deve estar em .streamlit/secrets.toml ou nos Secrets do
    Streamlit Cloud:

    [postgres]
    url = "postgresql://..."
    """
    db_url = st.secrets["postgres"]["url"]
    return create_engine(db_url, pool_pre_ping=True)


engine = get_engine()


# ============================================================
# SENHAS
# ============================================================
#
# A sua tabela atual chama a coluna de senha_hash, mas os valores
# exibidos na imagem parecem estar em texto puro ("123456").
#
# Esta implementação:
# 1. aceita temporariamente a senha antiga;
# 2. depois de um login correto, troca automaticamente por PBKDF2;
# 3. nunca grava a senha nova em texto puro.
#
# O ideal, em uma próxima etapa, é migrar para Supabase Auth.

PBKDF2_ITERATIONS = 310_000
PASSWORD_PREFIX = "pbkdf2_sha256"


def criar_hash_senha(senha: str) -> str:
    salt = secrets.token_bytes(16)
    derivada = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return (
        f"{PASSWORD_PREFIX}${PBKDF2_ITERATIONS}$"
        f"{salt.hex()}${derivada.hex()}"
    )


def verificar_senha(senha_digitada: str, senha_salva: str) -> tuple[bool, bool]:
    """
    Retorna:
      (senha_correta, precisa_migrar)

    precisa_migrar=True significa que o valor antigo estava em texto
    puro e deve ser substituído por um hash seguro.
    """
    senha_salva = str(senha_salva or "")

    if not senha_salva.startswith(f"{PASSWORD_PREFIX}$"):
        senha_correta = hmac.compare_digest(senha_digitada, senha_salva)
        return senha_correta, senha_correta

    try:
        prefixo, iteracoes, salt_hex, hash_hex = senha_salva.split("$")
        iteracoes_int = int(iteracoes)
        salt = bytes.fromhex(salt_hex)
        hash_esperado = bytes.fromhex(hash_hex)
        hash_recebido = hashlib.pbkdf2_hmac(
            "sha256",
            senha_digitada.encode("utf-8"),
            salt,
            iteracoes_int,
        )
        return hmac.compare_digest(hash_recebido, hash_esperado), False
    except (ValueError, TypeError):
        return False, False


# ============================================================
# AUTENTICAÇÃO E SESSÃO
# ============================================================

def autenticar(login_input: str, senha_input: str) -> bool:
    try:
        query = text(
            """
            SELECT id, nome, login, senha_hash, tipo, vendedor_id, ativo
            FROM public.usuarios
            WHERE LOWER(login) = LOWER(:login)
            LIMIT 1
            """
        )

        with engine.connect() as conn:
            result = conn.execute(
                query,
                {"login": login_input.strip()},
            ).mappings().first()

        if not result:
            return False

        if result["ativo"] is False:
            st.error("Este usuário está inativo.")
            return False

        senha_correta, precisa_migrar = verificar_senha(
            senha_input.strip(),
            result["senha_hash"],
        )

        if not senha_correta:
            return False

        tipo = normalizar_tipo(result["tipo"])

        if tipo not in PERMISSIONS:
            st.error(f"O tipo de usuário '{result['tipo']}' não está configurado.")
            return False

        # Migração automática dos registros antigos que estavam
        # armazenados como texto puro.
        if precisa_migrar:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        """
                        UPDATE public.usuarios
                        SET senha_hash = :senha_hash
                        WHERE id = :id
                        """
                    ),
                    {
                        "senha_hash": criar_hash_senha(senha_input.strip()),
                        "id": result["id"],
                    },
                )

        st.session_state["usuario_logado"] = {
            "id": result["id"],
            "nome": result["nome"],
            "login": result["login"],
            "tipo": tipo,
            "tipo_original": result["tipo"],
            "vendedor_id": result["vendedor_id"],
            "is_admin": tipo == "gerente",
        }

        return True

    except Exception as erro:
        st.error(f"Erro ao conectar para login: {erro}")
        return False


def limpar_sessao():
    chaves_para_limpar = [
        "usuario_logado",
        "filtro_categoria",
        "pagina_atual",
        "chat_vendedor_selecionado",
        "abrir_formulario",
    ]

    for chave in chaves_para_limpar:
        st.session_state.pop(chave, None)

    st.rerun()


def inicializar_sessao():
    defaults = {
        "usuario_logado": None,
        "filtro_categoria": "todos",
        "pagina_atual": "leads",
        "chat_vendedor_selecionado": None,
        "abrir_formulario": False,
        "banco_filtro": None,
    }

    for chave, valor in defaults.items():
        if chave not in st.session_state:
            st.session_state[chave] = valor


inicializar_sessao()


# ============================================================
# ESCOPO DE DADOS POR PERFIL
# ============================================================

def escopo_leads(usuario: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    """
    Retorna:
      - uma condição SQL fixa, criada pelo sistema;
      - os parâmetros dessa condição.

    Nenhum valor digitado pelo usuário é inserido diretamente no SQL.
    """
    tipo = usuario["tipo"]

    if tipo == "vendedor":
        if not usuario.get("vendedor_id"):
            return "FALSE", {}
        return "l.vendedor_id = :scope_vendedor_id", {
            "scope_vendedor_id": usuario["vendedor_id"],
        }

    if tipo == "gerente":
        return "TRUE", {}

    if tipo == "elfen_ai":
        return "TRUE", {}

    if tipo == "financeiro":
        return """
            (
                COALESCE(l.aprovou_credito, FALSE) = TRUE
                OR COALESCE(l.venda_concluida, FALSE) = TRUE
                OR COALESCE(l.vendeu, FALSE) = TRUE
            )
        """, {}

    if tipo == "documentista":
        return "COALESCE(l.gerou_ficha, FALSE) = TRUE", {}

    return "FALSE", {}


def pode_editar_lead(lead: pd.Series, usuario: Dict[str, Any]) -> bool:
    if usuario["tipo"] == "gerente":
        return True

    return (
        usuario["tipo"] == "vendedor"
        and usuario.get("vendedor_id") is not None
        and lead.get("vendedor_id") == usuario["vendedor_id"]
    )


def pode_deletar_lead(lead: pd.Series, usuario: Dict[str, Any]) -> bool:
    if usuario["tipo"] == "gerente":
        return True

    return (
        usuario["tipo"] == "vendedor"
        and usuario.get("vendedor_id") is not None
        and lead.get("vendedor_id") == usuario["vendedor_id"]
    )


# ============================================================
# CONSULTAS AUXILIARES
# ============================================================

def obter_vendedores() -> pd.DataFrame:
    try:
        query = text(
            """
            SELECT id, nome
            FROM public.vendedores
            WHERE COALESCE(ativo, TRUE) = TRUE
            ORDER BY nome
            """
        )

        with engine.connect() as conn:
            df = pd.read_sql_query(query, conn)

        if "foto_url" not in df.columns:
            df["foto_url"] = None

        return df

    except Exception:
        # Compatibilidade caso a tabela ainda não tenha a coluna ativo.
        try:
            with engine.connect() as conn:
                df = pd.read_sql_query(
                    text(
                        """
                        SELECT id, nome
                        FROM public.vendedores
                        ORDER BY nome
                        """
                    ),
                    conn,
                )
            df["foto_url"] = None
            return df
        except Exception:
            return pd.DataFrame(columns=["id", "nome", "foto_url"])


def obter_metricas(usuario: Dict[str, Any]) -> Dict[str, int]:
    condicao, parametros = escopo_leads(usuario)

    query = text(
        f"""
        SELECT
            COUNT(l.id) AS total_leads,
            COUNT(l.id) FILTER (
                WHERE COALESCE(l.gerou_ficha, FALSE) = TRUE
            ) AS total_fichas,
            COUNT(l.id) FILTER (
                WHERE COALESCE(l.aprovou_credito, FALSE) = TRUE
            ) AS total_aprovados,
            COUNT(l.id) FILTER (
                WHERE
                    COALESCE(l.venda_concluida, FALSE) = TRUE
                    OR COALESCE(l.vendeu, FALSE) = TRUE
            ) AS total_vendidos
        FROM public.leads l
        WHERE {condicao}
        """
    )

    try:
        with engine.connect() as conn:
            result = conn.execute(query, parametros).mappings().first()

        return {
            "total_leads": int(result["total_leads"] or 0),
            "total_fichas": int(result["total_fichas"] or 0),
            "total_aprovados": int(result["total_aprovados"] or 0),
            "total_vendidos": int(result["total_vendidos"] or 0),
        }
    except Exception as erro:
        st.error(f"Erro nas métricas: {erro}")
        return {
            "total_leads": 0,
            "total_fichas": 0,
            "total_aprovados": 0,
            "total_vendidos": 0,
        }


def buscar_leads(
    usuario: Dict[str, Any],
    categoria: str,
    termo_busca: str,
) -> pd.DataFrame:
    escopo, parametros = escopo_leads(usuario)

    filtros = [
        escopo,
        """
        (
            :categoria = 'todos'
            OR (:categoria = 'fichas' AND l.gerou_ficha = TRUE)
            OR (:categoria = 'aprovados' AND l.aprovou_credito = TRUE)
            OR (:categoria = 'vendidos' AND (
                l.venda_concluida = TRUE OR l.vendeu = TRUE
            ))
        )
        """,
        """
        (
            :busca = ''
            OR l.nome_lead ILIKE :termo
            OR l.cpf ILIKE :termo
            OR l.telefone ILIKE :termo
            OR l.observacao ILIKE :termo
        )
        """,
    ]

    parametros.update(
        {
            "categoria": categoria,
            "busca": termo_busca.strip(),
            "termo": f"%{termo_busca.strip()}%",
        }
    )

    query = text(
        f"""
        SELECT
            l.id,
            l.nome_lead,
            l.telefone,
            l.data_lead,
            l.gerou_ficha,
            l.venda_concluida,
            l.vendeu,
            l.cpf,
            l.data_nascimento,
            l.habilitado,
            l.aprovou_credito,
            l.observacao,
            l.updated_at,
            l.vendedor_id,
            v.nome AS nome_vendedor
        FROM public.leads l
        LEFT JOIN public.vendedores v
            ON v.id = l.vendedor_id
        WHERE {" AND ".join(f"({filtro})" for filtro in filtros)}
        ORDER BY l.updated_at DESC NULLS LAST, l.id DESC
        """
    )

    with engine.connect() as conn:
        return pd.read_sql_query(query, conn, params=parametros)


def marcar_mensagens_como_lidas(meu_id: int, outro_id: int) -> None:
    if not meu_id or not outro_id:
        return

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE public.chat_mensagens
                SET lida = TRUE
                WHERE destinatario_id = :meu_id
                  AND remetente_id = :outro_id
                  AND lida = FALSE
                """
            ),
            {"meu_id": meu_id, "outro_id": outro_id},
        )


def contar_mensagens_nao_lidas(
    meu_id: Optional[int],
    remetente_id: Optional[int] = None,
) -> int:
    if not meu_id:
        return 0

    if remetente_id:
        query = text(
            """
            SELECT COUNT(*)
            FROM public.chat_mensagens
            WHERE destinatario_id = :meu_id
              AND remetente_id = :remetente_id
              AND lida = FALSE
            """
        )
        parametros = {
            "meu_id": meu_id,
            "remetente_id": remetente_id,
        }
    else:
        query = text(
            """
            SELECT COUNT(*)
            FROM public.chat_mensagens
            WHERE destinatario_id = :meu_id
              AND lida = FALSE
            """
        )
        parametros = {"meu_id": meu_id}

    try:
        with engine.connect() as conn:
            return int(conn.execute(query, parametros).scalar() or 0)
    except Exception:
        return 0


def obter_usuarios_ativos() -> pd.DataFrame:
    query = text(
        """
        SELECT id, nome, login, tipo, ativo
        FROM public.usuarios
        WHERE COALESCE(ativo, TRUE) = TRUE
        ORDER BY nome
        """
    )

    with engine.connect() as conn:
        return pd.read_sql_query(query, conn)


def contar_tarefas_nao_visualizadas(usuario_id: int) -> int:
    query = text(
        """
        SELECT COUNT(*)
        FROM public.tarefas
        WHERE destinatario_id = :usuario_id
          AND visualizada_at IS NULL
        """
    )

    try:
        with engine.connect() as conn:
            return int(
                conn.execute(query, {"usuario_id": usuario_id}).scalar()
                or 0
            )
    except Exception:
        # Mantém a aplicação funcionando caso a migração ainda não
        # tenha sido executada.
        return 0


def marcar_tarefas_como_visualizadas(usuario_id: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE public.tarefas
                SET visualizada_at = NOW(),
                    updated_at = NOW()
                WHERE destinatario_id = :usuario_id
                  AND visualizada_at IS NULL
                """
            ),
            {"usuario_id": usuario_id},
        )


def obter_tarefas(usuario: Dict[str, Any]) -> pd.DataFrame:
    if usuario["tipo"] == "gerente":
        filtro = "TRUE"
        parametros = {}
    else:
        filtro = "t.destinatario_id = :usuario_id"
        parametros = {"usuario_id": usuario["id"]}

    query = text(
        f"""
        SELECT
            t.id,
            t.titulo,
            t.descricao,
            t.destinatario_id,
            t.criado_por_id,
            t.resposta,
            t.observacao,
            t.visualizada_at,
            t.respondida_at,
            t.created_at,
            t.updated_at,
            destinatario.nome AS destinatario_nome,
            criador.nome AS criador_nome
        FROM public.tarefas t
        JOIN public.usuarios destinatario
            ON destinatario.id = t.destinatario_id
        JOIN public.usuarios criador
            ON criador.id = t.criado_por_id
        WHERE {filtro}
        ORDER BY
            CASE WHEN t.resposta IS NULL THEN 0 ELSE 1 END,
            t.created_at DESC
        """
    )

    with engine.connect() as conn:
        return pd.read_sql_query(query, conn, params=parametros)


def obter_metas(usuario: Dict[str, Any]) -> pd.DataFrame:
    if usuario["tipo"] == "gerente":
        filtro = "TRUE"
        parametros = {}
    else:
        filtro = """
            m.destinatario_id = :usuario_id
            OR m.destinatario_id IS NULL
        """
        parametros = {"usuario_id": usuario["id"]}

    query = text(
        f"""
        SELECT
            m.id,
            m.titulo,
            m.descricao,
            m.unidade,
            m.valor_objetivo,
            m.periodo_inicio,
            m.periodo_fim,
            m.destinatario_id,
            m.criado_por_id,
            m.ativo,
            m.created_at,
            m.updated_at,
            destinatario.nome AS destinatario_nome,
            criador.nome AS criador_nome
        FROM public.metas m
        LEFT JOIN public.usuarios destinatario
            ON destinatario.id = m.destinatario_id
        JOIN public.usuarios criador
            ON criador.id = m.criado_por_id
        WHERE ({filtro})
          AND m.ativo = TRUE
        ORDER BY m.periodo_fim ASC NULLS LAST, m.created_at DESC
        """
    )

    with engine.connect() as conn:
        return pd.read_sql_query(query, conn, params=parametros)


def converter_data(valor: Any) -> date:
    if valor is None or pd.isna(valor):
        return date.today()
    return pd.to_datetime(valor).date()


def numero_seguro(valor: Any, padrao: float = 0.0) -> float:
    if valor is None or pd.isna(valor):
        return padrao
    return float(valor)


def inteiro_seguro(valor: Any, padrao: int = 1) -> int:
    if valor is None or pd.isna(valor):
        return padrao
    return int(valor)


BANCOS_CREDITO = [
    "Itau",
    "Bradesco",
    "Santander",
    "Safra",
    "Creditas",
    "BV",
    "Pan",
]


def contar_notificacoes_nao_lidas(usuario_id: int) -> int:
    query = text(
        """
        SELECT COUNT(*)
        FROM public.notificacoes
        WHERE usuario_id = :usuario_id
          AND lida = FALSE
        """
    )

    try:
        with engine.connect() as conn:
            return int(
                conn.execute(query, {"usuario_id": usuario_id}).scalar()
                or 0
            )
    except Exception:
        return 0


def marcar_notificacoes_como_lidas(usuario_id: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE public.notificacoes
                SET lida = TRUE
                WHERE usuario_id = :usuario_id
                  AND lida = FALSE
                """
            ),
            {"usuario_id": usuario_id},
        )


def criar_notificacao_vendedor(
    vendedor_id: Optional[int],
    ficha_id: int,
    titulo: str,
    mensagem: str,
    conn: Any,
) -> None:
    if not vendedor_id:
        return

    usuario = conn.execute(
        text(
            """
            SELECT id
            FROM public.usuarios
            WHERE vendedor_id = :vendedor_id
              AND COALESCE(ativo, TRUE) = TRUE
            ORDER BY id
            LIMIT 1
            """
        ),
        {"vendedor_id": vendedor_id},
    ).mappings().first()

    if not usuario:
        return

    conn.execute(
        text(
            """
            INSERT INTO public.notificacoes (
                usuario_id,
                tipo,
                titulo,
                mensagem,
                ficha_id
            )
            VALUES (
                :usuario_id,
                'resultado_ficha',
                :titulo,
                :mensagem,
                :ficha_id
            )
            """
        ),
        {
            "usuario_id": usuario["id"],
            "titulo": titulo,
            "mensagem": mensagem,
            "ficha_id": ficha_id,
        },
    )


def criar_ficha_credito(
    conn: Any,
    lead_id: int,
    vendedor_id: Optional[int],
    valor_entrada: float,
    usuario_id: int,
) -> int:
    """
    Cria a ficha uma única vez e inicializa os sete bancos como pendentes.
    """
    ficha_existente = conn.execute(
        text(
            """
            SELECT id
            FROM public.fichas_credito
            WHERE lead_id = :lead_id
            """
        ),
        {"lead_id": lead_id},
    ).scalar()

    if ficha_existente:
        return int(ficha_existente)

    ficha_id = conn.execute(
        text(
            """
            INSERT INTO public.fichas_credito (
                lead_id,
                vendedor_id,
                valor_entrada,
                criado_por_id,
                atualizado_por_id
            )
            VALUES (
                :lead_id,
                :vendedor_id,
                :valor_entrada,
                :usuario_id,
                :usuario_id
            )
            RETURNING id
            """
        ),
        {
            "lead_id": lead_id,
            "vendedor_id": vendedor_id,
            "valor_entrada": max(float(valor_entrada or 0), 0),
            "usuario_id": usuario_id,
        },
    ).scalar_one()

    for banco in BANCOS_CREDITO:
        conn.execute(
            text(
                """
                INSERT INTO public.ficha_bancos (ficha_id, banco)
                VALUES (:ficha_id, :banco)
                ON CONFLICT (ficha_id, banco) DO NOTHING
                """
            ),
            {"ficha_id": ficha_id, "banco": banco},
        )

    return int(ficha_id)


def obter_fichas_credito(
    usuario: Dict[str, Any],
    status: str = "todas",
    busca: str = "",
    banco_filtro: Optional[str] = None,
) -> pd.DataFrame:
    if usuario["tipo"] == "vendedor":
        filtro_acesso = "f.vendedor_id = :vendedor_id"
        parametros: Dict[str, Any] = {
            "vendedor_id": usuario.get("vendedor_id")
        }
    else:
        filtro_acesso = "TRUE"
        parametros = {}

    pode_ver_financeiro = usuario["tipo"] in {"financeiro", "gerente"}
    campos_financeiros = """
            f.valor_entrada,
            f.comprou,
            f.data_compra,
            f.valor_veiculo,
            f.valor_financiado,
            f.banco_contratado,
            f.valor_liberado,
            f.entrada_total,
            f.entrada_paga,
            f.valor_pendente,
            f.gerou_boleto,
            f.boleto_valor,
            f.boleto_meses,
            f.boleto_total,
    """ if pode_ver_financeiro else """
            NULL::numeric AS valor_entrada,
            NULL::boolean AS comprou,
            NULL::date AS data_compra,
            NULL::numeric AS valor_veiculo,
            NULL::numeric AS valor_financiado,
            NULL::varchar AS banco_contratado,
            NULL::numeric AS valor_liberado,
            NULL::numeric AS entrada_total,
            NULL::numeric AS entrada_paga,
            NULL::numeric AS valor_pendente,
            NULL::boolean AS gerou_boleto,
            NULL::numeric AS boleto_valor,
            NULL::integer AS boleto_meses,
            NULL::numeric AS boleto_total,
    """

    filtro_status = """
        (
            :status = 'todas'
            OR f.status_geral = :status
        )
    """
    filtro_busca = """
        (
            :busca = ''
            OR l.nome_lead ILIKE :termo
            OR l.nome_completo ILIKE :termo
            OR l.cpf ILIKE :termo
            OR l.telefone ILIKE :termo
            OR v.nome ILIKE :termo
        )
    """

    filtro_banco = "TRUE"
    join_banco = ""
    if banco_filtro:
        join_banco = """
            JOIN public.ficha_bancos banco_filtro
                ON banco_filtro.ficha_id = f.id
               AND banco_filtro.banco = :banco_filtro
        """
        filtro_banco = "banco_filtro.banco = :banco_filtro"

    parametros.update(
        {
            "status": status,
            "busca": busca.strip(),
            "termo": f"%{busca.strip()}%",
            "banco_filtro": banco_filtro,
        }
    )

    query = text(
        f"""
        SELECT
            f.id,
            f.lead_id,
            f.vendedor_id,
            f.status_geral,
            {campos_financeiros}
            f.created_at,
            f.updated_at,
            l.nome_lead,
            l.nome_completo,
            l.cpf,
            l.data_nascimento,
            l.habilitado,
            l.produto_interesse,
            l.telefone,
            v.nome AS vendedor_nome
        FROM public.fichas_credito f
        JOIN public.leads l
            ON l.id = f.lead_id
        LEFT JOIN public.vendedores v
            ON v.id = f.vendedor_id
        {join_banco}
        WHERE ({filtro_acesso})
          AND ({filtro_status})
          AND ({filtro_busca})
          AND ({filtro_banco})
        ORDER BY f.updated_at DESC, f.id DESC
        """
    )

    with engine.connect() as conn:
        return pd.read_sql_query(query, conn, params=parametros)


def obter_analises_banco(ficha_id: int) -> pd.DataFrame:
    query = text(
        """
        SELECT
            id,
            ficha_id,
            banco,
            status,
            valor_financiado,
            valor_entrada,
            parcela_48,
            parcela_64,
            observacao,
            atualizado_por_id,
            updated_at
        FROM public.ficha_bancos
        WHERE ficha_id = :ficha_id
        ORDER BY
            CASE banco
                WHEN 'Itau' THEN 1
                WHEN 'Bradesco' THEN 2
                WHEN 'Santander' THEN 3
                WHEN 'Safra' THEN 4
                WHEN 'Creditas' THEN 5
                WHEN 'BV' THEN 6
                WHEN 'Pan' THEN 7
                ELSE 99
            END
        """
    )

    with engine.connect() as conn:
        return pd.read_sql_query(
            query,
            conn,
            params={"ficha_id": ficha_id},
        )


def obter_fichas_com_valor_pendente() -> pd.DataFrame:
    query = text(
        """
        SELECT
            f.id,
            f.lead_id,
            l.nome_lead,
            l.nome_completo,
            l.cpf,
            l.telefone,
            l.data_nascimento,
            l.habilitado,
            l.produto_interesse,
            v.nome AS vendedor_nome,
            f.data_compra,
            f.valor_veiculo,
            f.banco_contratado,
            f.valor_liberado,
            f.entrada_total,
            f.entrada_paga,
            f.valor_pendente,
            f.boleto_valor,
            f.boleto_meses,
            f.boleto_total
        FROM public.fichas_credito f
        JOIN public.leads l
            ON l.id = f.lead_id
        LEFT JOIN public.vendedores v
            ON v.id = f.vendedor_id
        WHERE f.comprou = TRUE
          AND f.gerou_boleto = TRUE
          AND f.valor_pendente > 0
        ORDER BY f.valor_pendente DESC, f.updated_at DESC
        """
    )

    with engine.connect() as conn:
        return pd.read_sql_query(query, conn)


def recalcular_status_ficha(conn: Any, ficha_id: int) -> str:
    statuses = conn.execute(
        text(
            """
            SELECT status
            FROM public.ficha_bancos
            WHERE ficha_id = :ficha_id
            """
        ),
        {"ficha_id": ficha_id},
    ).scalars().all()

    if any(status == "aprovado" for status in statuses):
        novo_status = "aprovada"
    elif statuses and all(status == "negado" for status in statuses):
        novo_status = "negada"
    else:
        novo_status = "pendente"

    conn.execute(
        text(
            """
            UPDATE public.fichas_credito
            SET status_geral = :status,
                updated_at = NOW()
            WHERE id = :ficha_id
            """
        ),
        {"status": novo_status, "ficha_id": ficha_id},
    )

    conn.execute(
        text(
            """
            UPDATE public.leads l
            SET aprovou_credito = CASE
                    WHEN :status = 'aprovada' THEN TRUE
                    WHEN :status = 'negada' THEN FALSE
                    ELSE NULL
                END,
                updated_at = NOW()
            FROM public.fichas_credito f
            WHERE f.id = :ficha_id
              AND l.id = f.lead_id
            """
        ),
        {"status": novo_status, "ficha_id": ficha_id},
    )

    return novo_status


def salvar_analise_banco(
    usuario: Dict[str, Any],
    ficha: pd.Series,
    banco_id: int,
    banco: str,
    status: str,
    valor_financiado: Optional[float],
    valor_entrada: Optional[float],
    parcela_48: Optional[float],
    parcela_64: Optional[float],
    observacao: str,
) -> None:
    if not usuario_tem("edit_bank_results"):
        st.error("Você não pode alterar análises bancárias.")
        return

    if status == "aprovado" and valor_financiado is None:
        st.error("Uma aprovação precisa ter o valor financiado.")
        return

    # Para uma recusa ou pendência, os valores financeiros ficam nulos.
    if status != "aprovado":
        valor_financiado = None
        valor_entrada = None
        parcela_48 = None
        parcela_64 = None

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE public.ficha_bancos
                    SET
                        status = :status,
                        valor_financiado = :valor_financiado,
                        valor_entrada = :valor_entrada,
                        parcela_48 = :parcela_48,
                        parcela_64 = :parcela_64,
                        observacao = :observacao,
                        atualizado_por_id = :usuario_id,
                        updated_at = NOW()
                    WHERE id = :banco_id
                      AND ficha_id = :ficha_id
                    """
                ),
                {
                    "status": status,
                    "valor_financiado": valor_financiado,
                    "valor_entrada": valor_entrada,
                    "parcela_48": parcela_48,
                    "parcela_64": parcela_64,
                    "observacao": observacao.strip() or None,
                    "usuario_id": usuario["id"],
                    "banco_id": banco_id,
                    "ficha_id": ficha["id"],
                },
            )

            novo_status_geral = recalcular_status_ficha(
                conn,
                int(ficha["id"]),
            )
            criar_notificacao_vendedor(
                ficha.get("vendedor_id"),
                int(ficha["id"]),
                f"Atualização da ficha de {ficha['nome_lead']}",
                f"{banco}: {status}. Resultado geral: "
                f"{novo_status_geral}.",
                conn,
            )

        st.success(f"Resultado do {banco} salvo.")
        st.rerun()
    except Exception as erro:
        st.error(f"Erro ao salvar análise bancária: {erro}")


def salvar_dados_financeiros_ficha(
    usuario: Dict[str, Any],
    ficha: pd.Series,
    comprou: bool,
    data_compra: Optional[date],
    valor_veiculo: Optional[float],
    banco_contratado: Optional[str],
    valor_liberado: Optional[float],
    entrada_total: Optional[float],
    entrada_paga: Optional[float],
    gerou_boleto: bool,
    boleto_valor: Optional[float],
    boleto_meses: Optional[int],
) -> None:
    pode_alterar = usuario_tem("edit_sales_boleto")

    if not pode_alterar:
        st.error("Você não pode alterar esses dados financeiros.")
        return

    if not comprou:
        data_compra = None
        valor_veiculo = None
        banco_contratado = None
        valor_liberado = 0
        entrada_total = 0
        entrada_paga = 0
        valor_pendente = 0
        gerou_boleto = False
    else:
        entrada_total = max(float(entrada_total or 0), 0)
        entrada_paga = max(float(entrada_paga or 0), 0)
        valor_liberado = max(float(valor_liberado or 0), 0)
        valor_pendente = max(entrada_total - entrada_paga, 0)

    if not gerou_boleto:
        boleto_valor = None
        boleto_meses = None
        boleto_total = 0
    else:
        boleto_total = (
            float(boleto_valor or 0) * int(boleto_meses or 0)
        )

    if gerou_boleto and (
        boleto_valor is None or not boleto_meses or boleto_meses <= 0
    ):
        st.error(
            "Informe o valor e a quantidade de meses do boleto."
        )
        return

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE public.fichas_credito
                    SET
                        comprou = :comprou,
                        data_compra = :data_compra,
                        valor_veiculo = :valor_veiculo,
                        banco_contratado = :banco_contratado,
                        valor_liberado = :valor_liberado,
                        valor_financiado = :valor_liberado,
                        entrada_total = :entrada_total,
                        valor_entrada = :entrada_total,
                        entrada_paga = :entrada_paga,
                        valor_pendente = :valor_pendente,
                        gerou_boleto = :gerou_boleto,
                        boleto_valor = :boleto_valor,
                        boleto_meses = :boleto_meses,
                        boleto_total = :boleto_total,
                        atualizado_por_id = :usuario_id,
                        updated_at = NOW()
                    WHERE id = :ficha_id
                    """
                ),
                {
                    "comprou": comprou,
                    "data_compra": data_compra,
                    "valor_veiculo": valor_veiculo,
                    "banco_contratado": banco_contratado,
                    "valor_liberado": valor_liberado,
                    "entrada_total": entrada_total,
                    "entrada_paga": entrada_paga,
                    "valor_pendente": valor_pendente,
                    "gerou_boleto": gerou_boleto,
                    "boleto_valor": boleto_valor,
                    "boleto_meses": boleto_meses,
                    "boleto_total": boleto_total,
                    "usuario_id": usuario["id"],
                    "ficha_id": ficha["id"],
                },
            )

            conn.execute(
                text(
                    """
                    UPDATE public.leads l
                    SET venda_concluida = :comprou,
                        vendeu = :comprou,
                        updated_at = NOW()
                    FROM public.fichas_credito f
                    WHERE f.id = :ficha_id
                      AND l.id = f.lead_id
                    """
                ),
                {
                    "comprou": comprou,
                    "ficha_id": ficha["id"],
                },
            )

            if comprou:
                criar_notificacao_vendedor(
                    ficha.get("vendedor_id"),
                    int(ficha["id"]),
                    f"Compra atualizada: {ficha['nome_lead']}",
                    "Os dados de compra da sua ficha foram atualizados.",
                    conn,
                )

        st.success("Dados financeiros salvos.")
        st.rerun()
    except Exception as erro:
        st.error(f"Erro ao salvar dados financeiros: {erro}")


def salvar_dados_cadastrais_ficha(
    usuario: Dict[str, Any],
    ficha: pd.Series,
    nome_completo: str,
    cpf: str,
    data_nascimento: str,
    habilitado: bool,
    carro_interesse: str,
    valor_entrada: Optional[float],
) -> None:
    pode_alterar = (
        usuario_tem("edit_bank_results")
        or (
            usuario_tem("edit_own_credit_data")
            and ficha.get("vendedor_id") == usuario.get("vendedor_id")
        )
    )

    if not pode_alterar:
        st.error("Você não pode alterar os dados da ficha.")
        return

    if not nome_completo.strip() or not cpf.strip():
        st.error("Nome completo e CPF são obrigatórios.")
        return

    valor_entrada_atualizacao = (
        None
        if valor_entrada is None
        else max(float(valor_entrada or 0), 0)
    )

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE public.leads
                    SET
                        nome_completo = :nome_completo,
                        cpf = :cpf,
                        data_nascimento = :data_nascimento,
                        habilitado = :habilitado,
                        produto_interesse = :produto_interesse,
                        valor_entrada = COALESCE(
                            :valor_entrada,
                            valor_entrada
                        ),
                        updated_at = NOW()
                    WHERE id = :lead_id
                    """
                ),
                {
                    "nome_completo": nome_completo.strip(),
                    "cpf": cpf.strip(),
                    "data_nascimento": data_nascimento.strip() or None,
                    "habilitado": habilitado,
                    "produto_interesse": (
                        carro_interesse.strip() or None
                    ),
                        "valor_entrada": valor_entrada_atualizacao,
                    "lead_id": ficha["lead_id"],
                },
            )
            conn.execute(
                text(
                    """
                    UPDATE public.fichas_credito
                    SET valor_entrada = COALESCE(
                            :valor_entrada,
                            valor_entrada
                        ),
                        atualizado_por_id = :usuario_id,
                        updated_at = NOW()
                    WHERE id = :ficha_id
                    """
                ),
                {
                    "valor_entrada": valor_entrada_atualizacao,
                    "usuario_id": usuario["id"],
                    "ficha_id": ficha["id"],
                },
            )

        st.success("Dados cadastrais da ficha atualizados.")
        st.rerun()
    except Exception as erro:
        st.error(f"Erro ao atualizar dados da ficha: {erro}")


def obter_metricas_credito() -> tuple[pd.DataFrame, Dict[str, Any]]:
    query_bancos = text(
        """
        SELECT
            banco,
            COUNT(DISTINCT ficha_id) AS fichas_analisadas,
            COUNT(*) FILTER (WHERE status = 'aprovado')
                AS total_aprovados,
            COUNT(*) FILTER (WHERE status = 'negado')
                AS total_negados,
            COUNT(*) FILTER (WHERE status = 'pendente')
                AS total_pendentes,
            ROUND(
                100.0 * COUNT(*) FILTER (WHERE status = 'aprovado')
                / NULLIF(COUNT(*), 0),
                2
            ) AS taxa_aprovacao
        FROM public.ficha_bancos
        GROUP BY banco
        ORDER BY total_aprovados DESC, taxa_aprovacao DESC
        """
    )

    query_geral = text(
        """
        SELECT
            COUNT(*) AS total_fichas,
            COUNT(*) FILTER (WHERE status_geral = 'aprovada')
                AS fichas_aprovadas,
            COUNT(*) FILTER (WHERE status_geral = 'negada')
                AS fichas_negadas,
            COUNT(*) FILTER (WHERE status_geral = 'pendente')
                AS fichas_pendentes,
            COUNT(*) FILTER (WHERE comprou = TRUE)
                AS total_compras,
            COALESCE(SUM(valor_liberado + entrada_paga)
                FILTER (WHERE comprou = TRUE), 0) AS valor_vendas_bruto,
            COALESCE(SUM(valor_liberado)
                FILTER (WHERE comprou = TRUE), 0) AS valor_liberado,
            COALESCE(SUM(entrada_paga)
                FILTER (WHERE comprou = TRUE), 0) AS entrada_paga,
            COUNT(*) FILTER (
                WHERE comprou = TRUE AND gerou_boleto = TRUE
            )
                AS total_boletos,
            COALESCE(SUM(valor_pendente)
                FILTER (WHERE comprou = TRUE AND valor_pendente > 0), 0)
                AS valor_pendente,
            COALESCE(SUM(boleto_total)
                FILTER (WHERE comprou = TRUE AND gerou_boleto = TRUE), 0)
                AS valor_boletos,
            COUNT(*) FILTER (
                WHERE comprou = TRUE
                  AND gerou_boleto = TRUE
                  AND valor_pendente > 0
            ) AS clientes_com_valor_pendente
        FROM public.fichas_credito
        """
    )

    with engine.connect() as conn:
        por_banco = pd.read_sql_query(query_bancos, conn)
        geral = conn.execute(query_geral).mappings().first()

    return por_banco, dict(geral or {})


# ============================================================
# MODAIS DE EDIÇÃO
# ============================================================

@st.dialog("Editar Lead")
def editar_lead_modal(lead_data: pd.Series, df_vendedores: pd.DataFrame):
    usuario = st.session_state["usuario_logado"]

    if not pode_editar_lead(lead_data, usuario):
        st.error("Você não tem permissão para editar este lead.")
        return

    st.write(f"Editando informações de **{lead_data['nome_lead']}**")

    with st.form(f"form_edicao_{lead_data['id']}"):
        novo_nome = st.text_input(
            "Nome do Lead",
            value=str(lead_data.get("nome_lead") or ""),
        )
        novo_tel = st.text_input(
            "Telefone",
            value=str(lead_data.get("telefone") or ""),
        )

        ids_vendedores = (
            df_vendedores["id"].tolist()
            if not df_vendedores.empty
            else []
        )

        vendedor_atual = lead_data.get("vendedor_id")
        index_vendedor = (
            ids_vendedores.index(vendedor_atual)
            if vendedor_atual in ids_vendedores
            else 0
        )

        if usuario["tipo"] == "gerente" and ids_vendedores:
            novo_vendedor_id = st.selectbox(
                "Vendedor responsável",
                options=ids_vendedores,
                index=index_vendedor,
                format_func=lambda valor: df_vendedores.loc[
                    df_vendedores["id"] == valor, "nome"
                ].iloc[0],
            )
        else:
            novo_vendedor_id = vendedor_atual
            st.info(
                "Apenas o gerente pode alterar o vendedor responsável."
            )

        col1, col2, col3 = st.columns(3)
        with col1:
            gerou_ficha = st.checkbox(
                "Gerou ficha",
                value=bool(lead_data.get("gerou_ficha", False)),
            )
        with col2:
            respondeu = st.checkbox(
                "Respondeu",
                value=bool(lead_data.get("respondeu", False)),
            )
        with col3:
            venda_concluida = st.checkbox(
                "Venda concluída",
                value=bool(
                    lead_data.get(
                        "venda_concluida",
                        lead_data.get("vendeu", False),
                    )
                ),
            )

        novo_cpf = st.text_input(
            "CPF",
            value=str(lead_data.get("cpf") or ""),
        )
        nova_data_nascimento = st.text_input(
            "Data de nascimento",
            value=str(lead_data.get("data_nascimento") or ""),
        )
        nova_observacao = st.text_area(
            "Observações",
            value=str(lead_data.get("observacao") or ""),
        )

        salvar = st.form_submit_button(
            "Salvar alterações",
            use_container_width=True,
            type="primary",
        )

    if not salvar:
        return

    def vazio_para_none(valor: Any) -> Optional[str]:
        valor = str(valor or "").strip()
        return valor or None

    try:
        query = text(
            """
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
                observacao = :observacao,
                updated_at = NOW()
            WHERE id = :lead_id
            """
        )

        with engine.begin() as conn:
            conn.execute(
                query,
                {
                    "nome_lead": vazio_para_none(novo_nome),
                    "telefone": vazio_para_none(novo_tel),
                    "vendedor_id": novo_vendedor_id,
                    "gerou_ficha": gerou_ficha,
                    "respondeu": respondeu,
                    "venda_concluida": venda_concluida,
                    "cpf": vazio_para_none(novo_cpf),
                    "data_nascimento": vazio_para_none(
                        nova_data_nascimento
                    ),
                    "observacao": vazio_para_none(nova_observacao),
                    "lead_id": lead_data["id"],
                },
            )

        st.success("Lead atualizado com sucesso.")
        st.rerun()

    except Exception as erro:
        st.error(f"Erro ao salvar alterações: {erro}")


@st.dialog("Excluir Lead")
def deletar_lead_modal(lead_data: pd.Series):
    usuario = st.session_state["usuario_logado"]

    if not pode_deletar_lead(lead_data, usuario):
        st.error("Você não tem permissão para excluir este lead.")
        return

    st.warning(
        f"Tem certeza que deseja apagar o lead "
        f"**{lead_data['nome_lead']}**?"
    )

    col1, col2 = st.columns(2)

    with col1:
        confirmar = st.button(
            "Sim, excluir",
            type="primary",
            use_container_width=True,
        )

    with col2:
        cancelar = st.button(
            "Cancelar",
            use_container_width=True,
        )

    if cancelar:
        st.rerun()

    if confirmar:
        try:
            with engine.begin() as conn:
                conn.execute(
                    text("DELETE FROM public.leads WHERE id = :id"),
                    {"id": lead_data["id"]},
                )
            st.success("Lead excluído.")
            st.rerun()
        except Exception as erro:
            st.error(f"Erro ao excluir lead: {erro}")


# ============================================================
# COMPONENTES DE INTERFACE
# ============================================================

def mostrar_login() -> None:
    st.markdown("<br><br>", unsafe_allow_html=True)
    _, coluna_login, _ = st.columns([1, 1.5, 1])

    with coluna_login:
        with st.container(border=True):
            st.title("Acesso ao sistema")
            st.subheader("Entrar no sistema")

            with st.form("form_login"):
                login = st.text_input("Usuário")
                senha = st.text_input("Senha", type="password")
                entrar = st.form_submit_button(
                    "Entrar",
                    use_container_width=True,
                    type="primary",
                )

            if entrar:
                if autenticar(login, senha):
                    st.success("Login realizado com sucesso.")
                    st.rerun()
                else:
                    st.error("Usuário ou senha incorretos.")


def mostrar_sidebar(usuario: Dict[str, Any]) -> None:
    with st.sidebar:
        st.markdown(
            f"### 👤 Logado como\n**{usuario['nome']}**"
        )
        st.caption(f"Perfil: {usuario['tipo'].upper()}")

        if st.button("Sair", use_container_width=True):
            limpar_sessao()

        st.markdown("---")
        st.header("Navegação")

        pagina = st.session_state["pagina_atual"]

        if usuario_tem("view_leads"):
            if st.button(
                "Painel de Leads",
                use_container_width=True,
                type="primary" if pagina == "leads" else "secondary",
            ):
                st.session_state["pagina_atual"] = "leads"
                st.session_state["abrir_formulario"] = False
                st.rerun()

        if usuario_tem("view_team"):
            if st.button(
                "Equipe de Vendedores",
                use_container_width=True,
                type="primary" if pagina == "vendedores" else "secondary",
            ):
                st.session_state["pagina_atual"] = "vendedores"
                st.rerun()

        if usuario_tem("use_chat"):
            total_nao_lidas = contar_mensagens_nao_lidas(
                usuario.get("vendedor_id")
            )
            label_chat = "Central de Chat"
            if total_nao_lidas:
                label_chat += f" 🔴 ({total_nao_lidas})"

            if st.button(
                label_chat,
                use_container_width=True,
                type="primary" if pagina == "chat" else "secondary",
            ):
                st.session_state["pagina_atual"] = "chat"
                st.rerun()

        if usuario_tem("view_goals"):
            if st.button(
                "Metas",
                use_container_width=True,
                type="primary" if pagina == "metas" else "secondary",
            ):
                st.session_state["pagina_atual"] = "metas"
                st.session_state["abrir_formulario"] = False
                st.rerun()

        if usuario_tem("view_credit_fichas"):
            notificacoes_fichas = contar_notificacoes_nao_lidas(
                usuario["id"]
            )
            label_fichas = "Fichas de Crédito"
            if notificacoes_fichas:
                label_fichas += f" 🔴 ({notificacoes_fichas})"

            if st.button(
                label_fichas,
                use_container_width=True,
                type="primary" if pagina == "fichas" else "secondary",
            ):
                st.session_state["pagina_atual"] = "fichas"
                st.session_state["abrir_formulario"] = False
                st.rerun()

        if usuario_tem("view_tasks"):
            tarefas_nao_lidas = contar_tarefas_nao_visualizadas(
                usuario["id"]
            )
            label_tarefas = "Tarefas"
            if tarefas_nao_lidas:
                label_tarefas += f" 🔴 ({tarefas_nao_lidas})"

            if st.button(
                label_tarefas,
                use_container_width=True,
                type="primary" if pagina == "tarefas" else "secondary",
            ):
                st.session_state["pagina_atual"] = "tarefas"
                st.session_state["abrir_formulario"] = False
                st.rerun()

        if usuario_tem("use_elfen_ai"):
            if st.button(
                "Elfen AI",
                use_container_width=True,
                type="primary" if pagina == "elfen_ai" else "secondary",
            ):
                st.session_state["pagina_atual"] = "elfen_ai"
                st.rerun()

        if pagina == "leads" and usuario_tem("create_lead"):
            st.markdown("---")
            if st.button(
                "➕ Adicionar novo lead",
                use_container_width=True,
            ):
                st.session_state["abrir_formulario"] = True
                st.rerun()


def mostrar_formulario_novo_lead(
    usuario: Dict[str, Any],
    df_vendedores: pd.DataFrame,
) -> None:
    if not usuario_tem("create_lead"):
        return

    st.subheader("Novo Lead")

    if df_vendedores.empty:
        st.warning("Nenhum vendedor ativo foi encontrado.")
        return

    with st.form("form_novo_lead", clear_on_submit=False):
        col1, col2 = st.columns(2)

        with col1:
            nome = st.text_input("Nome do lead*")
            telefone = st.text_input("Telefone*")

            if usuario["tipo"] == "gerente":
                vendedor_id = st.selectbox(
                    "Vendedor responsável*",
                    options=df_vendedores["id"].tolist(),
                    format_func=lambda valor: df_vendedores.loc[
                        df_vendedores["id"] == valor, "nome"
                    ].iloc[0],
                )
            else:
                vendedor_id = usuario.get("vendedor_id")
                st.info(f"Vendedor atribuído: **{usuario['nome']}**")

        with col2:
            data_lead = st.date_input("Data que o lead chegou*")
            venda_concluida = st.checkbox("Venda concluída?")

        gerou_ficha = st.checkbox("Gerou ficha")

        cpf = None
        data_nascimento = None
        habilitado = None
        carro_interesse = None
        valor_entrada = None

        if gerou_ficha:
            st.markdown("### 📝 Dados da ficha")
            col_ficha_1, col_ficha_2 = st.columns(2)

            with col_ficha_1:
                cpf = st.text_input("CPF")
                nome_completo = st.text_input(
                    "Nome completo",
                    value=nome,
                )
                data_nascimento = st.text_input("Data de nascimento")
                carro_interesse = st.text_input("Carro de interesse")

            with col_ficha_2:
                habilitado = st.radio(
                    "O cliente é habilitado?",
                    ["Não", "Sim"],
                    horizontal=True,
                ) == "Sim"
                valor_entrada = st.number_input(
                    "Valor de entrada",
                    min_value=0.0,
                    step=100.0,
                )

        observacao = st.text_area("Observações gerais")

        salvar = st.form_submit_button(
            "Salvar lead",
            use_container_width=True,
            type="primary",
        )

    if not salvar:
        return

    if not nome.strip() or not telefone.strip() or not vendedor_id:
        st.warning("Preencha nome, telefone e vendedor.")
        return

    try:
        query = text(
            """
            INSERT INTO public.leads (
                nome_lead,
                telefone,
                vendedor_id,
                data_lead,
                gerou_ficha,
                venda_concluida,
                cpf,
                nome_completo,
                data_nascimento,
                habilitado,
                aprovou_credito,
                produto_interesse,
                valor_entrada,
                observacao,
                created_at,
                updated_at
            )
            VALUES (
                :nome,
                :telefone,
                :vendedor_id,
                :data_lead,
                :gerou_ficha,
                :venda_concluida,
                :cpf,
                :nome_completo,
                :data_nascimento,
                :habilitado,
                :aprovou_credito,
                :produto_interesse,
                :valor_entrada,
                :observacao,
                NOW(),
                NOW()
            )
            RETURNING id
            """
        )

        with engine.begin() as conn:
            lead_id = conn.execute(
                query,
                {
                    "nome": nome.strip(),
                    "telefone": telefone.strip(),
                    "vendedor_id": vendedor_id,
                    "data_lead": data_lead,
                    "gerou_ficha": gerou_ficha,
                    "venda_concluida": venda_concluida,
                    "cpf": cpf.strip() if cpf else None,
                    "nome_completo": (
                        nome_completo.strip()
                        if gerou_ficha and nome_completo.strip()
                        else nome.strip()
                    ),
                    "data_nascimento": (
                        data_nascimento.strip()
                        if gerou_ficha and data_nascimento
                        else None
                    ),
                    "habilitado": habilitado,
                    "aprovou_credito": None,
                    "produto_interesse": (
                        carro_interesse.strip()
                        if gerou_ficha and carro_interesse
                        else None
                    ),
                    "valor_entrada": (
                        valor_entrada
                        if gerou_ficha
                        else None
                    ),
                    "observacao": (
                        observacao.strip()
                        if observacao.strip()
                        else None
                    ),
                },
            ).scalar_one()

            if gerou_ficha:
                criar_ficha_credito(
                    conn=conn,
                    lead_id=int(lead_id),
                    vendedor_id=vendedor_id,
                    valor_entrada=float(valor_entrada or 0),
                    usuario_id=usuario["id"],
                )

        st.success("Lead inserido com sucesso.")
        st.session_state["abrir_formulario"] = False
        st.rerun()

    except Exception as erro:
        st.error(f"Erro ao inserir lead: {erro}")


def mostrar_card_lead(
    row: pd.Series,
    usuario: Dict[str, Any],
    df_vendedores: pd.DataFrame,
) -> None:
    with st.container(border=True):
        st.markdown(f"### 👤 {row['nome_lead']}")

        venda_realizada = bool(
            row.get("venda_concluida", False)
            or row.get("vendeu", False)
        )

        if venda_realizada:
            st.success("VENDA CONCLUÍDA")

        st.write(
            f"**Vendedor:** "
            f"{row.get('nome_vendedor') or 'Não atribuído'}"
        )
        st.write(f"**Telefone:** {row.get('telefone') or '-'}")
        st.write(f"**Data do lead:** {row.get('data_lead') or '-'}")
        st.write(
            f"**Ficha gerada:** "
            f"{'Sim' if row.get('gerou_ficha') else 'Não'}"
        )

        # Dados pessoais/documentais só aparecem para quem tem essa
        # permissão. O financeiro não recebe CPF na interface.
        if usuario_tem("view_documents") and row.get("gerou_ficha"):
            with st.expander("Ver dados da ficha"):
                st.write(f"**CPF:** {row.get('cpf') or 'Não informado'}")
                st.write(
                    f"**Data de nascimento:** "
                    f"{row.get('data_nascimento') or 'Não informada'}"
                )
                st.write(
                    f"**Habilitado:** "
                    f"{'Sim' if row.get('habilitado') else 'Não'}"
                )

        if usuario_tem("view_financial"):
            aprovado = row.get("aprovou_credito")
            if aprovado is True:
                st.success("Crédito: aprovado")
            elif aprovado is False:
                st.error("Crédito: recusado")
            else:
                st.warning("Crédito: em análise")

            st.write(
                f"**Venda concluída:** "
                f"{'Sim' if venda_realizada else 'Não'}"
            )

        if row.get("observacao"):
            st.info(f"**Observações:** {row['observacao']}")

        pode_editar = pode_editar_lead(row, usuario)
        pode_deletar = pode_deletar_lead(row, usuario)

        if pode_editar or pode_deletar:
            st.markdown("---")
            col_editar, col_excluir = st.columns(2)

            with col_editar:
                if pode_editar and st.button(
                    "Editar",
                    key=f"editar_{row['id']}",
                    use_container_width=True,
                ):
                    editar_lead_modal(row, df_vendedores)

            with col_excluir:
                if pode_deletar and st.button(
                    "Excluir",
                    key=f"excluir_{row['id']}",
                    use_container_width=True,
                ):
                    deletar_lead_modal(row)

        atualizado = row.get("updated_at")
        if atualizado:
            st.caption(f"Atualizado em: {atualizado}")


# ============================================================
# PÁGINAS
# ============================================================

def pagina_leads(usuario: Dict[str, Any]) -> None:
    st.title("Painel de Controle")

    metricas = obter_metricas(usuario)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total de leads", metricas["total_leads"])
    c2.metric("Fichas geradas", metricas["total_fichas"])
    c3.metric("Aprovados", metricas["total_aprovados"])
    c4.metric("Vendidos", metricas["total_vendidos"])

    filtros = ["todos", "fichas", "aprovados", "vendidos"]
    filtro_atual = st.session_state["filtro_categoria"]

    filtro = st.radio(
        "Filtro",
        filtros,
        index=filtros.index(filtro_atual)
        if filtro_atual in filtros
        else 0,
        horizontal=True,
        format_func=lambda valor: {
            "todos": "Todos",
            "fichas": "Fichas",
            "aprovados": "Aprovados",
            "vendidos": "Vendidos",
        }[valor],
    )
    st.session_state["filtro_categoria"] = filtro

    if st.session_state.get("abrir_formulario"):
        mostrar_formulario_novo_lead(
            usuario,
            obter_vendedores(),
        )

    st.markdown("---")
    busca = st.text_input(
        "Buscar lead",
        placeholder="Nome, CPF, telefone ou observação",
    )

    try:
        df_vendedores = obter_vendedores()
        df = buscar_leads(usuario, filtro, busca)
    except Exception as erro:
        st.error(f"Erro ao carregar leads: {erro}")
        return

    st.subheader("Leads cadastrados")

    if df.empty:
        st.info("Nenhum lead encontrado para este perfil e filtro.")
        return

    colunas = st.columns(3)
    for indice, (_, row) in enumerate(df.iterrows()):
        with colunas[indice % 3]:
            mostrar_card_lead(row, usuario, df_vendedores)


def pagina_vendedores(usuario: Dict[str, Any]) -> None:
    if not usuario_tem("view_team"):
        st.error("Você não tem permissão para ver a equipe.")
        return

    st.title("Equipe de Vendedores")
    st.caption("Visão geral do desempenho da equipe.")

    query = text(
        """
        SELECT
            v.id,
            v.nome,
            COUNT(l.id) AS total_leads,
            COUNT(l.id) FILTER (
                WHERE l.gerou_ficha = TRUE
            ) AS total_fichas,
            COUNT(l.id) FILTER (
                WHERE l.aprovou_credito = TRUE
            ) AS total_aprovados,
            COUNT(l.id) FILTER (
                WHERE l.venda_concluida = TRUE OR l.vendeu = TRUE
            ) AS total_vendas
        FROM public.vendedores v
        LEFT JOIN public.leads l
            ON l.vendedor_id = v.id
        WHERE COALESCE(v.ativo, TRUE) = TRUE
        GROUP BY v.id, v.nome
        ORDER BY total_vendas DESC, total_aprovados DESC, v.nome
        """
    )

    try:
        with engine.connect() as conn:
            df = pd.read_sql_query(query, conn)
    except Exception as erro:
        st.error(f"Erro ao carregar equipe: {erro}")
        return

    if df.empty:
        st.info("Nenhum vendedor encontrado.")
        return

    for _, row in df.iterrows():
        with st.container(border=True):
            st.subheader(row["nome"])
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Leads", int(row["total_leads"]))
            col2.metric("Fichas", int(row["total_fichas"]))
            col3.metric("Aprovados", int(row["total_aprovados"]))
            col4.metric("Vendas", int(row["total_vendas"]))


def pagina_fichas(usuario: Dict[str, Any]) -> None:
    if not usuario_tem("view_credit_fichas"):
        st.error("Você não tem permissão para acessar fichas de crédito.")
        return

    st.title("Fichas de Crédito")
    if usuario["tipo"] == "elfen_ai":
        st.caption(
            "Dados cadastrais, status da ficha e propostas bancárias."
        )
    elif usuario["tipo"] in {"financeiro", "gerente"}:
        st.caption(
            "Análise por banco, compras, valores recebidos e boletos."
        )
    else:
        st.caption("Dados cadastrais, status da ficha e propostas bancárias.")

    notificacoes = contar_notificacoes_nao_lidas(usuario["id"])
    if notificacoes:
        st.warning(
            f"Você tem {notificacoes} atualização(ões) de ficha não lida(s)."
        )
        marcar_notificacoes_como_lidas(usuario["id"])

    if usuario_tem("view_credit_metrics"):
        try:
            por_banco, geral = obter_metricas_credito()
            st.subheader("Métricas financeiras")
            metricas = st.columns(6)
            metricas[0].metric(
                "Fichas",
                int(geral.get("total_fichas") or 0),
            )
            metricas[1].metric(
                "Aprovadas",
                int(geral.get("fichas_aprovadas") or 0),
            )
            metricas[2].metric(
                "Negadas",
                int(geral.get("fichas_negadas") or 0),
            )
            metricas[3].metric(
                "Pendentes",
                int(geral.get("fichas_pendentes") or 0),
            )
            metricas[4].metric(
                "Compras",
                int(geral.get("total_compras") or 0),
            )
            metricas[5].metric(
                "Clientes com pendência",
                int(geral.get("clientes_com_valor_pendente") or 0),
            )

            if not por_banco.empty:
                st.markdown(
                    "#### Aprovação por banco — clique para abrir as fichas"
                )
                colunas_bancos = st.columns(4)
                for indice, (_, linha_banco) in enumerate(
                    por_banco.iterrows()
                ):
                    banco_nome = linha_banco["banco"]
                    with colunas_bancos[indice % 4]:
                        if st.button(
                            (
                                f"{banco_nome} • "
                                f"{int(linha_banco['fichas_analisadas'])} fichas • "
                                f"{int(linha_banco['total_aprovados'])} aprovadas"
                            ),
                            key=f"filtro_banco_{banco_nome}",
                            use_container_width=True,
                            type=(
                                "primary"
                                if st.session_state.get("banco_filtro")
                                == banco_nome
                                else "secondary"
                            ),
                        ):
                            st.session_state["banco_filtro"] = banco_nome
                            st.rerun()

                if st.session_state.get("banco_filtro"):
                    banco_selecionado = st.session_state["banco_filtro"]
                    if st.button(
                        "Mostrar todos os bancos",
                        key="limpar_filtro_banco",
                    ):
                        st.session_state["banco_filtro"] = None
                        st.rerun()
                    st.info(
                        f"Mostrando fichas do banco: {banco_selecionado}"
                    )

                st.dataframe(
                    por_banco.rename(
                        columns={
                            "fichas_analisadas": "fichas distintas",
                            "total_aprovados": "aprovadas",
                            "total_negados": "negadas",
                            "total_pendentes": "pendentes",
                            "taxa_aprovacao": "taxa (%)",
                        }
                    ),
                    use_container_width=True,
                    hide_index=True,
                )

            (
                c_fin_1,
                c_fin_2,
                c_fin_3,
                c_fin_4,
                c_fin_5,
                c_fin_6,
            ) = st.columns(6)
            c_fin_1.metric(
                "Valor bruto das vendas",
                f"R$ {numero_seguro(geral.get('valor_vendas_bruto')):,.2f}",
            )
            c_fin_2.metric(
                "Valor liberado",
                f"R$ {numero_seguro(geral.get('valor_liberado')):,.2f}",
            )
            c_fin_3.metric(
                "Entrada já paga",
                f"R$ {numero_seguro(geral.get('entrada_paga')):,.2f}",
            )
            c_fin_4.metric(
                "Total em boletos",
                f"R$ {numero_seguro(geral.get('valor_boletos')):,.2f}",
            )
            c_fin_5.metric(
                "Valor pendente",
                f"R$ {numero_seguro(geral.get('valor_pendente')):,.2f}",
            )
            c_fin_6.metric(
                "Clientes com boleto",
                int(geral.get("total_boletos") or 0),
            )

            st.caption(
                "Valor bruto das vendas = valor liberado pelo banco + "
                "entrada já paga pelo cliente. Isso representa venda bruta, "
                "não lucro líquido."
            )

            try:
                pendentes = obter_fichas_com_valor_pendente()
                with st.expander(
                    "💰 Valor pendente — clientes com boleto",
                    expanded=True,
                ):
                    if pendentes.empty:
                        st.info("Nenhum cliente com valor pendente.")
                    else:
                        st.dataframe(
                            pendentes.rename(
                                columns={
                                    "nome_completo": "cliente",
                                    "telefone": "telefone",
                                    "data_nascimento": "nascimento",
                                    "habilitado": "habilitado",
                                    "produto_interesse": "carro",
                                    "vendedor_nome": "vendedor",
                                    "data_compra": "data compra",
                                    "valor_veiculo": "valor veículo",
                                    "banco_contratado": "banco",
                                    "valor_liberado": "liberado",
                                    "entrada_total": "entrada total",
                                    "entrada_paga": "entrada paga",
                                    "valor_pendente": "valor pendente",
                                    "boleto_valor": "parcela boleto",
                                    "boleto_meses": "meses",
                                    "boleto_total": "total boletos",
                                }
                            ),
                            use_container_width=True,
                            hide_index=True,
                        )
            except Exception as erro:
                st.warning(f"Não foi possível carregar pendências: {erro}")
        except Exception as erro:
            st.warning(
                "As métricas ainda não estão disponíveis. "
                f"Detalhe: {erro}"
            )

        st.markdown("---")

    status_opcoes = [
        "todas",
        "pendente",
        "aprovada",
        "negada",
    ]
    status = st.radio(
        "Filtrar fichas",
        status_opcoes,
        horizontal=True,
        format_func=lambda valor: {
            "todas": "Todas",
            "pendente": "Pendentes",
            "aprovada": "Aprovadas",
            "negada": "Negadas",
        }[valor],
    )
    busca = st.text_input(
        "Buscar ficha",
        placeholder="Nome, CPF, telefone ou vendedor",
    )

    try:
        fichas = obter_fichas_credito(
            usuario,
            status,
            busca,
            st.session_state.get("banco_filtro"),
        )
    except Exception as erro:
        st.error(
            "Não foi possível carregar as fichas. "
            "Execute schema_fichas_credito.sql no Supabase. "
            f"Detalhe: {erro}"
        )
        return

    if fichas.empty:
        st.info("Nenhuma ficha encontrada.")
        return

    for _, ficha in fichas.iterrows():
        status_label = {
            "pendente": "⏳ Pendente",
            "aprovada": "✅ Aprovada",
            "negada": "❌ Negada",
        }.get(ficha["status_geral"], ficha["status_geral"])

        nome_cliente = (
            ficha.get("nome_completo")
            or ficha.get("nome_lead")
            or "Cliente sem nome"
        )

        with st.expander(
            f"{status_label}  |  {nome_cliente}",
            expanded=(status == "pendente"),
        ):
            col_cliente_1, col_cliente_2, col_cliente_3 = st.columns(3)
            col_cliente_1.write(f"**Vendedor:** {ficha.get('vendedor_nome') or '-'}")
            col_cliente_2.write(f"**CPF:** {ficha.get('cpf') or '-'}")
            col_cliente_3.write(
                f"**Carro:** {ficha.get('produto_interesse') or '-'}"
            )

            col_cliente_4, col_cliente_5, col_cliente_6 = st.columns(3)
            col_cliente_4.write(
                f"**Data de nascimento:** "
                f"{ficha.get('data_nascimento') or '-'}"
            )
            col_cliente_5.write(
                f"**Habilitado:** "
                f"{'Sim' if ficha.get('habilitado') else 'Não'}"
            )
            if usuario["tipo"] in {"financeiro", "gerente"}:
                col_cliente_6.write(
                    f"**Entrada solicitada:** "
                    f"R$ {numero_seguro(ficha.get('valor_entrada')):,.2f}"
                )

            pode_editar_dados = (
                usuario_tem("edit_bank_results")
                or (
                    usuario_tem("edit_own_credit_data")
                    and ficha.get("vendedor_id")
                    == usuario.get("vendedor_id")
                )
            )

            if pode_editar_dados:
                with st.expander("Editar dados da ficha"):
                    with st.form(f"form_dados_ficha_{ficha['id']}"):
                        d1, d2 = st.columns(2)
                        novo_nome_completo = d1.text_input(
                            "Nome completo",
                            value=str(ficha.get("nome_completo") or ""),
                        )
                        novo_cpf = d2.text_input(
                            "CPF",
                            value=str(ficha.get("cpf") or ""),
                        )
                        d3, d4 = st.columns(2)
                        nova_data_nascimento = d3.text_input(
                            "Data de nascimento",
                            value=str(
                                ficha.get("data_nascimento") or ""
                            ),
                        )
                        novo_carro = d4.text_input(
                            "Carro de interesse",
                            value=str(
                                ficha.get("produto_interesse") or ""
                            ),
                        )
                        novo_habilitado = st.checkbox(
                            "Cliente habilitado",
                            value=bool(ficha.get("habilitado")),
                        )
                        nova_entrada_ficha = None
                        if usuario["tipo"] in {"financeiro", "gerente"}:
                            nova_entrada_ficha = st.number_input(
                                "Valor de entrada",
                                min_value=0.0,
                                value=numero_seguro(
                                    ficha.get("valor_entrada")
                                ),
                                step=100.0,
                            )
                        salvar_cadastro = st.form_submit_button(
                            "Salvar dados da ficha",
                            use_container_width=True,
                        )

                    if salvar_cadastro:
                        salvar_dados_cadastrais_ficha(
                            usuario,
                            ficha,
                            novo_nome_completo,
                            novo_cpf,
                            nova_data_nascimento,
                            novo_habilitado,
                            novo_carro,
                            nova_entrada_ficha,
                        )

            st.markdown("### Resultado nos bancos")
            try:
                bancos_todos = obter_analises_banco(int(ficha["id"]))
            except Exception as erro:
                st.error(f"Erro ao carregar bancos: {erro}")
                bancos_todos = pd.DataFrame()

            bancos = bancos_todos
            banco_filtro_atual = st.session_state.get("banco_filtro")
            if banco_filtro_atual and not bancos.empty:
                bancos = bancos[
                    bancos["banco"] == banco_filtro_atual
                ]

            if bancos.empty:
                st.warning(
                    "Esta ficha não possui análise para o banco selecionado."
                    if banco_filtro_atual
                    else "Esta ficha ainda não possui bancos cadastrados."
                )
            else:
                for _, banco in bancos.iterrows():
                    status_banco = banco.get("status") or "pendente"
                    label_banco = {
                        "pendente": "⏳",
                        "aprovado": "✅",
                        "negado": "❌",
                    }.get(status_banco, "•")

                    with st.container(border=True):
                        st.markdown(
                            f"#### {label_banco} {banco['banco']}"
                        )

                        if usuario_tem("edit_bank_results"):
                            status_lista = [
                                "pendente",
                                "aprovado",
                                "negado",
                            ]
                            indice_status = (
                                status_lista.index(status_banco)
                                if status_banco in status_lista
                                else 0
                            )

                            def numero_banco(nome_coluna: str) -> float:
                                valor = banco.get(nome_coluna)
                                return (
                                    float(valor)
                                    if pd.notna(valor)
                                    else 0.0
                                )

                            with st.form(
                                f"form_banco_{ficha['id']}_{banco['id']}"
                            ):
                                novo_status = st.selectbox(
                                    "Status",
                                    status_lista,
                                    index=indice_status,
                                    format_func=lambda valor: {
                                        "pendente": "Pendente",
                                        "aprovado": "Aprovado",
                                        "negado": "Negado",
                                    }[valor],
                                )
                                st.caption(
                                    "Os valores abaixo só são gravados "
                                    "quando o banco estiver aprovado."
                                )
                                b1, b2, b3, b4 = st.columns(4)
                                novo_valor_financiado = b1.number_input(
                                    "Valor financiado",
                                    min_value=0.0,
                                    value=numero_banco(
                                        "valor_financiado"
                                    ),
                                    step=100.0,
                                )
                                nova_entrada = b2.number_input(
                                    "Entrada",
                                    min_value=0.0,
                                    value=numero_banco("valor_entrada"),
                                    step=100.0,
                                )
                                nova_parcela_48 = b3.number_input(
                                    "Parcela em 48x",
                                    min_value=0.0,
                                    value=numero_banco("parcela_48"),
                                    step=10.0,
                                )
                                nova_parcela_64 = b4.number_input(
                                    "Parcela em 64x",
                                    min_value=0.0,
                                    value=numero_banco("parcela_64"),
                                    step=10.0,
                                )
                                nova_observacao = st.text_area(
                                    "Observação do banco",
                                    value=str(
                                        banco.get("observacao") or ""
                                    ),
                                )
                                salvar_banco = st.form_submit_button(
                                    "Salvar resultado",
                                    use_container_width=True,
                                )

                            if salvar_banco:
                                valor_financiado_final = (
                                    novo_valor_financiado
                                    if novo_status == "aprovado"
                                    else None
                                )
                                salvar_analise_banco(
                                    usuario,
                                    ficha,
                                    int(banco["id"]),
                                    banco["banco"],
                                    novo_status,
                                    valor_financiado_final,
                                    nova_entrada,
                                    nova_parcela_48,
                                    nova_parcela_64,
                                    nova_observacao,
                                )
                        else:
                            st.write(f"**Status:** {status_banco}")
                            if status_banco == "aprovado":
                                a1, a2, a3, a4 = st.columns(4)
                                a1.metric(
                                    "Financiado",
                                    f"R$ {float(banco.get('valor_financiado') or 0):,.2f}",
                                )
                                a2.metric(
                                    "Entrada",
                                    f"R$ {float(banco.get('valor_entrada') or 0):,.2f}",
                                )
                                a3.metric(
                                    "48x",
                                    f"R$ {float(banco.get('parcela_48') or 0):,.2f}",
                                )
                                a4.metric(
                                    "64x",
                                    f"R$ {float(banco.get('parcela_64') or 0):,.2f}",
                                )
                            if banco.get("observacao"):
                                st.caption(banco["observacao"])

            pode_ver_financeiro = usuario["tipo"] in {
                "financeiro",
                "gerente",
            }
            pode_financeiro = (
                pode_ver_financeiro
                and usuario_tem("edit_sales_boleto")
            )

            if usuario["tipo"] == "elfen_ai":
                st.caption(
                    "A Elfen AI vê apenas os dados cadastrais, "
                    "o status da ficha e os resultados dos bancos."
                )
            elif pode_ver_financeiro:
                st.markdown("### Compra e boleto")
            if pode_financeiro:
                with st.form(f"form_financeiro_ficha_{ficha['id']}"):
                    comprou = st.checkbox(
                        "Cliente comprou?",
                        value=bool(ficha.get("comprou")),
                    )
                    analises_aprovadas = (
                        bancos_todos[
                            bancos_todos["status"] == "aprovado"
                        ]["banco"].tolist()
                        if not bancos_todos.empty
                        else []
                    )
                    bancos_financeiro = [None] + analises_aprovadas
                    banco_atual = ficha.get("banco_contratado")
                    if pd.isna(banco_atual):
                        banco_atual = None
                    if banco_atual not in bancos_financeiro:
                        banco_atual = None
                    banco_contratado = st.selectbox(
                        "Banco contratado",
                        options=bancos_financeiro,
                        index=bancos_financeiro.index(banco_atual),
                        format_func=lambda valor: (
                            "Selecione o banco"
                            if valor is None
                            else valor
                        ),
                        disabled=not comprou,
                    )
                    f1, f2, f3 = st.columns(3)
                    data_compra = f1.date_input(
                        "Data da compra",
                        value=converter_data(ficha.get("data_compra")),
                        disabled=not comprou,
                    )
                    valor_veiculo = f2.number_input(
                        "Valor do veículo",
                        min_value=0.0,
                        value=numero_seguro(ficha.get("valor_veiculo")),
                        step=100.0,
                        disabled=not comprou,
                    )
                    valor_liberado = f3.number_input(
                        "Valor liberado pelo banco",
                        min_value=0.0,
                        value=numero_seguro(
                            ficha.get(
                                "valor_liberado",
                                ficha.get("valor_financiado"),
                            )
                        ),
                        step=100.0,
                        disabled=not comprou,
                    )
                    e1, e2 = st.columns(2)
                    entrada_total = e1.number_input(
                        "Entrada total exigida",
                        min_value=0.0,
                        value=numero_seguro(
                            ficha.get(
                                "entrada_total",
                                ficha.get("valor_entrada"),
                            )
                        ),
                        step=100.0,
                        disabled=not comprou,
                    )
                    entrada_paga = e2.number_input(
                        "Entrada já paga pelo cliente",
                        min_value=0.0,
                        value=numero_seguro(
                            ficha.get("entrada_paga")
                        ),
                        step=100.0,
                        disabled=not comprou,
                    )
                    st.caption(
                        "Valor pendente calculado: "
                        f"R$ {max(entrada_total - entrada_paga, 0):,.2f}"
                    )
                    gerou_boleto = st.checkbox(
                        "Gerou boleto?",
                        value=bool(ficha.get("gerou_boleto")),
                        disabled=not comprou,
                    )
                    b1, b2 = st.columns(2)
                    boleto_valor = b1.number_input(
                        "Valor do boleto",
                        min_value=0.0,
                        value=numero_seguro(ficha.get("boleto_valor")),
                        step=10.0,
                        disabled=not gerou_boleto or not comprou,
                    )
                    boleto_meses = b2.number_input(
                        "Quantidade de meses",
                        min_value=1,
                        value=inteiro_seguro(
                            ficha.get("boleto_meses")
                        ),
                        step=1,
                        disabled=not gerou_boleto or not comprou,
                    )
                    if gerou_boleto and comprou:
                        st.caption(
                            "Total previsto em boletos: "
                            f"R$ {boleto_valor * boleto_meses:,.2f}"
                        )
                    salvar_financeiro = st.form_submit_button(
                        "Salvar compra e boleto",
                        use_container_width=True,
                    )

                if salvar_financeiro:
                    salvar_dados_financeiros_ficha(
                        usuario,
                        ficha,
                        comprou,
                        data_compra if comprou else None,
                        valor_veiculo if comprou else None,
                        banco_contratado if comprou else None,
                        valor_liberado if comprou else None,
                        entrada_total if comprou else None,
                        entrada_paga if comprou else None,
                        gerou_boleto,
                        boleto_valor if gerou_boleto else None,
                        boleto_meses if gerou_boleto else None,
                    )
            elif pode_ver_financeiro:
                st.write(
                    f"**Comprou:** {'Sim' if ficha.get('comprou') else 'Não'}"
                )
                st.write(
                    f"**Valor liberado:** "
                    f"R$ {numero_seguro(ficha.get('valor_liberado')):,.2f}"
                )
                st.write(
                    f"**Entrada paga:** "
                    f"R$ {numero_seguro(ficha.get('entrada_paga')):,.2f}"
                )
                st.write(
                    f"**Valor pendente:** "
                    f"R$ {numero_seguro(ficha.get('valor_pendente')):,.2f}"
                )
                st.write(
                    f"**Boleto:** "
                    f"{'Sim' if ficha.get('gerou_boleto') else 'Não'}"
                )
                if ficha.get("gerou_boleto"):
                    st.write(
                        f"R$ {numero_seguro(ficha.get('boleto_valor')):,.2f} "
                        f"por {inteiro_seguro(ficha.get('boleto_meses'), 0)} meses"
                    )


def pagina_elfen_ai() -> None:
    if not usuario_tem("use_elfen_ai"):
        st.error("Você não tem permissão para acessar a Elfen AI.")
        return

    pagina_fichas(st.session_state["usuario_logado"])


def pagina_chat(usuario: Dict[str, Any]) -> None:
    if not usuario_tem("use_chat"):
        st.error("Você não tem permissão para acessar o chat.")
        return

    meu_vendedor_id = usuario.get("vendedor_id")

    if not meu_vendedor_id:
        st.warning(
            "Este usuário não está associado a um vendedor. "
            "Preencha o campo vendedor_id na tabela usuarios para usar "
            "o chat."
        )
        return

    st.title("Central de Mensagens")

    df_vendedores = obter_vendedores()
    df_outros = df_vendedores[
        df_vendedores["id"] != meu_vendedor_id
    ].copy()

    if df_outros.empty:
        st.info("Não existem outros vendedores para conversar.")
        return

    ids_outros = df_outros["id"].tolist()
    selecionado = st.session_state.get("chat_vendedor_selecionado")

    if selecionado not in ids_outros:
        selecionado = ids_outros[0]
        st.session_state["chat_vendedor_selecionado"] = selecionado

    col_lista, col_conversa = st.columns([1.2, 3])

    with col_lista:
        st.subheader("Contatos")

        for _, vendedor in df_outros.iterrows():
            vid = vendedor["id"]
            nome = vendedor["nome"]
            nao_lidas = contar_mensagens_nao_lidas(meu_vendedor_id, vid)
            label = f"💬 {nome}"
            if nao_lidas:
                label += f" 🔴 ({nao_lidas})"

            if st.button(
                label,
                key=f"contato_{vid}",
                use_container_width=True,
                type=(
                    "primary"
                    if vid == selecionado
                    else "secondary"
                ),
            ):
                st.session_state["chat_vendedor_selecionado"] = vid
                st.rerun()

    with col_conversa:
        outro_id = st.session_state["chat_vendedor_selecionado"]
        outro = df_outros[df_outros["id"] == outro_id].iloc[0]

        marcar_mensagens_como_lidas(meu_vendedor_id, outro_id)
        st.subheader(f"Conversa com {outro['nome']}")

        query = text(
            """
            SELECT
                c.id,
                c.remetente_id,
                c.destinatario_id,
                c.mensagem,
                c.created_at,
                v.nome AS nome_remetente
            FROM public.chat_mensagens c
            JOIN public.vendedores v
                ON v.id = c.remetente_id
            WHERE
                (
                    c.remetente_id = :meu_id
                    AND c.destinatario_id = :outro_id
                )
                OR (
                    c.remetente_id = :outro_id
                    AND c.destinatario_id = :meu_id
                )
            ORDER BY c.created_at ASC
            """
        )

        with engine.connect() as conn:
            df_chat = pd.read_sql_query(
                query,
                conn,
                params={
                    "meu_id": meu_vendedor_id,
                    "outro_id": outro_id,
                },
            )

        area_chat = st.container(height=450)
        with area_chat:
            if df_chat.empty:
                st.caption("Nenhuma mensagem ainda.")
            else:
                for _, mensagem in df_chat.iterrows():
                    sou_eu = mensagem["remetente_id"] == meu_vendedor_id
                    horario = pd.to_datetime(
                        mensagem["created_at"]
                    ).strftime("%H:%M - %d/%m")

                    with st.chat_message(
                        "user" if sou_eu else "assistant"
                    ):
                        st.caption(
                            f"**{mensagem['nome_remetente']}** • {horario}"
                        )
                        st.write(mensagem["mensagem"])

        novo_texto = st.chat_input("Digite sua mensagem...")
        if novo_texto and novo_texto.strip():
            with engine.begin() as conn:
                conn.execute(
                    text(
                        """
                        INSERT INTO public.chat_mensagens (
                            remetente_id,
                            destinatario_id,
                            mensagem,
                            created_at,
                            lida
                        )
                        VALUES (
                            :meu_id,
                            :outro_id,
                            :mensagem,
                            NOW(),
                            FALSE
                        )
                        """
                    ),
                    {
                        "meu_id": meu_vendedor_id,
                        "outro_id": outro_id,
                        "mensagem": novo_texto.strip(),
                    },
                )
            st.rerun()


def pagina_tarefas(usuario: Dict[str, Any]) -> None:
    """
    Tarefas:
    - o gerente cria, altera, exclui e realoca;
    - cada usuário vê apenas as tarefas destinadas a si;
    - o gerente vê todas;
    - o destinatário responde Sim/Não e escreve uma observação;
    - visualizada_at alimenta a notificação de não visualizada.
    """
    if not usuario_tem("view_tasks"):
        st.error("Você não tem permissão para acessar tarefas.")
        return

    st.title("Tarefas")
    st.caption(
        "O gerente acompanha todas as tarefas. Cada colaborador "
        "visualiza apenas as tarefas destinadas a ele."
    )

    tarefas_nao_lidas = contar_tarefas_nao_visualizadas(usuario["id"])
    if tarefas_nao_lidas:
        st.warning(
            f"Você tem {tarefas_nao_lidas} tarefa(s) ainda não visualizada(s)."
        )
        # Abrir a aba representa a visualização das tarefas.
        marcar_tarefas_como_visualizadas(usuario["id"])

    if usuario["tipo"] == "gerente":
        usuarios = obter_usuarios_ativos()
        ids_usuarios = usuarios["id"].tolist()

        with st.expander("➕ Criar nova tarefa", expanded=True):
            with st.form("form_criar_tarefa"):
                titulo = st.text_input("Título da tarefa*")
                descricao = st.text_area("Descrição / instruções")

                destinatario_id = st.selectbox(
                    "Atribuir para*",
                    options=ids_usuarios,
                    format_func=lambda valor: usuarios.loc[
                        usuarios["id"] == valor, "nome"
                    ].iloc[0],
                )

                criar = st.form_submit_button(
                    "Criar tarefa",
                    use_container_width=True,
                    type="primary",
                )

            if criar:
                if not titulo.strip():
                    st.warning("Informe um título para a tarefa.")
                else:
                    try:
                        with engine.begin() as conn:
                            conn.execute(
                                text(
                                    """
                                    INSERT INTO public.tarefas (
                                        titulo,
                                        descricao,
                                        destinatario_id,
                                        criado_por_id
                                    )
                                    VALUES (
                                        :titulo,
                                        :descricao,
                                        :destinatario_id,
                                        :criado_por_id
                                    )
                                    """
                                ),
                                {
                                    "titulo": titulo.strip(),
                                    "descricao": (
                                        descricao.strip()
                                        if descricao.strip()
                                        else None
                                    ),
                                    "destinatario_id": destinatario_id,
                                    "criado_por_id": usuario["id"],
                                },
                            )
                        st.success("Tarefa criada e atribuída.")
                        st.rerun()
                    except Exception as erro:
                        st.error(f"Erro ao criar tarefa: {erro}")

    try:
        tarefas = obter_tarefas(usuario)
    except Exception as erro:
        st.error(
            "Não foi possível carregar tarefas. "
            "Execute primeiro o arquivo schema_metas_tarefas.sql "
            f"no Supabase. Detalhe: {erro}"
        )
        return

    if tarefas.empty:
        st.info("Nenhuma tarefa encontrada.")
        return

    st.subheader(f"{len(tarefas)} tarefa(s)")

    usuarios = (
        obter_usuarios_ativos()
        if usuario["tipo"] == "gerente"
        else pd.DataFrame()
    )

    for _, tarefa in tarefas.iterrows():
        resposta = tarefa.get("resposta")
        if pd.isna(resposta):
            status = "⏳ Aguardando resposta"
        elif bool(resposta):
            status = "✅ Concluída / Sim"
        else:
            status = "❌ Não realizada"

        with st.expander(
            f"{status}  |  {tarefa['titulo']}",
            expanded=(pd.isna(resposta)),
        ):
            st.write(tarefa.get("descricao") or "Sem descrição.")
            st.caption(
                f"Destinatário: {tarefa['destinatario_nome']}  •  "
                f"Criada por: {tarefa['criador_nome']}  •  "
                f"Em: {tarefa['created_at']}"
            )

            if tarefa.get("observacao"):
                st.info(f"**Observação da resposta:** {tarefa['observacao']}")

            # O destinatário pode responder. O gerente também pode
            # responder quando a tarefa foi atribuída a ele próprio.
            eh_destinatario = tarefa["destinatario_id"] == usuario["id"]
            if eh_destinatario and usuario_tem("respond_tasks"):
                opcoes_resposta = [
                    "Ainda não respondi",
                    "Sim",
                    "Não",
                ]

                if pd.isna(resposta):
                    indice_resposta = 0
                else:
                    indice_resposta = 1 if bool(resposta) else 2

                with st.form(f"form_resposta_tarefa_{tarefa['id']}"):
                    resposta_escolhida = st.radio(
                        "Você realizou esta tarefa?",
                        opcoes_resposta,
                        index=indice_resposta,
                        horizontal=True,
                    )
                    observacao = st.text_area(
                        "Observação",
                        value=str(tarefa.get("observacao") or ""),
                    )
                    salvar_resposta = st.form_submit_button(
                        "Salvar minha resposta",
                        use_container_width=True,
                    )

                if salvar_resposta:
                    nova_resposta = None
                    if resposta_escolhida == "Sim":
                        nova_resposta = True
                    elif resposta_escolhida == "Não":
                        nova_resposta = False

                    try:
                        with engine.begin() as conn:
                            conn.execute(
                                text(
                                    """
                                    UPDATE public.tarefas
                                    SET
                                        resposta = :resposta,
                                        observacao = :observacao,
                                        respondida_at = CASE
                                            WHEN :resposta IS NULL
                                            THEN NULL
                                            ELSE NOW()
                                        END,
                                        updated_at = NOW()
                                    WHERE id = :id
                                      AND destinatario_id = :usuario_id
                                    """
                                ),
                                {
                                    "resposta": nova_resposta,
                                    "observacao": (
                                        observacao.strip()
                                        if observacao.strip()
                                        else None
                                    ),
                                    "id": tarefa["id"],
                                    "usuario_id": usuario["id"],
                                },
                            )
                        st.success("Resposta salva.")
                        st.rerun()
                    except Exception as erro:
                        st.error(f"Erro ao responder tarefa: {erro}")

            # Somente gerente altera a tarefa, inclusive o destinatário.
            if usuario["tipo"] == "gerente":
                st.markdown("---")
                st.markdown("**Administração da tarefa**")

                ids_usuarios = usuarios["id"].tolist()
                indice_destinatario = (
                    ids_usuarios.index(tarefa["destinatario_id"])
                    if tarefa["destinatario_id"] in ids_usuarios
                    else 0
                )

                with st.form(f"form_editar_tarefa_{tarefa['id']}"):
                    novo_titulo = st.text_input(
                        "Título",
                        value=str(tarefa["titulo"]),
                    )
                    nova_descricao = st.text_area(
                        "Descrição",
                        value=str(tarefa.get("descricao") or ""),
                    )
                    novo_destinatario = st.selectbox(
                        "Realocar para",
                        options=ids_usuarios,
                        index=indice_destinatario,
                        format_func=lambda valor: usuarios.loc[
                            usuarios["id"] == valor, "nome"
                        ].iloc[0],
                    )
                    salvar_alteracao = st.form_submit_button(
                        "Salvar alteração / realocação",
                        use_container_width=True,
                    )

                if salvar_alteracao:
                    if not novo_titulo.strip():
                        st.warning("O título não pode ficar vazio.")
                    else:
                        try:
                            with engine.begin() as conn:
                                conn.execute(
                                    text(
                                        """
                                        UPDATE public.tarefas
                                        SET
                                            titulo = :titulo,
                                            descricao = :descricao,
                                            destinatario_id = :destinatario_id,
                                            updated_at = NOW()
                                        WHERE id = :id
                                        """
                                    ),
                                    {
                                        "titulo": novo_titulo.strip(),
                                        "descricao": (
                                            nova_descricao.strip()
                                            if nova_descricao.strip()
                                            else None
                                        ),
                                        "destinatario_id": novo_destinatario,
                                        "id": tarefa["id"],
                                    },
                                )
                            st.success("Tarefa atualizada.")
                            st.rerun()
                        except Exception as erro:
                            st.error(
                                f"Erro ao atualizar tarefa: {erro}"
                            )

                if st.button(
                    "🗑️ Remover tarefa",
                    key=f"remover_tarefa_{tarefa['id']}",
                    type="secondary",
                ):
                    try:
                        with engine.begin() as conn:
                            conn.execute(
                                text(
                                    """
                                    DELETE FROM public.tarefas
                                    WHERE id = :id
                                    """
                                ),
                                {"id": tarefa["id"]},
                            )
                        st.success("Tarefa removida.")
                        st.rerun()
                    except Exception as erro:
                        st.error(f"Erro ao remover tarefa: {erro}")


def pagina_metas(usuario: Dict[str, Any]) -> None:
    """
    Metas são visíveis para cada destinatário e para o gerente.
    Somente o gerente cria, altera e remove.
    """
    if not usuario_tem("view_goals"):
        st.error("Você não tem permissão para acessar metas.")
        return

    st.title("Metas")
    st.caption(
        "As metas podem ser gerais ou destinadas a um usuário específico. "
        "Somente o gerente pode administrar esta área."
    )

    usuarios = obter_usuarios_ativos()

    if usuario["tipo"] == "gerente":
        ids_usuarios = [None] + usuarios["id"].tolist()
        nomes_usuarios = {None: "Meta geral — todos"}
        nomes_usuarios.update(
            dict(zip(usuarios["id"], usuarios["nome"]))
        )

        with st.expander("➕ Criar nova meta", expanded=True):
            with st.form("form_criar_meta"):
                titulo = st.text_input("Nome da meta*")
                descricao = st.text_area("Descrição")
                unidade = st.text_input(
                    "Unidade",
                    value="vendas",
                    help="Ex.: vendas, leads, fichas ou reais.",
                )
                valor_objetivo = st.number_input(
                    "Valor objetivo",
                    min_value=0.0,
                    step=1.0,
                )
                periodo_inicio = st.date_input(
                    "Início do período",
                    value=date.today(),
                )
                periodo_fim = st.date_input(
                    "Fim do período",
                    value=date.today(),
                )
                destinatario_id = st.selectbox(
                    "Destinatário",
                    options=ids_usuarios,
                    format_func=lambda valor: nomes_usuarios[valor],
                )
                criar = st.form_submit_button(
                    "Criar meta",
                    use_container_width=True,
                    type="primary",
                )

            if criar:
                if not titulo.strip():
                    st.warning("Informe o nome da meta.")
                elif periodo_fim < periodo_inicio:
                    st.warning(
                        "O fim do período não pode ser anterior ao início."
                    )
                else:
                    try:
                        with engine.begin() as conn:
                            conn.execute(
                                text(
                                    """
                                    INSERT INTO public.metas (
                                        titulo,
                                        descricao,
                                        unidade,
                                        valor_objetivo,
                                        periodo_inicio,
                                        periodo_fim,
                                        destinatario_id,
                                        criado_por_id
                                    )
                                    VALUES (
                                        :titulo,
                                        :descricao,
                                        :unidade,
                                        :valor_objetivo,
                                        :periodo_inicio,
                                        :periodo_fim,
                                        :destinatario_id,
                                        :criado_por_id
                                    )
                                    """
                                ),
                                {
                                    "titulo": titulo.strip(),
                                    "descricao": (
                                        descricao.strip()
                                        if descricao.strip()
                                        else None
                                    ),
                                    "unidade": unidade.strip() or "unidade",
                                    "valor_objetivo": valor_objetivo,
                                    "periodo_inicio": periodo_inicio,
                                    "periodo_fim": periodo_fim,
                                    "destinatario_id": destinatario_id,
                                    "criado_por_id": usuario["id"],
                                },
                            )
                        st.success("Meta criada.")
                        st.rerun()
                    except Exception as erro:
                        st.error(f"Erro ao criar meta: {erro}")

    try:
        metas = obter_metas(usuario)
    except Exception as erro:
        st.error(
            "Não foi possível carregar metas. "
            "Execute primeiro o arquivo schema_metas_tarefas.sql "
            f"no Supabase. Detalhe: {erro}"
        )
        return

    if metas.empty:
        st.info("Nenhuma meta encontrada.")
        return

    for _, meta in metas.iterrows():
        destino = meta.get("destinatario_nome") or "Todos"
        periodo = (
            f"{meta.get('periodo_inicio')} até {meta.get('periodo_fim')}"
        )

        with st.expander(
            f"🎯 {meta['titulo']}  |  {destino}",
            expanded=True,
        ):
            st.write(meta.get("descricao") or "Sem descrição.")
            c1, c2, c3 = st.columns(3)
            c1.metric(
                f"Objetivo ({meta.get('unidade') or 'unidade'})",
                meta.get("valor_objetivo") or 0,
            )
            c2.write("**Período**")
            c2.write(periodo)
            c3.write("**Criada por**")
            c3.write(meta.get("criador_nome") or "-")

            if usuario["tipo"] == "gerente":
                st.markdown("---")
                ids_usuarios = [None] + usuarios["id"].tolist()
                nomes_usuarios = {None: "Meta geral — todos"}
                nomes_usuarios.update(
                    dict(zip(usuarios["id"], usuarios["nome"]))
                )
                destinatario_atual = meta.get("destinatario_id")
                indice_destinatario = (
                    ids_usuarios.index(destinatario_atual)
                    if destinatario_atual in ids_usuarios
                    else 0
                )

                with st.form(f"form_editar_meta_{meta['id']}"):
                    novo_titulo = st.text_input(
                        "Nome",
                        value=str(meta["titulo"]),
                    )
                    nova_descricao = st.text_area(
                        "Descrição",
                        value=str(meta.get("descricao") or ""),
                    )
                    nova_unidade = st.text_input(
                        "Unidade",
                        value=str(meta.get("unidade") or "unidade"),
                    )
                    novo_valor = st.number_input(
                        "Valor objetivo",
                        min_value=0.0,
                        value=float(meta.get("valor_objetivo") or 0),
                        step=1.0,
                    )
                    novo_inicio = st.date_input(
                        "Início",
                        value=converter_data(meta.get("periodo_inicio")),
                    )
                    novo_fim = st.date_input(
                        "Fim",
                        value=converter_data(meta.get("periodo_fim")),
                    )
                    novo_destinatario = st.selectbox(
                        "Destinatário",
                        options=ids_usuarios,
                        index=indice_destinatario,
                        format_func=lambda valor: nomes_usuarios[valor],
                    )
                    salvar_meta = st.form_submit_button(
                        "Salvar alteração",
                        use_container_width=True,
                    )

                if salvar_meta:
                    if not novo_titulo.strip():
                        st.warning("O nome da meta não pode ficar vazio.")
                    elif novo_fim < novo_inicio:
                        st.warning(
                            "O fim do período não pode ser anterior ao início."
                        )
                    else:
                        try:
                            with engine.begin() as conn:
                                conn.execute(
                                    text(
                                        """
                                        UPDATE public.metas
                                        SET
                                            titulo = :titulo,
                                            descricao = :descricao,
                                            unidade = :unidade,
                                            valor_objetivo = :valor_objetivo,
                                            periodo_inicio = :periodo_inicio,
                                            periodo_fim = :periodo_fim,
                                            destinatario_id = :destinatario_id,
                                            updated_at = NOW()
                                        WHERE id = :id
                                        """
                                    ),
                                    {
                                        "titulo": novo_titulo.strip(),
                                        "descricao": (
                                            nova_descricao.strip()
                                            if nova_descricao.strip()
                                            else None
                                        ),
                                        "unidade": (
                                            nova_unidade.strip()
                                            or "unidade"
                                        ),
                                        "valor_objetivo": novo_valor,
                                        "periodo_inicio": novo_inicio,
                                        "periodo_fim": novo_fim,
                                        "destinatario_id": novo_destinatario,
                                        "id": meta["id"],
                                    },
                                )
                            st.success("Meta atualizada.")
                            st.rerun()
                        except Exception as erro:
                            st.error(f"Erro ao atualizar meta: {erro}")

                if st.button(
                    "🗑️ Remover meta",
                    key=f"remover_meta_{meta['id']}",
                ):
                    try:
                        with engine.begin() as conn:
                            conn.execute(
                                text(
                                    """
                                    UPDATE public.metas
                                    SET ativo = FALSE,
                                        updated_at = NOW()
                                    WHERE id = :id
                                    """
                                ),
                                {"id": meta["id"]},
                            )
                        st.success("Meta removida.")
                        st.rerun()
                    except Exception as erro:
                        st.error(f"Erro ao remover meta: {erro}")


# ============================================================
# EXECUÇÃO PRINCIPAL
# ============================================================

if st.session_state["usuario_logado"] is None:
    mostrar_login()
    st.stop()


usuario_atual = st.session_state["usuario_logado"]
mostrar_sidebar(usuario_atual)


paginas_permitidas = {"leads"}

if usuario_tem("view_team"):
    paginas_permitidas.add("vendedores")

if usuario_tem("use_chat"):
    paginas_permitidas.add("chat")

if usuario_tem("use_elfen_ai"):
    paginas_permitidas.add("elfen_ai")

if usuario_tem("view_credit_fichas"):
    paginas_permitidas.add("fichas")

if usuario_tem("view_tasks"):
    paginas_permitidas.add("tarefas")

if usuario_tem("view_goals"):
    paginas_permitidas.add("metas")


if st.session_state["pagina_atual"] not in paginas_permitidas:
    st.session_state["pagina_atual"] = "leads"


pagina_atual = st.session_state["pagina_atual"]

if pagina_atual == "leads":
    pagina_leads(usuario_atual)
elif pagina_atual == "vendedores":
    pagina_vendedores(usuario_atual)
elif pagina_atual == "chat":
    pagina_chat(usuario_atual)
elif pagina_atual == "elfen_ai":
    pagina_elfen_ai()
elif pagina_atual == "fichas":
    pagina_fichas(usuario_atual)
elif pagina_atual == "tarefas":
    pagina_tarefas(usuario_atual)
elif pagina_atual == "metas":
    pagina_metas(usuario_atual)