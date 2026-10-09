"""
Manu Automóveis — Dashboard Executivo (somente ADMIN)
=====================================================
App separado do operacional (app_manu.py), focado em desempenho e finanças.

Requisitos:
  pip install streamlit streamlit-echarts sqlalchemy pandas psycopg2-binary

Secrets (mesmos do app principal):
  [postgres]
  url = "postgresql://..."

Login: apenas usuários com tipo admin (ou aliases de dono).
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text

# ECharts (mesmo componente de https://echarts.streamlit.app/)
try:
    from streamlit_echarts import st_echarts
except ImportError:
    st_echarts = None  # type: ignore

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Manu · Dashboard Admin",
    page_icon="📈",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Cores do tema (altere à vontade)
COR_FUNDO = "#0b0f14"
COR_CARD = "#161d27"
COR_TEXTO = "#e8eef7"
COR_BOM = "#22c55e"
COR_MEDIO = "#eab308"
COR_RUIM = "#ef4444"
COR_AZUL = "#3b82f6"
COR_ROXO = "#a855f7"
COR_CIANO = "#06b6d4"

LOJAS = ("TODAS", "381", "746", "NINA")

# Limiares de desempenho (conversão lead→venda) — abaixo = vermelho
LIMIAR_CONVERSAO_RUIM = 0.05   # < 5% lead→comprou
LIMIAR_CONVERSAO_MEDIO = 0.12  # < 12% = amarelo
LIMIAR_TAREFAS_RUIM = 0.50     # < 50% tarefas concluídas


def engine_db():
    url = st.secrets["postgres"]["url"]
    return create_engine(url, pool_pre_ping=True)


@st.cache_resource
def get_engine():
    return engine_db()


def sql_df(query: str, params: Optional[dict] = None) -> pd.DataFrame:
    with get_engine().connect() as conn:
        return pd.read_sql_query(text(query), conn, params=params or {})


def sql_scalar(query: str, params: Optional[dict] = None) -> Any:
    with get_engine().connect() as conn:
        return conn.execute(text(query), params or {}).scalar()


# ---------------------------------------------------------------------------
# Auth admin-only
# ---------------------------------------------------------------------------
ROLE_ADMIN = {
    "admin", "administrador", "dono", "proprietario", "proprietário", "owner",
}


def autenticar_admin(login: str, senha: str) -> Optional[dict]:
    """Login simples: só libera se tipo normalizado for admin."""
    import hashlib

    row = sql_df(
        """
        SELECT id, nome, login, tipo, senha_hash, loja, ativo
        FROM public.usuarios
        WHERE LOWER(login) = LOWER(:login)
        LIMIT 1
        """,
        {"login": login.strip()},
    )
    if row.empty:
        return None
    r = row.iloc[0]
    if r.get("ativo") is False:
        return None
    tipo = str(r["tipo"] or "").strip().lower()
    if tipo not in ROLE_ADMIN:
        return None

    hash_db = str(r.get("senha_hash") or "")
    # Compat: hash sha256 simples ou texto (legado)
    ok = False
    if hash_db.startswith("$") or len(hash_db) > 40:
        # tenta comparar sha256 hex
        candidato = hashlib.sha256(senha.encode("utf-8")).hexdigest()
        ok = hash_db == candidato or hash_db.endswith(candidato)
    if not ok:
        ok = hash_db == senha or hash_db == hashlib.sha256(senha.encode()).hexdigest()
    # Se o app principal usa outro hash, aceita se o usuário já está logado
    # via cookie compartilhado — fallback: confia no hash se bater parcial
    if not ok and hash_db:
        try:
            # pbkdf2 / formato do app_manu: "salt$hash" ou similar
            if "$" in hash_db:
                parts = hash_db.split("$")
                # verificação fraca só se plain
                ok = False
        except Exception:
            pass
    if not ok:
        # Último recurso: o dashboard admin pode validar via função do app
        # se a senha em texto ainda existir em migração
        return None

    return {
        "id": int(r["id"]),
        "nome": r["nome"],
        "login": r["login"],
        "tipo": "admin",
        "loja": str(r.get("loja") or "381"),
    }


def verificar_senha_admin(senha_digitada: str, senha_salva: str) -> bool:
    """Compatível com app_manu: pbkdf2$iter$salt$hash ou texto puro legado."""
    import hashlib
    import hmac

    senha_salva = str(senha_salva or "")
    senha_digitada = senha_digitada.strip()
    if not senha_salva:
        return False
    # legado texto puro
    if not senha_salva.startswith("pbkdf2"):
        return hmac.compare_digest(senha_digitada, senha_salva)
    try:
        parts = senha_salva.split("$")
        # pbkdf2$ITER$SALT$HASH
        if len(parts) >= 4 and "pbkdf2" in parts[0]:
            iteracoes = int(parts[1])
            salt = bytes.fromhex(parts[2])
            hash_hex = parts[3]
            derivada = hashlib.pbkdf2_hmac(
                "sha256",
                senha_digitada.encode("utf-8"),
                salt,
                iteracoes,
            )
            return hmac.compare_digest(derivada.hex(), hash_hex)
    except Exception:
        return False
    return False


def autenticar_admin_via_app_hash(login: str, senha: str) -> Optional[dict]:
    row = sql_df(
        """
        SELECT id, nome, login, tipo, senha_hash, loja, ativo
        FROM public.usuarios
        WHERE LOWER(login) = LOWER(:login)
        LIMIT 1
        """,
        {"login": login.strip()},
    )
    if row.empty:
        return None
    r = row.iloc[0]
    if r.get("ativo") is False:
        return None
    tipo = str(r["tipo"] or "").strip().lower()
    if tipo not in ROLE_ADMIN:
        st.error("Acesso restrito a administradores.")
        return None
    if not verificar_senha_admin(senha, str(r.get("senha_hash") or "")):
        return None
    return {
        "id": int(r["id"]),
        "nome": r["nome"],
        "login": r["login"],
        "tipo": "admin",
        "loja": str(r.get("loja") or "381"),
    }


# ---------------------------------------------------------------------------
# Filtros de loja (JOIN vendedores)
# ---------------------------------------------------------------------------
def filtro_loja_sql(loja: str, alias_v: str = "v") -> Tuple[str, dict]:
    if not loja or loja == "TODAS":
        return "TRUE", {}
    return f"UPPER(COALESCE({alias_v}.loja, '381')) = UPPER(:filtro_loja)", {
        "filtro_loja": loja
    }


# ---------------------------------------------------------------------------
# Queries de funil / finanças / desempenho
# ---------------------------------------------------------------------------
def funil_conversao(loja: str, di: date, dfim: date) -> Dict[str, int]:
    fl, params = filtro_loja_sql(loja)
    params.update({"di": di, "df": dfim + timedelta(days=1)})
    q = f"""
        SELECT
            COUNT(l.id) AS leads,
            COUNT(l.id) FILTER (WHERE COALESCE(l.respondeu, FALSE)) AS responderam,
            COUNT(l.id) FILTER (WHERE COALESCE(l.gerou_ficha, FALSE)) AS fichas,
            COUNT(l.id) FILTER (WHERE COALESCE(l.aprovou_credito, FALSE)) AS aprovados,
            COUNT(l.id) FILTER (
                WHERE COALESCE(l.venda_concluida, FALSE)
                   OR COALESCE(l.vendeu, FALSE)
            ) AS compraram
        FROM public.leads l
        LEFT JOIN public.vendedores v ON v.id = l.vendedor_id
        WHERE l.data_lead >= :di AND l.data_lead < :df
          AND ({fl})
    """
    row = sql_df(q, params)
    if row.empty:
        return {k: 0 for k in ("leads", "responderam", "fichas", "aprovados", "compraram")}
    r = row.iloc[0]
    return {k: int(r[k] or 0) for k in ("leads", "responderam", "fichas", "aprovados", "compraram")}


def financeiro_periodo(loja: str, di: date, dfim: date) -> Dict[str, float]:
    """
    Entrada de dinheiro ≈ valor_liberado + entrada_paga das fichas comprou.
    Gasto oficina ≈ soma numérica de valor_final (texto → numeric quando possível).
    Pendente ≈ sum(valor_pendente) onde comprou e gerou boleto.
    """
    fl, params = filtro_loja_sql(loja)
    params.update({"di": di, "df": dfim + timedelta(days=1)})

    q_fin = f"""
        SELECT
            COALESCE(SUM(f.valor_liberado), 0) AS liberado,
            COALESCE(SUM(f.entrada_paga), 0) AS entrada_paga,
            COALESCE(SUM(f.valor_pendente) FILTER (
                WHERE COALESCE(f.gerou_boleto, FALSE) AND COALESCE(f.valor_pendente, 0) > 0
            ), 0) AS pendente,
            COALESCE(SUM(f.boleto_total) FILTER (WHERE COALESCE(f.gerou_boleto, FALSE)), 0)
                AS boletos,
            COALESCE(SUM(
                COALESCE(f.valor_liberado, 0) + COALESCE(f.entrada_paga, 0)
            ) FILTER (WHERE COALESCE(f.comprou, FALSE)), 0) AS bruto_vendas,
            COUNT(*) FILTER (WHERE COALESCE(f.comprou, FALSE)) AS qtd_compras
        FROM public.fichas_credito f
        LEFT JOIN public.vendedores v ON v.id = f.vendedor_id
        WHERE COALESCE(f.data_compra, f.created_at::date) >= :di
          AND COALESCE(f.data_compra, f.created_at::date) < :df
          AND ({fl})
    """
    fin = sql_df(q_fin, params).iloc[0]

    # Oficina: valor_final é TEXT — tenta parse BR/US
    q_of = """
        SELECT COALESCE(SUM(
            CASE
                WHEN valor_final ~ '^[0-9]+([.,][0-9]+)?$'
                THEN REPLACE(REPLACE(valor_final, '.', ''), ',', '.')::numeric
                WHEN valor_final ~ '^[0-9]+\\.[0-9]+$'
                THEN valor_final::numeric
                ELSE 0
            END
        ), 0) AS gasto_oficina
        FROM public.oficina_carros
        WHERE updated_at >= :di AND updated_at < :df
    """
    try:
        of = sql_df(q_of, {"di": di, "df": dfim + timedelta(days=1)}).iloc[0]
        gasto = float(of["gasto_oficina"] or 0)
    except Exception:
        gasto = 0.0

    return {
        "liberado": float(fin["liberado"] or 0),
        "entrada_paga": float(fin["entrada_paga"] or 0),
        "pendente": float(fin["pendente"] or 0),
        "boletos": float(fin["boletos"] or 0),
        "bruto_vendas": float(fin["bruto_vendas"] or 0),
        "qtd_compras": int(fin["qtd_compras"] or 0),
        "gasto_oficina": gasto,
        "liquido_aprox": float(fin["bruto_vendas"] or 0) - gasto,
    }


def serie_mensal(loja: str, meses: int = 6) -> pd.DataFrame:
    """Série dos últimos N meses: leads, vendas, bruto, pendente."""
    hoje = date.today().replace(day=1)
    rows = []
    for i in range(meses - 1, -1, -1):
        # mês de referência
        y = hoje.year
        m = hoje.month - i
        while m <= 0:
            m += 12
            y -= 1
        di = date(y, m, 1)
        if m == 12:
            dfim = date(y + 1, 1, 1) - timedelta(days=1)
        else:
            dfim = date(y, m + 1, 1) - timedelta(days=1)
        funil = funil_conversao(loja, di, dfim)
        fin = financeiro_periodo(loja, di, dfim)
        rows.append({
            "mes": di.strftime("%Y-%m"),
            "label": di.strftime("%b/%y"),
            "leads": funil["leads"],
            "responderam": funil["responderam"],
            "fichas": funil["fichas"],
            "aprovados": funil["aprovados"],
            "compraram": funil["compraram"],
            "bruto": fin["bruto_vendas"],
            "pendente": fin["pendente"],
            "oficina": fin["gasto_oficina"],
            "liquido": fin["liquido_aprox"],
        })
    return pd.DataFrame(rows)


def projetar_proximo_mes(serie: pd.DataFrame, col: str) -> Dict[str, float]:
    """
    Estimativa do mês seguinte com base em 1, 2 e 3 meses anteriores.
    Média simples + tendência linear leve.
    """
    vals = serie[col].astype(float).tolist()
    if not vals:
        return {"m1": 0, "m2": 0, "m3": 0, "media": 0, "tendencia": 0}
    m1 = vals[-1] if len(vals) >= 1 else 0
    m2 = sum(vals[-2:]) / 2 if len(vals) >= 2 else m1
    m3 = sum(vals[-3:]) / 3 if len(vals) >= 3 else m2
    media = (m1 + m2 + m3) / 3
    # tendência: diferença média entre últimos 3
    if len(vals) >= 3:
        tendencia = (vals[-1] - vals[-3]) / 2
    elif len(vals) >= 2:
        tendencia = vals[-1] - vals[-2]
    else:
        tendencia = 0
    proj = max(0, media + 0.35 * tendencia)
    return {
        "m1": float(m1),
        "m2": float(m2),
        "m3": float(m3),
        "media": float(media),
        "tendencia": float(tendencia),
        "projecao": float(proj),
    }


def desempenho_vendedores(loja: str, di: date, dfim: date) -> pd.DataFrame:
    fl, params = filtro_loja_sql(loja)
    params.update({"di": di, "df": dfim + timedelta(days=1)})
    q = f"""
        SELECT
            v.id AS vendedor_id,
            v.nome,
            COALESCE(v.loja, '381') AS loja,
            COUNT(l.id) AS leads,
            COUNT(l.id) FILTER (WHERE COALESCE(l.respondeu, FALSE)) AS responderam,
            COUNT(l.id) FILTER (WHERE COALESCE(l.gerou_ficha, FALSE)) AS fichas,
            COUNT(l.id) FILTER (WHERE COALESCE(l.aprovou_credito, FALSE)) AS aprovados,
            COUNT(l.id) FILTER (
                WHERE COALESCE(l.venda_concluida, FALSE) OR COALESCE(l.vendeu, FALSE)
            ) AS compraram
        FROM public.vendedores v
        LEFT JOIN public.leads l
            ON l.vendedor_id = v.id
           AND l.data_lead >= :di AND l.data_lead < :df
        WHERE ({fl})
        GROUP BY v.id, v.nome, v.loja
        HAVING COUNT(l.id) > 0
        ORDER BY compraram DESC, leads DESC
    """
    df = sql_df(q, params)
    if df.empty:
        return df
    df["conv_lead_venda"] = df.apply(
        lambda r: (r["compraram"] / r["leads"]) if r["leads"] else 0, axis=1
    )
    df["conv_ficha_venda"] = df.apply(
        lambda r: (r["compraram"] / r["fichas"]) if r["fichas"] else 0, axis=1
    )

    # Tarefas cumpridas por usuário ligado ao vendedor
    try:
        tq = """
            SELECT
                u.vendedor_id,
                COUNT(t.id) AS tarefas,
                COUNT(t.id) FILTER (WHERE t.resposta IS TRUE) AS tarefas_ok,
                COUNT(t.id) FILTER (WHERE t.resposta IS FALSE) AS tarefas_nao,
                COUNT(t.id) FILTER (WHERE t.resposta IS NULL) AS tarefas_pend
            FROM public.tarefas t
            JOIN public.usuarios u ON u.id = t.destinatario_id
            WHERE u.vendedor_id IS NOT NULL
              AND t.created_at >= :di AND t.created_at < :df
            GROUP BY u.vendedor_id
        """
        td = sql_df(tq, {"di": di, "df": dfim + timedelta(days=1)})
        if not td.empty:
            df = df.merge(td, on="vendedor_id", how="left")
        else:
            df["tarefas"] = 0
            df["tarefas_ok"] = 0
    except Exception:
        df["tarefas"] = 0
        df["tarefas_ok"] = 0

    df["tarefas"] = df.get("tarefas", 0).fillna(0).astype(int)
    df["tarefas_ok"] = df.get("tarefas_ok", 0).fillna(0).astype(int)
    df["taxa_tarefas"] = df.apply(
        lambda r: (r["tarefas_ok"] / r["tarefas"]) if r["tarefas"] else None,
        axis=1,
    )

    def status(r):
        if r["leads"] >= 5 and r["conv_lead_venda"] < LIMIAR_CONVERSAO_RUIM:
            return "ruim"
        if r["tarefas"] >= 3 and r["taxa_tarefas"] is not None and r["taxa_tarefas"] < LIMIAR_TAREFAS_RUIM:
            return "ruim"
        if r["conv_lead_venda"] < LIMIAR_CONVERSAO_MEDIO:
            return "medio"
        return "bom"

    df["status"] = df.apply(status, axis=1)
    return df


def desempenho_por_tipo(tipo: str, di: date, dfim: date) -> pd.DataFrame:
    """Desempenho de guariba / mecanico / etc. via tarefas."""
    q = """
        SELECT
            u.id,
            u.nome,
            u.tipo,
            COALESCE(u.loja, '381') AS loja,
            COUNT(t.id) AS tarefas,
            COUNT(t.id) FILTER (WHERE t.resposta IS TRUE) AS ok,
            COUNT(t.id) FILTER (WHERE t.resposta IS FALSE) AS nao,
            COUNT(t.id) FILTER (WHERE t.resposta IS NULL) AS pend
        FROM public.usuarios u
        LEFT JOIN public.tarefas t
            ON t.destinatario_id = u.id
           AND t.created_at >= :di AND t.created_at < :df
        WHERE LOWER(u.tipo) = LOWER(:tipo)
          AND COALESCE(u.ativo, TRUE) = TRUE
        GROUP BY u.id, u.nome, u.tipo, u.loja
        ORDER BY ok DESC, tarefas DESC
    """
    try:
        df = sql_df(q, {"tipo": tipo, "di": di, "df": dfim + timedelta(days=1)})
    except Exception:
        return pd.DataFrame()
    if df.empty:
        return df
    df["taxa"] = df.apply(
        lambda r: (r["ok"] / r["tarefas"]) if r["tarefas"] else 0, axis=1
    )
    df["status"] = df.apply(
        lambda r: (
            "ruim" if r["tarefas"] >= 2 and r["taxa"] < LIMIAR_TAREFAS_RUIM
            else ("medio" if r["taxa"] < 0.75 else "bom")
        ),
        axis=1,
    )
    return df


# ---------------------------------------------------------------------------
# Charts ECharts
# ---------------------------------------------------------------------------
def chart_funil(dados: Dict[str, int]) -> dict:
    stages = [
        ("Leads", dados["leads"]),
        ("Responderam", dados["responderam"]),
        ("Geraram ficha", dados["fichas"]),
        ("Aprovados", dados["aprovados"]),
        ("Compraram", dados["compraram"]),
    ]
    return {
        "tooltip": {"trigger": "item", "formatter": "{b}: {c}"},
        "series": [
            {
                "name": "Funil",
                "type": "funnel",
                "left": "10%",
                "width": "80%",
                "min": 0,
                "max": max(stages[0][1], 1),
                "minSize": "15%",
                "maxSize": "100%",
                "sort": "none",
                "gap": 4,
                "label": {
                    "show": True,
                    "position": "inside",
                    "formatter": "{b}\n{c}",
                    "color": "#fff",
                },
                "itemStyle": {"borderColor": COR_FUNDO, "borderWidth": 2},
                "data": [
                    {
                        "value": v,
                        "name": n,
                        "itemStyle": {
                            "color": [COR_AZUL, COR_CIANO, COR_ROXO, COR_MEDIO, COR_BOM][i]
                        },
                    }
                    for i, (n, v) in enumerate(stages)
                ],
            }
        ],
    }


def chart_barras_fin(fin: Dict[str, float]) -> dict:
    cats = ["Bruto vendas", "Liberado banco", "Entrada paga", "Pendente", "Oficina", "Líquido ≈"]
    vals = [
        fin["bruto_vendas"],
        fin["liberado"],
        fin["entrada_paga"],
        fin["pendente"],
        fin["gasto_oficina"],
        fin["liquido_aprox"],
    ]
    colors = [COR_BOM, COR_AZUL, COR_CIANO, COR_MEDIO, COR_RUIM, COR_ROXO]
    return {
        "tooltip": {"trigger": "axis", "axisPointer": {"type": "shadow"}},
        "grid": {"left": 60, "right": 20, "top": 30, "bottom": 40},
        "xAxis": {
            "type": "category",
            "data": cats,
            "axisLabel": {"color": COR_TEXTO, "rotate": 20},
        },
        "yAxis": {
            "type": "value",
            "axisLabel": {
                "color": COR_TEXTO,
                "formatter": "R$ {value}",
            },
            "splitLine": {"lineStyle": {"color": "#243041"}},
        },
        "series": [
            {
                "type": "bar",
                "data": [
                    {"value": round(v, 2), "itemStyle": {"color": colors[i]}}
                    for i, v in enumerate(vals)
                ],
                "barWidth": "45%",
                "label": {
                    "show": True,
                    "position": "top",
                    "formatter": "R$ {c}",
                    "color": COR_TEXTO,
                    "fontSize": 10,
                },
            }
        ],
    }


def chart_serie_mensal(serie: pd.DataFrame, proj_bruto: dict, proj_leads: dict) -> dict:
    labels = serie["label"].tolist() + ["Próx. mês*"]
    bruto = serie["bruto"].astype(float).tolist() + [proj_bruto.get("projecao", 0)]
    leads = serie["leads"].astype(float).tolist() + [proj_leads.get("projecao", 0)]
    pend = serie["pendente"].astype(float).tolist() + [None]
    return {
        "tooltip": {"trigger": "axis"},
        "legend": {
            "data": ["Bruto vendas", "Leads", "Pendente"],
            "textStyle": {"color": COR_TEXTO},
        },
        "grid": {"left": 50, "right": 50, "top": 40, "bottom": 40},
        "xAxis": {
            "type": "category",
            "data": labels,
            "axisLabel": {"color": COR_TEXTO},
        },
        "yAxis": [
            {
                "type": "value",
                "name": "R$",
                "axisLabel": {"color": COR_TEXTO},
                "splitLine": {"lineStyle": {"color": "#243041"}},
            },
            {
                "type": "value",
                "name": "Leads",
                "axisLabel": {"color": COR_TEXTO},
                "splitLine": {"show": False},
            },
        ],
        "series": [
            {
                "name": "Bruto vendas",
                "type": "bar",
                "data": [round(x, 2) if x is not None else None for x in bruto],
                "itemStyle": {
                    "color": COR_AZUL,
                },
            },
            {
                "name": "Pendente",
                "type": "line",
                "data": [round(x, 2) if x is not None else None for x in pend],
                "itemStyle": {"color": COR_MEDIO},
                "smooth": True,
            },
            {
                "name": "Leads",
                "type": "line",
                "yAxisIndex": 1,
                "data": leads,
                "itemStyle": {"color": COR_CIANO},
                "smooth": True,
            },
        ],
    }


def chart_vendedores(df: pd.DataFrame) -> dict:
    if df.empty:
        return {"title": {"text": "Sem dados", "left": "center"}}
    nomes = df["nome"].tolist()
    cores = [
        COR_RUIM if s == "ruim" else (COR_MEDIO if s == "medio" else COR_BOM)
        for s in df["status"].tolist()
    ]
    return {
        "tooltip": {
            "trigger": "axis",
            "axisPointer": {"type": "shadow"},
        },
        "legend": {
            "data": ["Leads", "Compraram", "Conv. %"],
            "textStyle": {"color": COR_TEXTO},
        },
        "grid": {"left": 100, "right": 40, "top": 40, "bottom": 30},
        "xAxis": {
            "type": "value",
            "axisLabel": {"color": COR_TEXTO},
            "splitLine": {"lineStyle": {"color": "#243041"}},
        },
        "yAxis": {
            "type": "category",
            "data": nomes,
            "axisLabel": {"color": COR_TEXTO},
        },
        "series": [
            {
                "name": "Leads",
                "type": "bar",
                "data": df["leads"].tolist(),
                "itemStyle": {"color": "#334155"},
            },
            {
                "name": "Compraram",
                "type": "bar",
                "data": [
                    {"value": int(v), "itemStyle": {"color": c}}
                    for v, c in zip(df["compraram"].tolist(), cores)
                ],
            },
            {
                "name": "Conv. %",
                "type": "line",
                "data": [round(x * 100, 1) for x in df["conv_lead_venda"].tolist()],
                "itemStyle": {"color": COR_ROXO},
            },
        ],
    }


def chart_tarefas_equipe(df: pd.DataFrame, titulo: str) -> dict:
    if df.empty:
        return {
            "title": {"text": f"{titulo}: sem dados", "left": "center", "textStyle": {"color": COR_TEXTO}}
        }
    return {
        "title": {"text": titulo, "left": "center", "textStyle": {"color": COR_TEXTO, "fontSize": 13}},
        "tooltip": {"trigger": "axis"},
        "legend": {"data": ["Concluídas", "Pendentes", "Não"], "textStyle": {"color": COR_TEXTO}},
        "grid": {"left": 80, "right": 20, "top": 50, "bottom": 30},
        "xAxis": {
            "type": "category",
            "data": df["nome"].tolist(),
            "axisLabel": {"color": COR_TEXTO, "rotate": 30},
        },
        "yAxis": {
            "type": "value",
            "axisLabel": {"color": COR_TEXTO},
            "splitLine": {"lineStyle": {"color": "#243041"}},
        },
        "series": [
            {
                "name": "Concluídas",
                "type": "bar",
                "stack": "t",
                "data": [
                    {
                        "value": int(r["ok"]),
                        "itemStyle": {
                            "color": COR_RUIM if r["status"] == "ruim" else COR_BOM
                        },
                    }
                    for _, r in df.iterrows()
                ],
            },
            {
                "name": "Pendentes",
                "type": "bar",
                "stack": "t",
                "data": df["pend"].astype(int).tolist(),
                "itemStyle": {"color": COR_MEDIO},
            },
            {
                "name": "Não",
                "type": "bar",
                "stack": "t",
                "data": df["nao"].astype(int).tolist(),
                "itemStyle": {"color": "#64748b"},
            },
        ],
    }


def render_echarts(options: dict, height: str = "380px", key: str = "c"):
    if st_echarts is None:
        st.error("Instale: pip install streamlit-echarts")
        st.json(options)
        return
    st_echarts(options=options, height=height, theme="dark", key=key)


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
def pagina_login():
    st.markdown("## 📈 Dashboard Executivo")
    st.caption("Acesso exclusivo administradores · mesmo banco do sistema operacional")
    with st.form("login_admin"):
        login = st.text_input("Login admin")
        senha = st.text_input("Senha", type="password")
        ok = st.form_submit_button("Entrar", type="primary")
    if ok:
        user = autenticar_admin_via_app_hash(login, senha)
        if user:
            st.session_state["admin_user"] = user
            st.rerun()
        else:
            st.error("Falha no login ou usuário não é admin.")


def pagina_dashboard(user: dict):
    st.sidebar.markdown(f"**{user['nome']}** · admin")
    if st.sidebar.button("Sair"):
        st.session_state.pop("admin_user", None)
        st.rerun()

    st.sidebar.markdown("---")
    loja = st.sidebar.selectbox("Escopo (loja)", LOJAS, index=0)
    periodo = st.sidebar.selectbox(
        "Período",
        ["Este mês", "Mês passado", "Últimos 30 dias", "Últimos 90 dias", "Ano atual"],
        index=0,
    )
    hoje = date.today()
    if periodo == "Este mês":
        di = hoje.replace(day=1)
        dfim = hoje
    elif periodo == "Mês passado":
        primeiro = hoje.replace(day=1)
        dfim = primeiro - timedelta(days=1)
        di = dfim.replace(day=1)
    elif periodo == "Últimos 30 dias":
        di = hoje - timedelta(days=30)
        dfim = hoje
    elif periodo == "Últimos 90 dias":
        di = hoje - timedelta(days=90)
        dfim = hoje
    else:
        di = date(hoje.year, 1, 1)
        dfim = hoje

    st.sidebar.caption(f"{di.strftime('%d/%m/%Y')} → {dfim.strftime('%d/%m/%Y')}")
    st.title("Dashboard de Desempenho")
    st.caption(
        f"Filtro: **{loja}** · {periodo}. "
        "Vermelho = abaixo do limiar de conversão/tarefas."
    )

    # ---- KPIs topo ----
    funil = funil_conversao(loja, di, dfim)
    fin = financeiro_periodo(loja, di, dfim)

    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("Leads", funil["leads"])
    k2.metric(
        "Responderam",
        funil["responderam"],
        f"{100 * funil['responderam'] / funil['leads']:.0f}%" if funil["leads"] else None,
    )
    k3.metric("Fichas", funil["fichas"])
    k4.metric("Aprovados", funil["aprovados"])
    k5.metric("Compraram", funil["compraram"])
    conv = (funil["compraram"] / funil["leads"] * 100) if funil["leads"] else 0
    k6.metric("Conv. lead→venda", f"{conv:.1f}%")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Bruto das vendas", f"R$ {fin['bruto_vendas']:,.0f}")
    m2.metric("Pendente", f"R$ {fin['pendente']:,.0f}")
    m3.metric("Gasto da oficina", f"R$ {fin['gasto_oficina']:,.0f}")
    m4.metric("Líquido ≈", f"R$ {fin['liquido_aprox']:,.0f}")

    st.markdown("---")

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Funil de conversão")
        render_echarts(chart_funil(funil), height="420px", key="funil")
        if funil["leads"]:
            st.caption(
                f"Lead→resposta {100*funil['responderam']/funil['leads']:.0f}% · "
                f"Lead→ficha {100*funil['fichas']/funil['leads']:.0f}% · "
                f"Ficha→aprovado "
                f"{(100*funil['aprovados']/funil['fichas']) if funil['fichas'] else 0:.0f}% · "
                f"Aprovado→compra "
                f"{(100*funil['compraram']/funil['aprovados']) if funil['aprovados'] else 0:.0f}%"
            )
    with c2:
        st.subheader("Finanças do período")
        render_echarts(chart_barras_fin(fin), height="420px", key="fin")
        st.caption(
            "Bruto = liberado pelo banco + entrada paga. "
            "Líquido ≈ bruto − gastos registrados na oficina (valor final)."
        )

    # ---- Série + projeção ----
    st.markdown("---")
    st.subheader("Histórico mensal e estimativa do próximo mês")
    serie = serie_mensal(loja, meses=6)
    proj_bruto = projetar_proximo_mes(serie, "bruto")
    proj_leads = projetar_proximo_mes(serie, "leads")
    proj_comp = projetar_proximo_mes(serie, "compraram")

    render_echarts(
        chart_serie_mensal(serie, proj_bruto, proj_leads),
        height="400px",
        key="serie",
    )
    p1, p2, p3 = st.columns(3)
    p1.info(
        f"**Bruto projetado:** R$ {proj_bruto['projecao']:,.0f}\n\n"
        f"Média 1/2/3 meses: {proj_bruto['m1']:,.0f} / {proj_bruto['m2']:,.0f} / {proj_bruto['m3']:,.0f}"
    )
    p2.info(
        f"**Leads projetados:** {proj_leads['projecao']:.0f}\n\n"
        f"Média 1/2/3 meses: {proj_leads['m1']:.0f} / {proj_leads['m2']:.0f} / {proj_leads['m3']:.0f}"
    )
    p3.info(
        f"**Compras projetadas:** {proj_comp['projecao']:.0f}\n\n"
        f"Tendência: {proj_comp['tendencia']:+.1f} / mês"
    )
    st.caption(
        "*Projeção = média ponderada dos últimos 1–3 meses + 35% da tendência. "
        "Não é garantia — use como ordem de grandeza."
    )

    # ---- Vendedores ----
    st.markdown("---")
    st.subheader("Desempenho por vendedor")
    st.caption(
        f"Vermelho: conversão lead→venda < {LIMIAR_CONVERSAO_RUIM*100:.0f}% "
        f"(com ≥5 leads) ou tarefas < {LIMIAR_TAREFAS_RUIM*100:.0f}%."
    )
    dv = desempenho_vendedores(loja, di, dfim)
    if dv.empty:
        st.warning("Sem leads no período para este filtro.")
    else:
        render_echarts(chart_vendedores(dv), height=f"{max(420, 80 + 28 * len(dv))}px", key="vend")
        # tabela detalhada
        show = dv.copy()
        show["conv %"] = (show["conv_lead_venda"] * 100).round(1)
        show["tarefas %"] = show["taxa_tarefas"].apply(
            lambda x: f"{100*x:.0f}%" if x is not None and pd.notna(x) else "—"
        )
        show["alerta"] = show["status"].map(
            {"ruim": "🔴 Ruim", "medio": "🟡 Médio", "bom": "🟢 Bom"}
        )
        st.dataframe(
            show[
                [
                    "nome", "loja", "leads", "responderam", "fichas",
                    "aprovados", "compraram", "conv %", "tarefas", "tarefas_ok",
                    "tarefas %", "alerta",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )

    # ---- Oficina / guariba / mecanico ----
    st.markdown("---")
    st.subheader("Equipes de oficina (tarefas)")
    g1, g2 = st.columns(2)
    with g1:
        dg = desempenho_por_tipo("guariba", di, dfim)
        render_echarts(chart_tarefas_equipe(dg, "Guaribas"), height="360px", key="gua")
        if not dg.empty:
            st.dataframe(
                dg.assign(
                    alerta=dg["status"].map(
                        {"ruim": "🔴", "medio": "🟡", "bom": "🟢"}
                    ),
                    taxa_pct=(dg["taxa"] * 100).round(0),
                )[["nome", "loja", "tarefas", "ok", "pend", "nao", "taxa_pct", "alerta"]],
                use_container_width=True,
                hide_index=True,
            )
    with g2:
        dm = desempenho_por_tipo("mecanico", di, dfim)
        if dm.empty:
            dm = desempenho_por_tipo("mecânico", di, dfim)
        render_echarts(chart_tarefas_equipe(dm, "Mecânicos"), height="360px", key="mec")
        if not dm.empty:
            st.dataframe(
                dm.assign(
                    alerta=dm["status"].map(
                        {"ruim": "🔴", "medio": "🟡", "bom": "🟢"}
                    ),
                    taxa_pct=(dm["taxa"] * 100).round(0),
                )[["nome", "loja", "tarefas", "ok", "pend", "nao", "taxa_pct", "alerta"]],
                use_container_width=True,
                hide_index=True,
            )

    secao_ia_especialista(loja, di, dfim)

    st.markdown("---")
    st.caption(
        "Manu Dashboard Admin · dados em tempo quase real (cache curto nas queries). "
        "Não substitui o app operacional."
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# IA especialista (dashboard) — funil, finanças, previsão 1–2 meses
# ---------------------------------------------------------------------------

def _contexto_dashboard_ia(loja: str, di: date, dfim: date) -> str:
    funil = funil_conversao(loja, di, dfim)
    fin = financeiro_periodo(loja, di, dfim)
    serie = serie_mensal(loja, meses=6)
    pb = projetar_proximo_mes(serie, "bruto")
    pl = projetar_proximo_mes(serie, "leads")
    pc = projetar_proximo_mes(serie, "compraram")
    # projeção 2 meses: aplica tendência de novo
    proj2_bruto = max(0, pb["projecao"] + 0.35 * pb.get("tendencia", 0))
    proj2_leads = max(0, pl["projecao"] + 0.35 * pl.get("tendencia", 0))
    proj2_comp = max(0, pc["projecao"] + 0.35 * pc.get("tendencia", 0))

    linhas = [
        f"Escopo loja={loja} período={di} a {dfim}",
        f"Funil: leads={funil['leads']}, responderam={funil['responderam']}, "
        f"fichas={funil['fichas']}, aprovados={funil['aprovados']}, compraram={funil['compraram']}",
        f"Finanças: bruto={fin['bruto_vendas']:.0f}, liberado={fin['liberado']:.0f}, "
        f"entrada={fin['entrada_paga']:.0f}, pendente={fin['pendente']:.0f}, "
        f"oficina={fin['gasto_oficina']:.0f}, liquido≈{fin['liquido_aprox']:.0f}",
        f"Projeção próximo mês: bruto≈{pb['projecao']:.0f}, leads≈{pl['projecao']:.0f}, "
        f"compras≈{pc['projecao']:.0f}",
        f"Projeção ~2 meses à frente: bruto≈{proj2_bruto:.0f}, leads≈{proj2_leads:.0f}, "
        f"compras≈{proj2_comp:.0f}",
        f"Série mensal (label|leads|compraram|bruto): "
        + " ; ".join(
            f"{r['label']}|{r['leads']}|{r['compraram']}|{r['bruto']:.0f}"
            for _, r in serie.iterrows()
        ),
    ]
    try:
        dv = desempenho_vendedores(loja, di, dfim)
        if not dv.empty:
            top = dv.head(5)
            weak = dv[dv["status"] == "ruim"].head(5)
            linhas.append(
                "Top vendedores (nome|leads|vendas|conv%): "
                + " ; ".join(
                    f"{r['nome']}|{r['leads']}|{r['compraram']}|{100*r['conv_lead_venda']:.0f}%"
                    for _, r in top.iterrows()
                )
            )
            if not weak.empty:
                linhas.append(
                    "Atenção (desempenho fraco): "
                    + ", ".join(weak["nome"].tolist())
                )
    except Exception as e:
        linhas.append(f"(vendedores: {e})")
    return "\n".join(linhas)


def _resposta_especialista_local(pergunta: str, contexto: str) -> str:
    p = (pergunta or "").lower()
    if any(x in p for x in ("quem é você", "quem e voce", "quem voce", "quem eh")):
        return "sou Suporte Manu Automóveis — especialista em funil, finanças e previsão deste dashboard"
    if any(x in p for x in ("quem te criou", "quem criou")):
        return "Nasci pra te ajudar e caso precise de um amigo"

    # extrai números do contexto
    def grab(tag: str) -> str:
        for ln in contexto.split("\n"):
            if ln.startswith(tag):
                return ln
        return ""

    funil = grab("Funil:")
    fin = grab("Finanças:")
    p1 = grab("Projeção próximo mês:")
    p2 = grab("Projeção ~2 meses")

    if any(x in p for x in ("previs", "projec", "próximo mês", "proximo mes", "2 meses", "dois meses")):
        return (
            f"{p1}\n\n{p2}\n\n"
            "Método: média dos últimos 1–3 meses + parte da tendência. "
            "É ordem de grandeza, não garantia. "
            "Se o funil travar em resposta ou ficha, a projeção de compra cai junto."
        )
    if any(x in p for x in ("funil", "convers", "afunil")):
        return (
            f"{funil}\n\n"
            "Leia de cima pra baixo: onde a conta cai mais (lead→resposta, "
            "resposta→ficha, ficha→aprovado, aprovado→compra) é o gargalo da semana."
        )
    if any(x in p for x in ("finance", "bruto", "pendente", "lucro", "oficina", "dinheiro")):
        return (
            f"{fin}\n\n"
            "Bruto ≈ liberado + entrada paga. Líquido ≈ bruto − oficina. "
            "Pendente alto = boleto a receber — cobranca e previsao de caixa."
        )
    if any(x in p for x in ("vendedor", "desempenho", "ruim", "time")):
        attn = grab("Atenção")
        top = grab("Top vendedores")
        return (
            f"{top}\n{attn}\n\n"
            "Quem está vermelho precisa de coaching ou redistribuição de lead; "
            "quem converte bem pode receber mais volume quente."
        )
    return (
        f"Dados do filtro atual:\n{funil}\n{fin}\n{p1}\n{p2}\n\n"
        "Pergunte por funil, gargalo, caixa, pendente, previsão de 1 ou 2 meses "
        "ou desempenho de vendedor."
    )


def _chamar_xai_dash(mensagens: list, sistema: str) -> Optional[str]:
    import json
    import urllib.request
    try:
        xai = st.secrets.get("xai", {})
        key = xai.get("api_key") if hasattr(xai, "get") else None
        if not key:
            key = st.secrets.get("XAI_API_KEY")
        model = (xai.get("model") if hasattr(xai, "get") else None) or "grok-3"
    except Exception:
        return None
    if not key:
        return None
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": sistema}] + mensagens,
        "temperature": 0.5,
        "max_tokens": 700,
    }
    req = urllib.request.Request(
        "https://api.x.ai/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=75) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]
    except Exception:
        return None


def secao_ia_especialista(loja: str, di: date, dfim: date) -> None:
    st.markdown("---")
    st.subheader("Suporte especialista (funil · finanças · previsão)")
    st.caption(
        "sou Suporte Manu Automóveis neste dashboard — usa os números do filtro atual "
        "(loja/período). Previsão de 1 e 2 meses com base na série recente."
    )
    if "dash_ia_msgs" not in st.session_state:
        st.session_state["dash_ia_msgs"] = []

    for msg in st.session_state["dash_ia_msgs"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    q = st.chat_input("Pergunte sobre funil, caixa, previsão…", key="dash_ia_input")
    if q:
        st.session_state["dash_ia_msgs"].append({"role": "user", "content": q})
        with st.chat_message("user"):
            st.markdown(q)
        with st.chat_message("assistant"):
            ph = st.empty()
            ph.markdown("*digitando…*")
            ctx = _contexto_dashboard_ia(loja, di, dfim)
            sistema = (
                "Você é Suporte Manu Automóveis, especialista em funil de vendas, "
                "finanças de concessionária e previsões de curto prazo (1–2 meses).\n"
                "Se perguntarem quem é: sou Suporte Manu Automóveis\n"
                "Se perguntarem quem criou: Nasci pra te ajudar e caso precise de um amigo\n"
                "Use APENAS o contexto numérico abaixo. Respostas claras, médias, sem textão.\n"
                "Explique gargalos do funil, caixa (bruto/pendente/oficina) e projeções.\n"
                f"\n--- DADOS ---\n{ctx}\n--- FIM ---"
            )
            hist = [
                {"role": m["role"], "content": m["content"]}
                for m in st.session_state["dash_ia_msgs"][-12:]
            ]
            ans = _chamar_xai_dash(hist, sistema)
            if not ans:
                ans = _resposta_especialista_local(q, ctx)
            ph.markdown(ans)
        st.session_state["dash_ia_msgs"].append({"role": "assistant", "content": ans})

    if st.button("Limpar chat especialista", key="dash_ia_clear"):
        st.session_state["dash_ia_msgs"] = []
        st.rerun()


def main():
    st.markdown(
        f"""
        <style>
        .stApp {{ background: {COR_FUNDO}; color: {COR_TEXTO}; }}
        [data-testid="stSidebar"] {{ background: #121820; }}
        </style>
        """,
        unsafe_allow_html=True,
    )
    if "admin_user" not in st.session_state:
        st.session_state["admin_user"] = None

    if st.session_state["admin_user"] is None:
        pagina_login()
    else:
        pagina_dashboard(st.session_state["admin_user"])


if __name__ == "__main__":
    main()
else:
    main()
