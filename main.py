import pandas as pd
import requests
from io import StringIO
from datetime import datetime
import psycopg2

# ====================== CONFIGURAÇÃO ======================
SHEET_ID = "1a9Syo0Qf_yZmRaTHoX2NRO_-rsivvvaV5G6durUbBz4"
GID = "0"
CSV_URL = f"https://docs.google.com/spreadsheets/d/{SHEET_ID}/export?format=csv&gid={GID}"

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "manuProject",
    "user": "postgres",
    "password": "danielDantas"
}
# ==========================================================

def limpar_texto(valor):
    if pd.isna(valor):
        return None
    texto = str(valor).strip()
    if texto.lower() in ["", "não informado", "nao informado", "n/i", "nao informa", "não informa", "naõ informado"]:
        return None
    return texto

def normalizar_bool(valor):
    if pd.isna(valor):
        return False
    v = str(valor).strip().lower()
    return v in ["sim", "s", "true", "1", "yes"]

def normalizar_origem(origem):
    if not origem:
        return None
    o = origem.lower().strip()
    mapa = {
        "instagram": "instagram",
        "facebook": "facebook",
        "whatsapp": "whatsapp",
        "web motors": "webmotors",
        "webmotors": "webmotors",
        "messenger": "messenger",
        "na pista": "na_pista",
        "mercado livre": "mercado_livre",
        "olx": "olx",
    }
    return mapa.get(o, o)

def converter_data(data_str):
    if not data_str:
        return None
    try:
        return datetime.strptime(str(data_str).strip(), "%d/%m/%Y").date()
    except:
        return None

def main():
    print("Baixando planilha...")
    response = requests.get(CSV_URL)
    response.raise_for_status()
    
    df = pd.read_csv(StringIO(response.text))
    print(f"Total de linhas baixadas: {len(df)}")

    df.columns = [c.strip() for c in df.columns]

    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    print("Conectado ao banco.")

    # --- Vendedores ---
    vendedores = {}
    for nome in df["Vendedor"].dropna().unique():
        nome_limpo = limpar_texto(nome)
        if nome_limpo:
            cursor.execute(
                "INSERT INTO vendedores (nome) VALUES (%s) ON CONFLICT (nome) DO NOTHING RETURNING id",
                (nome_limpo,)
            )
            result = cursor.fetchone()
            if result:
                vendedores[nome_limpo] = result[0]
            else:
                cursor.execute("SELECT id FROM vendedores WHERE nome = %s", (nome_limpo,))
                vendedores[nome_limpo] = cursor.fetchone()[0]
    print(f"Vendedores: {len(vendedores)}")

    # --- Origens ---
    origens = {}
    for origem in df["Origem da Lead"].dropna().unique():
        origem_norm = normalizar_origem(limpar_texto(origem))
        if origem_norm:
            cursor.execute(
                "INSERT INTO origens_lead (nome) VALUES (%s) ON CONFLICT (nome) DO NOTHING RETURNING id",
                (origem_norm,)
            )
            result = cursor.fetchone()
            if result:
                origens[origem_norm] = result[0]
            else:
                cursor.execute("SELECT id FROM origens_lead WHERE nome = %s", (origem_norm,))
                origens[origem_norm] = cursor.fetchone()[0]
    print(f"Origens: {len(origens)}")

    # --- Leads ---
    inseridos = 0
    atualizados = 0

    for _, row in df.iterrows():
        data_lead = converter_data(row.get("Data"))
        if not data_lead:
            continue

        vendedor_nome = limpar_texto(row.get("Vendedor"))
        if not vendedor_nome or vendedor_nome not in vendedores:
            continue

        vendedor_id = vendedores[vendedor_nome]
        origem_nome = normalizar_origem(limpar_texto(row.get("Origem da Lead")))
        origem_id = origens.get(origem_nome)

        nome_lead = limpar_texto(row.get("Nome do Lead"))
        telefone = limpar_texto(row.get("Telefone"))
        produto = limpar_texto(row.get("Produto/Veículo"))

        respondeu = normalizar_bool(row.get("Respondeu"))
        gerou_ficha = normalizar_bool(row.get("Gerou Ficha"))
        aprovou_credito = normalizar_bool(row.get("Aprovou Crédito"))
        visita_agendada = normalizar_bool(row.get("Visita Agendada"))
        compareceu = normalizar_bool(row.get("Compareceu"))
        vendeu = normalizar_bool(row.get("Vendeu"))

        # Tenta encontrar se o lead já existe
        if telefone:
            cursor.execute("""
                SELECT id FROM leads 
                WHERE data_lead = %s 
                  AND vendedor_id = %s 
                  AND telefone = %s
            """, (data_lead, vendedor_id, telefone))
        else:
            cursor.execute("""
                SELECT id FROM leads 
                WHERE data_lead = %s 
                  AND vendedor_id = %s 
                  AND nome_lead = %s
            """, (data_lead, vendedor_id, nome_lead))

        existing = cursor.fetchone()

        if existing:
            # -- atualizacao
            lead_id = existing[0]
            cursor.execute("""
                UPDATE leads SET
                    origem_id = %s,
                    produto_interesse = %s,
                    nome_lead = %s,
                    telefone = %s,
                    respondeu = %s,
                    gerou_ficha = %s,
                    aprovou_credito = %s,
                    visita_agendada = %s,
                    compareceu = %s,
                    vendeu = %s,
                    updated_at = NOW()
                WHERE id = %s
            """, (
                origem_id, produto, nome_lead, telefone,
                respondeu, gerou_ficha, aprovou_credito,
                visita_agendada, compareceu, vendeu,
                lead_id
            ))
            atualizados += 1
        else:
            # Novo
            cursor.execute("""
                INSERT INTO leads (
                    data_lead, vendedor_id, origem_id,
                    produto_interesse, nome_lead, telefone,
                    respondeu, gerou_ficha, aprovou_credito,
                    visita_agendada, compareceu, vendeu
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                data_lead, vendedor_id, origem_id,
                produto, nome_lead, telefone,
                respondeu, gerou_ficha, aprovou_credito,
                visita_agendada, compareceu, vendeu
            ))
            inseridos += 1

    conn.commit()
    cursor.close()
    conn.close()

    print(f"\n✅ Importação concluída!")
    print(f"Novos leads inseridos: {inseridos}")
    print(f"Leads atualizados:     {atualizados}")

if __name__ == "__main__":
    main()