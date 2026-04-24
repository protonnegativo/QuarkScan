import json
import os
import sqlite3
from typing import Optional

DB_PATH = os.environ.get("DB_PATH", "data/resultados.db")


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS resultados (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                alvo       TEXT NOT NULL,
                ferramenta TEXT NOT NULL,
                parametros TEXT,
                resultado  TEXT NOT NULL,
                timestamp  TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alvo ON resultados(alvo, ferramenta)"
        )
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilidades (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                alvo_raiz     TEXT NOT NULL,
                subdominio    TEXT NOT NULL DEFAULT '',
                tipo          TEXT NOT NULL,
                identificador TEXT NOT NULL,
                severidade    TEXT DEFAULT 'unknown',
                detalhes      TEXT,
                status        TEXT DEFAULT 'encontrado',
                primeira_vez  TEXT DEFAULT (datetime('now', 'localtime')),
                ultima_vez    TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_dedup
            ON vulnerabilidades(alvo_raiz, subdominio, identificador)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS subdominios_memoria (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                alvo_raiz   TEXT NOT NULL,
                subdominio  TEXT NOT NULL,
                ferramentas TEXT DEFAULT '[]',
                ultimo_scan TEXT DEFAULT (datetime('now', 'localtime')),
                UNIQUE(alvo_raiz, subdominio)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metricas_execucao (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ferramenta  TEXT NOT NULL,
                alvo        TEXT NOT NULL,
                exit_code   INTEGER,
                duracao_ms  INTEGER,
                sucesso     INTEGER DEFAULT 1,
                timestamp   TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_metricas ON metricas_execucao(ferramenta, alvo)"
        )


_init()


def salvar(alvo: str, ferramenta: str, resultado: str, parametros: dict = None) -> None:
    with _conn() as conn:
        conn.execute(
            "INSERT INTO resultados (alvo, ferramenta, parametros, resultado) VALUES (?,?,?,?)",
            (alvo.lower(), ferramenta, json.dumps(parametros) if parametros else None, resultado),
        )


def historico(alvo: str, ferramenta: str = None, limite: int = 10) -> list[dict]:
    with _conn() as conn:
        if ferramenta:
            rows = conn.execute(
                "SELECT * FROM resultados WHERE alvo=? AND ferramenta=? ORDER BY timestamp DESC LIMIT ?",
                (alvo.lower(), ferramenta, limite),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM resultados WHERE alvo=? ORDER BY timestamp DESC LIMIT ?",
                (alvo.lower(), limite),
            ).fetchall()
        return [dict(r) for r in rows]


def alvos() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute("""
            SELECT alvo,
                   COUNT(*)                      AS total,
                   MIN(timestamp)                AS primeiro,
                   MAX(timestamp)                AS ultimo,
                   GROUP_CONCAT(DISTINCT ferramenta) AS ferramentas
            FROM resultados
            GROUP BY alvo
            ORDER BY ultimo DESC
        """).fetchall()
        return [dict(r) for r in rows]


def resultado_recente(alvo: str, ferramenta: str, horas: int = 24) -> dict | None:
    """Retorna resultado mais recente dentro do TTL, ou None se não houver."""
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM resultados WHERE alvo=? AND ferramenta=? "
            "AND datetime(timestamp) >= datetime('now', 'localtime', ?) "
            "ORDER BY timestamp DESC LIMIT 1",
            (alvo.lower(), ferramenta, f"-{horas} hours"),
        ).fetchone()
        return dict(row) if row else None


def ultimos_dois(alvo: str, ferramenta: str) -> tuple:
    registros = historico(alvo, ferramenta, limite=2)
    return (
        registros[0] if len(registros) > 0 else None,
        registros[1] if len(registros) > 1 else None,
    )


# ─── Memória de Longo Prazo ───────────────────────────────────────────────────

def registrar_vuln(
    alvo_raiz: str,
    subdominio: str,
    tipo: str,
    identificador: str,
    severidade: str = "unknown",
    detalhes: dict = None,
) -> bool:
    """Registra vulnerabilidade. Retorna True se nova, False se já conhecida."""
    with _conn() as conn:
        row = conn.execute(
            "SELECT id FROM vulnerabilidades WHERE alvo_raiz=? AND subdominio=? AND identificador=?",
            (alvo_raiz.lower(), subdominio.lower(), identificador),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE vulnerabilidades SET ultima_vez=datetime('now','localtime'), severidade=? WHERE id=?",
                (severidade, row["id"]),
            )
            return False
        conn.execute(
            "INSERT INTO vulnerabilidades "
            "(alvo_raiz, subdominio, tipo, identificador, severidade, detalhes) "
            "VALUES (?,?,?,?,?,?)",
            (
                alvo_raiz.lower(), subdominio.lower(), tipo, identificador,
                severidade, json.dumps(detalhes) if detalhes else None,
            ),
        )
        return True


def vulns_conhecidas(alvo_raiz: str, subdominio: str = None) -> list[dict]:
    """Retorna vulnerabilidades já registradas para evitar rescan redundante."""
    with _conn() as conn:
        if subdominio:
            rows = conn.execute(
                "SELECT * FROM vulnerabilidades WHERE alvo_raiz=? AND subdominio=? "
                "AND status != 'falso-positivo' ORDER BY severidade DESC",
                (alvo_raiz.lower(), subdominio.lower()),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM vulnerabilidades WHERE alvo_raiz=? "
                "AND status != 'falso-positivo' ORDER BY subdominio, severidade DESC",
                (alvo_raiz.lower(),),
            ).fetchall()
        return [dict(r) for r in rows]


def subdominio_precisa_scan(
    alvo_raiz: str,
    subdominio: str,
    ferramenta: str,
    horas: int = 168,
) -> bool:
    """True se o subdomínio ainda não foi scaneado com essa ferramenta na janela de horas."""
    with _conn() as conn:
        row = conn.execute(
            "SELECT ferramentas, ultimo_scan FROM subdominios_memoria "
            "WHERE alvo_raiz=? AND subdominio=? "
            "AND datetime(ultimo_scan) >= datetime('now','localtime',?)",
            (alvo_raiz.lower(), subdominio.lower(), f"-{horas} hours"),
        ).fetchone()
        if not row:
            return True
        ferramentas_feitas = json.loads(row["ferramentas"] or "[]")
        return ferramenta not in ferramentas_feitas


def marcar_subdominio_scaneado(alvo_raiz: str, subdominio: str, ferramenta: str) -> None:
    """Acumula ferramenta na lista do subdomínio, atualizando o timestamp."""
    with _conn() as conn:
        row = conn.execute(
            "SELECT ferramentas FROM subdominios_memoria WHERE alvo_raiz=? AND subdominio=?",
            (alvo_raiz.lower(), subdominio.lower()),
        ).fetchone()
        ferramentas = json.loads(row["ferramentas"]) if row else []
        if ferramenta not in ferramentas:
            ferramentas.append(ferramenta)
        conn.execute(
            "INSERT INTO subdominios_memoria (alvo_raiz, subdominio, ferramentas) VALUES (?,?,?) "
            "ON CONFLICT(alvo_raiz, subdominio) DO UPDATE SET "
            "ferramentas=excluded.ferramentas, ultimo_scan=datetime('now','localtime')",
            (alvo_raiz.lower(), subdominio.lower(), json.dumps(ferramentas)),
        )


# ─── Métricas de Execução ─────────────────────────────────────────────────────

def salvar_metrica(ferramenta: str, alvo: str, exit_code: int, duracao_ms: int, sucesso: bool) -> None:
    """Registra métricas de cada execução para aprendizado sobre estabilidade das ferramentas."""
    with _conn() as conn:
        conn.execute(
            "INSERT INTO metricas_execucao (ferramenta, alvo, exit_code, duracao_ms, sucesso) "
            "VALUES (?,?,?,?,?)",
            (ferramenta, alvo.lower(), exit_code, duracao_ms, 1 if sucesso else 0),
        )


def estatisticas_ferramenta(ferramenta: str, alvo: str = None) -> dict:
    """Retorna taxa de sucesso e duração média de uma ferramenta (global ou por alvo)."""
    with _conn() as conn:
        if alvo:
            row = conn.execute(
                "SELECT COUNT(*) AS total, AVG(duracao_ms) AS avg_ms, SUM(sucesso) AS sucessos "
                "FROM metricas_execucao WHERE ferramenta=? AND alvo=?",
                (ferramenta, alvo.lower()),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) AS total, AVG(duracao_ms) AS avg_ms, SUM(sucesso) AS sucessos "
                "FROM metricas_execucao WHERE ferramenta=?",
                (ferramenta,),
            ).fetchone()
    if not row or not row["total"]:
        return {}
    return {
        "total_execucoes": row["total"],
        "duracao_media_ms": int(row["avg_ms"] or 0),
        "taxa_sucesso_pct": round((row["sucessos"] or 0) / row["total"] * 100, 1),
    }


def resumo_memoria(alvo_raiz: str) -> dict:
    """Resumo da memória acumulada sobre o alvo para injetar no contexto do LLM."""
    with _conn() as conn:
        sev_rows = conn.execute(
            "SELECT severidade, COUNT(*) AS n FROM vulnerabilidades "
            "WHERE alvo_raiz=? AND status != 'falso-positivo' GROUP BY severidade",
            (alvo_raiz.lower(),),
        ).fetchall()
        sub_count = conn.execute(
            "SELECT COUNT(*) AS n FROM subdominios_memoria WHERE alvo_raiz=?",
            (alvo_raiz.lower(),),
        ).fetchone()
    return {
        "subdomains_scanned": sub_count["n"] if sub_count else 0,
        "vulns_by_severity": {r["severidade"]: r["n"] for r in sev_rows},
    }
