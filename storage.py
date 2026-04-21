import json
import os
import sqlite3

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
