import os
from pathlib import Path
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(REPO_ROOT / ".env", override=True)

DEFAULT_DB_PATH = os.path.abspath(REPO_ROOT / "threatlens.db")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def run_migrations():
    """Ensure user_session_id column exists on all relevant tables."""
    tables = [
        "scans",
        "watchlist",
        "alerts",
        "inbox_messages",
        "graph_nodes",
        "graph_edges",
        "forensic_events",
        "cases",
        "case_items",
        "case_comments",
        "case_audit",
    ]
    try:
        with engine.connect() as conn:
            for t in tables:
                try:
                    result = conn.execute(text(f"PRAGMA table_info({t});"))
                    cols = [row[1] for row in result.fetchall()]
                    if cols and "user_session_id" not in cols:
                        conn.execute(text(f"ALTER TABLE {t} ADD COLUMN user_session_id VARCHAR(64) NULL;"))
                        conn.execute(text(f"UPDATE {t} SET user_session_id = 'migrated_default' WHERE user_session_id IS NULL;"))
                        conn.commit()
                except Exception:
                    pass

            # Ensure graph_nodes unique index includes user_session_id
            try:
                conn.execute(text("DROP INDEX IF EXISTS ix_graph_nodes_tenant_type_val;"))
                conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_graph_nodes_tenant_session_type_val ON graph_nodes (tenant_id, user_session_id, node_type, value);"))
                conn.commit()
            except Exception:
                pass
    except Exception:
        pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
