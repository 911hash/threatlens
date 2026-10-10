import pytest
from sqlalchemy import text
from app.database import SessionLocal


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_artifacts_after_session():
    yield
    session = SessionLocal()
    try:
        session.execute(
            text(
                """
                DELETE FROM graph_nodes WHERE
                  value LIKE '%.test%' OR
                  display_value LIKE '%.test%' OR
                  value LIKE '%@%.test%' OR
                  display_value LIKE '%@%.test%' OR
                  value = '192.0.2.1' OR
                  display_value = '192.0.2.1' OR
                  value LIKE 'recent-test%' OR
                  value LIKE '%msg%@%' OR
                  display_value LIKE '%msg%@%' OR
                  value LIKE '%example.com%' OR
                  display_value LIKE '%example.com%';
                """
            )
        )
        session.execute(
            text(
                """
                DELETE FROM graph_edges WHERE from_node_id NOT IN (SELECT id FROM graph_nodes)
                   OR to_node_id NOT IN (SELECT id FROM graph_nodes);
                """
            )
        )
        session.execute(
            text(
                """
                DELETE FROM scans WHERE
                  target LIKE '%.test%' OR
                  target LIKE '%@%.test%' OR
                  target = '192.0.2.1' OR
                  target LIKE '%example.com%';
                """
            )
        )
        session.execute(
            text(
                """
                DELETE FROM graph_nodes WHERE id NOT IN (SELECT from_node_id FROM graph_edges)
                   AND id NOT IN (SELECT to_node_id FROM graph_edges);
                """
            )
        )
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()
