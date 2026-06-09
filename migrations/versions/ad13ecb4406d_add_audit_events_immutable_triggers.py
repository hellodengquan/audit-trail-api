"""add_audit_events_immutable_triggers

Revision ID: ad13ecb4406d
Revises: d73d9e05e6c7
Create Date: 2026-06-10 02:23:34.093940

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'ad13ecb4406d'
down_revision: Union[str, None] = 'd73d9e05e6c7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _dialect() -> str:
    bind = op.get_bind()
    if bind is None:
        return "sqlite"
    return bind.dialect.name.lower()


def _sqlite_upgrade():
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_update;")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_delete;")

    op.execute("""
    CREATE TRIGGER trg_audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW
    BEGIN
        SELECT RAISE(ABORT, 'UPDATE on audit_events is forbidden - table is immutable');
    END;
    """)

    op.execute("""
    CREATE TRIGGER trg_audit_events_no_delete
    BEFORE DELETE ON audit_events
    FOR EACH ROW
    BEGIN
        SELECT RAISE(ABORT, 'DELETE on audit_events is forbidden - table is immutable');
    END;
    """)


def _sqlite_downgrade():
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_update;")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_delete;")


def _postgres_upgrade():
    op.execute("""
    CREATE OR REPLACE FUNCTION audit_events_immutable()
    RETURNS trigger AS $$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            RAISE EXCEPTION 'DELETE on audit_events is forbidden - table is immutable';
        ELSIF (TG_OP = 'UPDATE') THEN
            RAISE EXCEPTION 'UPDATE on audit_events is forbidden - table is immutable';
        END IF;
        RETURN NULL;
    END;
    $$ LANGUAGE plpgsql;
    """)

    op.execute("""
    DROP TRIGGER IF EXISTS trg_audit_events_no_update ON audit_events;
    CREATE TRIGGER trg_audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
    """)

    op.execute("""
    DROP TRIGGER IF EXISTS trg_audit_events_no_delete ON audit_events;
    CREATE TRIGGER trg_audit_events_no_delete
    BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
    """)


def _postgres_downgrade():
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_update ON audit_events;")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_delete ON audit_events;")
    op.execute("DROP FUNCTION IF EXISTS audit_events_immutable();")


def _mysql_upgrade():
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_update;")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_delete;")
    op.execute("""
    CREATE TRIGGER trg_audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW
    SIGNAL SQLSTATE '45000'
      SET MESSAGE_TEXT = 'UPDATE on audit_events is forbidden - table is immutable';
    """)
    op.execute("""
    CREATE TRIGGER trg_audit_events_no_delete
    BEFORE DELETE ON audit_events
    FOR EACH ROW
    SIGNAL SQLSTATE '45000'
      SET MESSAGE_TEXT = 'DELETE on audit_events is forbidden - table is immutable';
    """)


def _mysql_downgrade():
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_update;")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_no_delete;")


def upgrade() -> None:
    dialect = _dialect()
    if dialect == "sqlite":
        _sqlite_upgrade()
    elif dialect in ("postgresql", "postgres"):
        _postgres_upgrade()
    elif dialect == "mysql":
        _mysql_upgrade()
    else:
        raise NotImplementedError(
            f"Audit immutable triggers not implemented for dialect: {dialect}"
        )


def downgrade() -> None:
    dialect = _dialect()
    if dialect == "sqlite":
        _sqlite_downgrade()
    elif dialect in ("postgresql", "postgres"):
        _postgres_downgrade()
    elif dialect == "mysql":
        _mysql_downgrade()
    else:
        raise NotImplementedError(
            f"Audit immutable triggers downgrade not implemented for dialect: {dialect}"
        )
