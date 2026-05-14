"""add manifest FK to DigestAlias

Revision ID: f9f19f6f74dd
Revises: f6e3ad07cffd
Create Date: 2026-05-14 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = "f9f19f6f74dd"
down_revision = "f6e3ad07cffd"

import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector


def upgrade(op, tables, tester):
    bind = op.get_bind()
    inspector = Inspector.from_engine(bind)
    existing_columns = [c["name"] for c in inspector.get_columns("digestalias")]

    if "manifest_id" not in existing_columns:
        op.add_column(
            "digestalias",
            sa.Column("manifest_id", sa.Integer(), nullable=True),
        )
        op.create_foreign_key(
            op.f("fk_digestalias_manifest_id_manifest"),
            "digestalias",
            "manifest",
            ["manifest_id"],
            ["id"],
        )
        op.create_index(
            "digestalias_manifest_id",
            "digestalias",
            ["manifest_id"],
            unique=False,
        )

    tester.populate_column(
        "digestalias",
        "manifest_id",
        tester.TestDataType.Foreign("manifest"),
    )


def downgrade(op, tables, tester):
    op.drop_constraint(
        op.f("fk_digestalias_manifest_id_manifest"),
        "digestalias",
        type_="foreignkey",
    )
    op.drop_index("digestalias_manifest_id", table_name="digestalias")
    op.drop_column("digestalias", "manifest_id")
