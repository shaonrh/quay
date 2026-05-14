"""add canonical_sha256 column to ImageStorage

Revision ID: e23d3ca507ed
Revises: f9f19f6f74dd
Create Date: 2026-05-14 20:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = "e23d3ca507ed"
down_revision = "f9f19f6f74dd"

import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector


def upgrade(op, tables, tester):
    bind = op.get_bind()
    inspector = Inspector.from_engine(bind)
    existing_columns = [c["name"] for c in inspector.get_columns("imagestorage")]

    if "canonical_sha256" not in existing_columns:
        # Step 1: Add nullable column -- no lock, instant on PostgreSQL
        op.add_column(
            "imagestorage",
            sa.Column("canonical_sha256", sa.String(255), nullable=True),
        )

        # Step 2: Create index (non-unique)
        # Note: Alembic doesn't support CREATE INDEX CONCURRENTLY in a transaction.
        # For very large tables, operators may want to create the index manually
        # with CONCURRENTLY before running migration.
        op.create_index(
            "imagestorage_canonical_sha256",
            "imagestorage",
            ["canonical_sha256"],
            unique=False,
        )

    tester.populate_column(
        "imagestorage",
        "canonical_sha256",
        tester.TestDataType.String,
    )


def downgrade(op, tables, tester):
    op.drop_index("imagestorage_canonical_sha256", table_name="imagestorage")
    op.drop_column("imagestorage", "canonical_sha256")
