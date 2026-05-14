"""backfill canonical_sha256 and set NOT NULL

Revision ID: 829dfc0d0194
Revises: e23d3ca507ed
Create Date: 2026-05-14 20:01:00.000000

"""

# revision identifiers, used by Alembic.
revision = "829dfc0d0194"
down_revision = "e23d3ca507ed"

import logging

import sqlalchemy as sa

logger = logging.getLogger(__name__)

BATCH_SIZE = 50000


def upgrade(op, tables, tester):
    bind = op.get_bind()

    # Check if backfill is needed (idempotent)
    result = bind.execute(
        sa.text("SELECT COUNT(*) FROM imagestorage WHERE canonical_sha256 IS NULL")
    )
    null_count = result.scalar()
    if null_count == 0:
        logger.info("canonical_sha256 already fully backfilled, skipping")
    else:
        logger.info("Backfilling %d rows in batches of %d", null_count, BATCH_SIZE)

        total_updated = 0
        while True:
            result = bind.execute(
                sa.text(
                    "UPDATE imagestorage SET canonical_sha256 = content_checksum "
                    "WHERE canonical_sha256 IS NULL AND id IN "
                    "(SELECT id FROM imagestorage WHERE canonical_sha256 IS NULL LIMIT :batch)"
                ),
                {"batch": BATCH_SIZE},
            )

            rows_updated = result.rowcount
            total_updated += rows_updated
            logger.info("Backfilled %d/%d rows", total_updated, null_count)

            if rows_updated == 0:
                break

    # Set NOT NULL after backfill
    # WARNING: This acquires ACCESS EXCLUSIVE lock on imagestorage.
    # PostgreSQL must scan all rows to verify no NULLs.
    # For 50M rows with warm buffer cache, this takes ~1-5 seconds.
    # During this window, all blob operations block.
    op.alter_column(
        "imagestorage",
        "canonical_sha256",
        nullable=False,
    )


def downgrade(op, tables, tester):
    op.alter_column(
        "imagestorage",
        "canonical_sha256",
        nullable=True,
    )
