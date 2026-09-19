from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

import audit_models  # noqa: F401
import content_impact_models  # noqa: F401
import dguv_catalog_models  # noqa: F401
import identity_models  # noqa: F401
import industry_models  # noqa: F401
import ingestion_models  # noqa: F401
import integration_models  # noqa: F401
import learning_content_models  # noqa: F401
import legal_graph_models  # noqa: F401
import models  # noqa: F401
import occupational_health_models  # noqa: F401
import privacy_models  # noqa: F401
import realtime_models  # noqa: F401
import regulatory_models  # noqa: F401
import session_models  # noqa: F401
from database import DATABASE_URL, Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(
        DATABASE_URL,
        poolclass=pool.NullPool,
        pool_pre_ping=True,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
