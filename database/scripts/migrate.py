#!/usr/bin/env python3
"""
CobaltGraph Database Migration Runner
Executes PostgreSQL migration scripts in order
"""

import sys
import os
from pathlib import Path
import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import configparser
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
MIGRATIONS_DIR = PROJECT_ROOT / "database" / "migrations"
CONFIG_FILE = PROJECT_ROOT / "config" / "database.conf"


def load_config():
    """Load database configuration from config file"""
    if not CONFIG_FILE.exists():
        logger.error(f"Configuration file not found: {CONFIG_FILE}")
        logger.info("Creating default config file...")

        # Create config directory
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

        # Create default config
        config = configparser.ConfigParser()
        config['database'] = {
            'host': 'localhost',
            'port': '5432',
            'database': 'cobaltgraph',
            'user': 'cobaltgraph_user',
            'password': 'CHANGE_ME_PLEASE'
        }

        with open(CONFIG_FILE, 'w') as f:
            config.write(f)

        logger.info(f"Created default config at: {CONFIG_FILE}")
        logger.warning("⚠️  Please edit config/database.conf and set your database credentials!")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    return {
        'host': config.get('database', 'host'),
        'port': config.getint('database', 'port'),
        'database': config.get('database', 'database'),
        'user': config.get('database', 'user'),
        'password': config.get('database', 'password')
    }


def create_database_if_not_exists(config):
    """Create database if it doesn't exist"""
    try:
        # Connect to postgres database (default)
        conn = psycopg2.connect(
            host=config['host'],
            port=config['port'],
            database='postgres',
            user=config['user'],
            password=config['password']
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()

        # Check if database exists
        cursor.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s",
            (config['database'],)
        )
        exists = cursor.fetchone()

        if not exists:
            logger.info(f"Creating database: {config['database']}")
            cursor.execute(
                sql.SQL("CREATE DATABASE {}").format(
                    sql.Identifier(config['database'])
                )
            )
            logger.info(f"✅ Database created: {config['database']}")
        else:
            logger.info(f"Database already exists: {config['database']}")

        cursor.close()
        conn.close()

    except psycopg2.Error as e:
        logger.error(f"Failed to create database: {e}")
        raise


def get_applied_migrations(cursor):
    """Get list of already applied migrations"""
    try:
        cursor.execute("""
            SELECT migration_file, applied_at
            FROM schema_migrations
            ORDER BY applied_at
        """)
        return {row[0]: row[1] for row in cursor.fetchall()}
    except psycopg2.Error:
        # Table doesn't exist yet
        return {}


def create_migrations_table(cursor):
    """Create schema_migrations tracking table"""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id SERIAL PRIMARY KEY,
            migration_file VARCHAR(255) NOT NULL UNIQUE,
            applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
    """)
    logger.info("Created schema_migrations tracking table")


def run_migration(cursor, migration_file):
    """Execute a migration file"""
    migration_path = MIGRATIONS_DIR / migration_file

    if not migration_path.exists():
        raise FileNotFoundError(f"Migration file not found: {migration_path}")

    logger.info(f"Running migration: {migration_file}")

    # Read migration SQL
    with open(migration_path, 'r') as f:
        sql_content = f.read()

    # Execute migration
    cursor.execute(sql_content)

    # Record migration
    cursor.execute(
        "INSERT INTO schema_migrations (migration_file) VALUES (%s)",
        (migration_file,)
    )

    logger.info(f"✅ Migration completed: {migration_file}")


def get_pending_migrations(applied_migrations):
    """Get list of migrations that haven't been applied"""
    all_migrations = sorted([
        f.name for f in MIGRATIONS_DIR.glob("*.sql")
        if f.is_file()
    ])

    pending = [
        m for m in all_migrations
        if m not in applied_migrations
    ]

    return pending


def main():
    """Main migration runner"""
    logger.info("🔄 CobaltGraph Database Migration Tool")
    logger.info("=" * 50)

    # Load configuration
    try:
        config = load_config()
        logger.info(f"Loaded config: {config['user']}@{config['host']}:{config['port']}/{config['database']}")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return 1

    # Create database if needed
    try:
        create_database_if_not_exists(config)
    except Exception as e:
        logger.error(f"Failed to create database: {e}")
        return 1

    # Connect to CobaltGraph database
    try:
        conn = psycopg2.connect(
            host=config['host'],
            port=config['port'],
            database=config['database'],
            user=config['user'],
            password=config['password']
        )
        cursor = conn.cursor()
        logger.info(f"✅ Connected to database: {config['database']}")

    except psycopg2.Error as e:
        logger.error(f"Failed to connect to database: {e}")
        logger.error("Please check your database credentials in config/database.conf")
        return 1

    try:
        # Create migrations tracking table
        create_migrations_table(cursor)
        conn.commit()

        # Get applied migrations
        applied_migrations = get_applied_migrations(cursor)
        logger.info(f"Applied migrations: {len(applied_migrations)}")

        # Get pending migrations
        pending_migrations = get_pending_migrations(applied_migrations)
        logger.info(f"Pending migrations: {len(pending_migrations)}")

        if not pending_migrations:
            logger.info("✅ Database is up to date!")
            return 0

        # Run pending migrations
        for migration in pending_migrations:
            try:
                run_migration(cursor, migration)
                conn.commit()
            except Exception as e:
                logger.error(f"❌ Migration failed: {migration}")
                logger.error(f"Error: {e}")
                conn.rollback()
                return 1

        logger.info("=" * 50)
        logger.info(f"✅ All migrations completed successfully!")
        logger.info(f"Total migrations applied: {len(pending_migrations)}")

    except Exception as e:
        logger.error(f"Migration error: {e}")
        conn.rollback()
        return 1

    finally:
        cursor.close()
        conn.close()

    return 0


if __name__ == '__main__':
    sys.exit(main())
