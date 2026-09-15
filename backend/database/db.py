import time
import threading

class DatabaseConnection:
    """
    DatabaseConnection — Manages connections to MySQL database (with graceful fallback).
    """

    HOST = "localhost"
    PORT = 3306
    DATABASE = "security_logs"
    USER = "root"
    PASSWORD = "Phungvanvo358pvv@#"

    _connection_tested = False
    _is_available = False
    _last_ping_time = 0
    _PING_INTERVAL_SEC = 30
    _lock = threading.Lock()

    @classmethod
    def get_connection(cls):
        """Attempts to open and return a MySQL connection (or None if driver/server unavailable)."""
        try:
            try:
                import mysql.connector
                return mysql.connector.connect(
                    host=cls.HOST,
                    port=cls.PORT,
                    database=cls.DATABASE,
                    user=cls.USER,
                    password=cls.PASSWORD,
                    connect_timeout=3
                )
            except ImportError:
                import pymysql
                return pymysql.connect(
                    host=cls.HOST,
                    port=cls.PORT,
                    database=cls.DATABASE,
                    user=cls.USER,
                    password=cls.PASSWORD,
                    connect_timeout=3,
                    autocommit=True
                )
        except Exception:
            return None

    @classmethod
    def test_connection(cls) -> bool:
        with cls._lock:
            if cls._connection_tested:
                return cls._is_available

            cls._connection_tested = True
            conn = cls.get_connection()
            if conn:
                cls._is_available = True
                print("   [Database] MySQL connection successful!")
                print(f"   Host: {cls.HOST}:{cls.PORT}, Database: {cls.DATABASE}")
                try:
                    conn.close()
                except Exception:
                    pass
                cls.ensure_schema()
                return True
            else:
                cls._is_available = False
                print("   [Database] MySQL unavailable -> Using text file as data source")
                print("   To enable MySQL: install mysql-connector-python or pymysql and start MySQL Server")
                return False

    @classmethod
    def ensure_schema(cls):
        conn = cls.get_connection()
        if not conn:
            return

        columns_to_add = [
            ("attack_type", "ALTER TABLE logs ADD COLUMN attack_type VARCHAR(50) NOT NULL DEFAULT 'NORMAL' AFTER status"),
            ("description", "ALTER TABLE logs ADD COLUMN description TEXT AFTER attack_type"),
            ("score", "ALTER TABLE logs ADD COLUMN score INT DEFAULT 0 AFTER attack_type")
        ]

        try:
            cursor = conn.cursor()
            for col_name, alter_sql in columns_to_add:
                check_sql = ("SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS "
                             "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'logs' AND COLUMN_NAME = %s")
                cursor.execute(check_sql, (cls.DATABASE, col_name))
                res = cursor.fetchone()
                if res and res[0] == 0:
                    cursor.execute(alter_sql)
                    conn.commit()
                    print(f"   [Schema] Added missing column: {col_name}")
                else:
                    print(f"   [Schema] Column OK: {col_name}")
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"   [Schema] Migration error (non-fatal): {e}")

    @classmethod
    def is_available(cls) -> bool:
        with cls._lock:
            if not cls._connection_tested:
                cls.test_connection()

            if not cls._is_available:
                return False

            now = time.time()
            if now - cls._last_ping_time < cls._PING_INTERVAL_SEC:
                return cls._is_available

            cls._last_ping_time = now
            conn = cls.get_connection()
            if conn:
                cls._is_available = True
                try:
                    conn.close()
                except Exception:
                    pass
                return True
            else:
                cls._is_available = False
                print("[Database] Connection lost")
                return False
