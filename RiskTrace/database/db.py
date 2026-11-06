import os
import sqlite3
import threading

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DB_DIR, "risktrace.db")

# SQLiteの接続設定
CONNECTION_TIMEOUT = 10.0
BUSY_TIMEOUT_MS = 10000

# WALモードはDB全体に保持されるため、プロセス内では初回だけ設定する
_wal_lock = threading.Lock()
_wal_initialized = False


def get_connection():
    """
    SQLiteデータベースへの接続を取得する。

    - 接続待ち時間を設定する
    - 外部キー制約を有効にする
    - ロック中の待機時間を設定する
    - 初回接続時にWALモードを有効にする
    """
    global _wal_initialized

    os.makedirs(DB_DIR, exist_ok=True)

    conn = sqlite3.connect(
        DB_PATH,
        timeout=CONNECTION_TIMEOUT,
    )
    conn.row_factory = sqlite3.Row

    try:
        # この接続で外部キー制約を有効にする
        conn.execute("PRAGMA foreign_keys = ON")

        # ロック中に待機する時間（ミリ秒）
        conn.execute(
            f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}"
        )

        # WALモードはデータベースファイルに保持される
        # 同一プロセス内での初回設定を排他制御する
        if not _wal_initialized:
            with _wal_lock:
                if not _wal_initialized:
                    cursor = conn.execute(
                        "PRAGMA journal_mode = WAL"
                    )
                    row = cursor.fetchone()

                    if row is None or row[0].lower() != "wal":
                        raise sqlite3.OperationalError(
                            "SQLiteのWALモードを有効にできませんでした"
                        )

                    _wal_initialized = True

        return conn

    except Exception:
        conn.close()
        raise


def close_connection(conn):
    """SQLite接続を閉じる。"""
    if conn is not None:
        conn.close()