"""単一パスワードの認証。

環境変数 ``RISKTRACE_PASSWORD`` を読む。未設定なら起動時に生成して
標準出力へ出し、そのプロセス内だけで有効にする。

セッションに印を置くだけの簡易方式。利用者は1人を想定する。
"""

from __future__ import annotations

import hmac
import os
import secrets

from flask import session

SESSION_KEY = "authenticated"
PASSWORD_ENV = "RISKTRACE_PASSWORD"
MIN_LENGTH = 8

#: 起動時に決まるパスワード。環境変数が無ければ生成する。
_PASSWORD: str | None = None


def password() -> str:
    """使用中のパスワード。初回だけ生成する。"""
    global _PASSWORD
    if _PASSWORD is None:
        configured = (os.environ.get(PASSWORD_ENV) or "").strip()
        if configured:
            _PASSWORD = configured
        else:
            _PASSWORD = secrets.token_urlsafe(12)
            print(f"[RiskTrace] {PASSWORD_ENV} 未設定のため一時パスワードを使います: {_PASSWORD}")
    return _PASSWORD


def reset(value: str | None = None) -> None:
    """テスト用。値を差し替える。"""
    global _PASSWORD
    _PASSWORD = value


def is_configured() -> bool:
    """環境変数で与えられているか。"""
    return bool((os.environ.get(PASSWORD_ENV) or "").strip())

def required() -> bool:
    """環境変数でパスワードが与えられているときだけ認証を要求する。"""
    return is_configured()

def check(candidate: str | None) -> bool:
    if not candidate:
        return False
    return hmac.compare_digest(password(), candidate)


def remember() -> None:
    session[SESSION_KEY] = True


def forget() -> None:
    session.pop(SESSION_KEY, None)


def is_authenticated() -> bool:
    return session.get(SESSION_KEY) is True