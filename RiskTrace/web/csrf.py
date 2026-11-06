"""セッション単位の CSRF トークン。

トークンはセッションに1つだけ持つ。フォームは hidden、非同期は
``X-CSRF-Token`` ヘッダで送る。比較は定数時間で行う。
"""

from __future__ import annotations

import hmac
import secrets

from flask import session

SESSION_KEY = "csrf_token"
FIELD = "csrf_token"
HEADER = "X-CSRF-Token"


def token() -> str:
    """セッションのトークンを返す。無ければ作る。"""
    value = session.get(SESSION_KEY)
    if not value:
        value = secrets.token_urlsafe(32)
        session[SESSION_KEY] = value
    return value


def submitted(form, headers) -> str | None:
    """送信されたトークンを取り出す。フォームを優先する。"""
    value = form.get(FIELD) if form is not None else None
    if value:
        return value
    if headers is not None:
        return headers.get(HEADER)
    return None


def check(value: str | None) -> bool:
    expected = session.get(SESSION_KEY)
    if not expected or not value:
        return False
    return hmac.compare_digest(expected, value)