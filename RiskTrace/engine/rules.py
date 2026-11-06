"""YAML ルールの読み込みとロード時バリデーション。

責務は「読む・検証する・構造化する」だけ。述語の評価は
``engine/rule_runner.py`` が行う。

設計方針:
    - eval / exec を使わない。述語はデータ構造に落とす
    - 不正なルールは実行時に無視せず、ロード時に落とす
    - 未知キー・未知 op・ID 重複はすべてエラー
    - confidence は必須。省略を許さない
    - regex はロード時にコンパイルし、危険な形を弾く
    - rules/ が空でも空の RuleSet を返し、起動を妨げない
    - ``requires: []`` は「条件なし」として許容する（collectors は空不可）
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping

import yaml

SEVERITIES: tuple[str, ...] = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
CONFIDENCES: tuple[str, ...] = ("low", "medium", "high")
REQUIREMENTS: tuple[str, ...] = ("consent", "proof")

RULE_REQUIRED_KEYS = frozenset(
    {
        "id",
        "title",
        "severity",
        "confidence",
        "requires",
        "collectors",
        "when",
        "message",
        "why",
        "fix",
        "verify",
    }
)
RULE_OPTIONAL_KEYS = frozenset({"evidence", "tags"})

PREDICATE_KINDS = frozenset({"all", "any", "not", "obs"})
OBS_KEYS = frozenset({"collector", "path", "key", "op", "value"})

OPS = frozenset(
    {"eq", "ne", "present", "absent", "empty", "in", "not_in", "contains", "regex", "gt", "lt"}
)
VALUE_REQUIRED_OPS = frozenset({"eq", "ne", "in", "not_in", "contains", "regex", "gt", "lt"})
LIST_VALUE_OPS = frozenset({"in", "not_in"})
NUMERIC_VALUE_OPS = frozenset({"gt", "lt"})

MAX_REGEX_LENGTH = 512

#: 破滅的後戻りを起こしやすい形のヒューリスティック。
#: ``(.*)*`` ``(.+)+`` ``(a+)*`` のような「内側が短い量化子＋外側が量化子」を弾く。
#: ``(?:[a-z0-9-]+\.)+`` のような実用的な形は通す。
RISKY_REGEX = re.compile(r"\((?:\?:)?[^()]{1,3}[+*]\)[+*]")

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class RuleLoadError(Exception):
    """ルールの読み込み・検証に失敗した。``errors`` に全件を保持する。"""

    def __init__(self, errors: list[str]) -> None:
        self.errors = list(errors)
        super().__init__("\n".join(self.errors))


# --- 述語 ---------------------------------------------------------------


@dataclass(frozen=True)
class ObsPredicate:
    """1つの観測値に対する比較。

    ``path`` と ``key`` は ``ref`` に連結済み。ロード後の参照で例外は出ない。
    """

    collector: str
    path: str
    key: str
    op: str
    value: Any = None
    compiled: re.Pattern[str] | None = None

    @property
    def ref(self) -> str:
        return build_ref(self.path, self.key)


@dataclass(frozen=True)
class AllPredicate:
    children: tuple["Predicate", ...]


@dataclass(frozen=True)
class AnyPredicate:
    children: tuple["Predicate", ...]


@dataclass(frozen=True)
class NotPredicate:
    child: "Predicate"


Predicate = ObsPredicate | AllPredicate | AnyPredicate | NotPredicate


def build_ref(path: str | None, key: str | None) -> str:
    """``path`` と ``key`` を1つの参照文字列に連結する。

    どちらも空なら ``ValueError``。片方だけならそのまま返す。
    前後の空白と、端の ``.`` は落とす。
    """
    left = (path or "").strip().strip(".")
    right = (key or "").strip().strip(".")
    if not left and not right:
        raise ValueError("path と key が両方空です")
    if not left:
        return right
    if not right:
        return left
    return f"{left}.{right}"


# --- ルール -------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    confidence: str
    requires: tuple[str, ...]
    collectors: tuple[str, ...]
    when: Predicate
    message: str
    why: str
    fix: str
    verify: str
    evidence: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    source: str = "<memory>"


@dataclass(frozen=True)
class RuleSet:
    rules: tuple[Rule, ...] = ()

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self) -> Iterator[Rule]:
        return iter(self.rules)

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(rule.id for rule in self.rules)

    @property
    def collectors(self) -> frozenset[str]:
        return frozenset(c for rule in self.rules for c in rule.collectors)

    def by_collector(self, collector: str) -> tuple[Rule, ...]:
        return tuple(rule for rule in self.rules if collector in rule.collectors)

    def by_id(self, rule_id: str) -> Rule | None:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None


# --- 検証ヘルパ ---------------------------------------------------------


def _require_mapping(value: Any, where: str, errors: list[str]) -> Mapping | None:
    if not isinstance(value, Mapping):
        errors.append(f"{where}: mapping である必要があります（実際: {type(value).__name__}）")
        return None
    return value


def _require_text(mapping: Mapping, key: str, where: str, errors: list[str]) -> str | None:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{where}: '{key}' は空でない文字列である必要があります")
        return None
    return value.strip()


def _require_str_list(
    mapping: Mapping,
    key: str,
    where: str,
    errors: list[str],
    *,
    allow_empty: bool = False,
) -> tuple[str, ...] | None:
    value = mapping.get(key)
    if not isinstance(value, list):
        errors.append(f"{where}: '{key}' はリストである必要があります")
        return None
    if not value and not allow_empty:
        errors.append(f"{where}: '{key}' は空でないリストである必要があります")
        return None
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{where}: '{key}[{index}]' は空でない文字列である必要があります")
            continue
        items.append(item.strip())
    return tuple(items)


def _optional_str_list(mapping: Mapping, key: str, where: str, errors: list[str]) -> tuple[str, ...]:
    if key not in mapping:
        return ()
    value = mapping[key]
    if not isinstance(value, list):
        errors.append(f"{where}: '{key}' はリストである必要があります")
        return ()
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{where}: '{key}[{index}]' は空でない文字列である必要があります")
            continue
        items.append(item.strip())
    return tuple(items)


def _compile_regex(pattern: Any, where: str, errors: list[str]) -> re.Pattern[str] | None:
    if not isinstance(pattern, str) or not pattern:
        errors.append(f"{where}: regex の value は空でない文字列である必要があります")
        return None
    if len(pattern) > MAX_REGEX_LENGTH:
        errors.append(
            f"{where}: regex が長すぎます（{len(pattern)} 文字 > 上限 {MAX_REGEX_LENGTH}）"
        )
        return None
    if RISKY_REGEX.search(pattern):
        errors.append(
            f"{where}: 入れ子の量化子を含む regex は過剰な CPU 消費の恐れがあります: {pattern!r}"
        )
        return None
    try:
        return re.compile(pattern)
    except re.error as exc:
        errors.append(f"{where}: regex をコンパイルできません: {exc}")
        return None


# --- 述語のパース -------------------------------------------------------


def parse_obs(payload: Mapping, where: str, errors: list[str]) -> ObsPredicate | None:
    for key in sorted(set(payload) - OBS_KEYS, key=str):
        errors.append(f"{where}: obs の未知のキー '{key}'")

    collector = _require_text(payload, "collector", where, errors)

    op = payload.get("op")
    if not isinstance(op, str) or not op.strip():
        errors.append(f"{where}: 'op' は必須です")
        op = None
    elif op.strip() not in OPS:
        errors.append(f"{where}: 未知の op '{op.strip()}'（使用可能: {sorted(OPS)}）")
        op = None
    else:
        op = op.strip()

    path = payload.get("path")
    key = payload.get("key")
    ref_ok = True
    if path is not None and not isinstance(path, str):
        errors.append(f"{where}: 'path' は文字列である必要があります")
        ref_ok = False
    if key is not None and not isinstance(key, str):
        errors.append(f"{where}: 'key' は文字列である必要があります")
        ref_ok = False
    if ref_ok:
        try:
            build_ref(path, key)
        except ValueError as exc:
            errors.append(f"{where}: {exc}")
            ref_ok = False

    value = payload.get("value")
    compiled: re.Pattern[str] | None = None

    if op in VALUE_REQUIRED_OPS and "value" not in payload:
        errors.append(f"{where}: op '{op}' には 'value' が必須です")
    elif op in LIST_VALUE_OPS:
        if not isinstance(value, list) or not value:
            errors.append(f"{where}: op '{op}' の 'value' は空でないリストである必要があります")
    elif op in NUMERIC_VALUE_OPS:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors.append(f"{where}: op '{op}' の 'value' は数値である必要があります")
    elif op == "regex":
        compiled = _compile_regex(value, where, errors)

    if collector is None or op is None or not ref_ok:
        return None

    return ObsPredicate(
        collector=collector,
        path=(path or "").strip(),
        key=(key or "").strip(),
        op=op,
        value=value,
        compiled=compiled,
    )


def parse_predicate(payload: Any, where: str, errors: list[str]) -> Predicate | None:
    mapping = _require_mapping(payload, where, errors)
    if mapping is None:
        return None

    for key in sorted(set(mapping) - PREDICATE_KINDS, key=str):
        errors.append(f"{where}: 述語の未知のキー '{key}'")

    present = [kind for kind in PREDICATE_KINDS if kind in mapping]
    if len(present) != 1:
        errors.append(
            f"{where}: 述語は all / any / not / obs のいずれか1つだけを持つ必要があります"
            f"（実際: {present or 'なし'}）"
        )
        return None

    kind = present[0]
    body = mapping[kind]

    if kind == "obs":
        obs_mapping = _require_mapping(body, f"{where}.obs", errors)
        if obs_mapping is None:
            return None
        return parse_obs(obs_mapping, f"{where}.obs", errors)

    if kind == "not":
        child = parse_predicate(body, f"{where}.not", errors)
        return None if child is None else NotPredicate(child=child)

    if not isinstance(body, list) or not body:
        errors.append(f"{where}.{kind}: 空でないリストである必要があります")
        return None

    children: list[Predicate] = []
    for index, item in enumerate(body):
        child = parse_predicate(item, f"{where}.{kind}[{index}]", errors)
        if child is not None:
            children.append(child)

    if not children:
        return None
    return AllPredicate(children=tuple(children)) if kind == "all" else AnyPredicate(children=tuple(children))


# --- ルールのパース -----------------------------------------------------


def parse_rule(payload: Any, source: str, errors: list[str]) -> Rule | None:
    where = source
    mapping = _require_mapping(payload, where, errors)
    if mapping is None:
        return None

    for key in sorted(set(mapping) - RULE_REQUIRED_KEYS - RULE_OPTIONAL_KEYS, key=str):
        errors.append(f"{where}: 未知のキー '{key}'")

    missing = sorted(RULE_REQUIRED_KEYS - set(mapping))
    for key in missing:
        errors.append(f"{where}: 必須キー '{key}' がありません")
    if missing:
        # 欠落があると以降の検証が無意味になるため打ち切る。
        return None

    rule_id = _require_text(mapping, "id", where, errors)
    if rule_id is not None and not _ID_PATTERN.match(rule_id):
        errors.append(f"{where}: 'id' に使用できない文字があります: {rule_id!r}")
        rule_id = None

    title = _require_text(mapping, "title", where, errors)
    message = _require_text(mapping, "message", where, errors)
    why = _require_text(mapping, "why", where, errors)
    fix = _require_text(mapping, "fix", where, errors)
    verify = _require_text(mapping, "verify", where, errors)

    severity = mapping.get("severity")
    if not isinstance(severity, str) or severity.strip().upper() not in SEVERITIES:
        errors.append(f"{where}: 'severity' は {list(SEVERITIES)} のいずれかである必要があります")
        severity = None
    else:
        severity = severity.strip().upper()

    confidence = mapping.get("confidence")
    if not isinstance(confidence, str) or confidence.strip().lower() not in CONFIDENCES:
        errors.append(f"{where}: 'confidence' は {list(CONFIDENCES)} のいずれかである必要があります")
        confidence = None
    else:
        confidence = confidence.strip().lower()

    # requires は「条件なし」を表す空リストを許す。
    requires = _require_str_list(mapping, "requires", where, errors, allow_empty=True)
    if requires is not None:
        unknown_requires = [item for item in requires if item not in REQUIREMENTS]
        if unknown_requires:
            errors.append(
                f"{where}: 'requires' に未知の値 {unknown_requires}（使用可能: {list(REQUIREMENTS)}）"
            )
            requires = None

    collectors = _require_str_list(mapping, "collectors", where, errors)

    when = parse_predicate(mapping["when"], f"{where}.when", errors)

    evidence = _optional_str_list(mapping, "evidence", where, errors)
    tags = _optional_str_list(mapping, "tags", where, errors)

    if None in (rule_id, title, severity, confidence, requires, collectors, when, message, why, fix, verify):
        return None

    return Rule(
        id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        requires=requires,
        collectors=collectors,
        when=when,
        message=message,
        why=why,
        fix=fix,
        verify=verify,
        evidence=evidence,
        tags=tags,
        source=source,
    )


# --- 読み込み -----------------------------------------------------------


def _load_document(text: str, source: str, errors: list[str]) -> list[Rule]:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        errors.append(f"{source}: YAML を解析できません: {exc}")
        return []

    if document is None:
        return []

    if not isinstance(document, list):
        errors.append(f"{source}: ファイル直下はルールのリストである必要があります")
        return []

    rules: list[Rule] = []
    for index, payload in enumerate(document):
        rule = parse_rule(payload, f"{source}[{index}]", errors)
        if rule is not None:
            rules.append(rule)
    return rules


def _build(rules: list[Rule], errors: list[str]) -> RuleSet:
    seen: dict[str, str] = {}
    unique: list[Rule] = []
    for rule in rules:
        if rule.id in seen:
            errors.append(
                f"{rule.source}: ルール ID が重複しています '{rule.id}'"
                f"（初出: {seen[rule.id]}）"
            )
            continue
        seen[rule.id] = rule.source
        unique.append(rule)

    if errors:
        raise RuleLoadError(errors)
    return RuleSet(rules=tuple(unique))


def load_rules_from_text(text: str, source: str = "<memory>") -> RuleSet:
    """YAML 文字列からルールセットを構築する。"""
    errors: list[str] = []
    return _build(_load_document(text, source, errors), errors)


def load_rules_from_dir(directory: str | Path) -> RuleSet:
    """ディレクトリ内の ``*.yaml`` / ``*.yml`` をすべて読み込む。

    ディレクトリが無い、またはファイルが0件でも空の RuleSet を返す。
    """
    path = Path(directory)
    if not path.is_dir():
        return RuleSet()

    files = sorted({*path.glob("*.yaml"), *path.glob("*.yml")})
    errors: list[str] = []
    rules: list[Rule] = []
    for file in files:
        try:
            text = file.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{file.name}: 読み込めません: {exc}")
            continue
        rules.extend(_load_document(text, file.name, errors))

    return _build(rules, errors)