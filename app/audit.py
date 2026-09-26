"""交接事件审计检索：过滤条件摘要与防篡改翻页游标。

游标设计
--------
GET /audit/events 是跨链检索，结果按 (created_at, 事件数据库 id) 全局升序。
- 首次查询（不带 cursor）时，服务端在**同一个读事务**内取当时最大的事件 id
  作为快照上界 max_id：后续翻页始终只检索 id <= max_id 的事件集合。这样
  翻页期间新追加的移交事件不会插入旧页（重复）也不会改变末页边界（漏项）。
- next_cursor 为不透明令牌，载荷（v1 JSON）携带：
  - filters：本次过滤条件的规范摘要（chain_id / holder / role /
    created_from / created_to）；翻页请求必须与本次查询参数逐字段一致，
    否则返回 400 cursor_filter_mismatch，且**绝不回退为一次新查询**；
  - max_id：首次查询固定的快照上界；
  - last_created_at / last_event_id：上一页末条事件的排序键，下一页用
    (created_at, id) 严格大于该键的 keyset 方式继续。
- 载荷以 `audit-cursor:v1:` 为域前缀，用 AUDIT_CURSOR_SECRET 做
  HMAC-SHA256 签名；签名与载荷分别做 URL 安全 base64 后以 "." 拼接。
  篡改载荷、伪造签名、结构非法或非本服务签发的游标一律 400 invalid_cursor。

时间过滤
--------
created_from / created_to 接受 ISO-8601（建议显式时区；无时区按 UTC 解释），
统一归一化为 UTC 秒精度（与事件 created_at 一致，isoformat(timespec="seconds")
的字符串字典序与时间先后一致），比较语义为闭区间 created_from <= created_at
<= created_to。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from . import config

_CURSOR_VERSION = "v1"
_CURSOR_DOMAIN = "audit-cursor:v1:"
_ROLES = ("giver", "receiver", "either")


class AuditError(Exception):
    """审计检索的客户端错误（统一映射为 HTTP 400）。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _normalize_optional_str(value: Optional[str], field: str) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if len(value) > 200:
        raise AuditError(f"invalid_{field}", f"{field} 长度不能超过 200")
    return value


def normalize_timestamp(value: Optional[str], field: str) -> Optional[str]:
    """把 ISO-8601 输入归一化为 UTC 秒精度字符串；空值透传 None。"""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AuditError(
            f"invalid_{field}",
            f"{field} 必须是 ISO-8601 时间（如 2026-09-01T00:00:00+00:00）: {exc}",
        ) from exc
    if dt.tzinfo is None:
        # 不带时区一律按 UTC 解释，避免依赖服务进程本地时区。
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class AuditFilter:
    """归一化后的审计检索过滤条件（游标内摘要与查询参数共用同一表示）。"""

    chain_id: Optional[str] = None
    holder: Optional[str] = None
    role: str = "either"
    created_from: Optional[str] = None
    created_to: Optional[str] = None

    def summary(self) -> dict[str, Any]:
        """过滤条件的规范摘要（嵌入游标并在翻页时逐字段比对）。"""
        return {
            "chain_id": self.chain_id,
            "holder": self.holder,
            "role": self.role,
            "created_from": self.created_from,
            "created_to": self.created_to,
        }


def build_filter(
    chain_id: Optional[str],
    holder: Optional[str],
    role: str = "either",
    created_from: Optional[str] = None,
    created_to: Optional[str] = None,
) -> AuditFilter:
    """校验并归一化查询参数。

    role 仅在给定 holder 时有意义：未提供 holder 却指定 role（giver /
    receiver）无法按角色过滤，返回 400 role_requires_holder。创世事件没有
    giver/receiver 字段，仅在 role=either 时按 chains.first_holder 匹配首位
    持有人（SQL 层实现）。
    """
    chain_id = _normalize_optional_str(chain_id, "chain_id")
    holder = _normalize_optional_str(holder, "holder")
    if role not in _ROLES:
        # FastAPI 的 Literal 校验通常已在 422 拦截；这里兜底。
        raise AuditError("invalid_role", f"role 必须是 {_ROLES} 之一")
    if holder is None and role != "either":
        raise AuditError(
            "role_requires_holder",
            "仅在提供 holder 时才能按 role=giver/receiver 过滤；"
            "不指定持有人时 role 必须为 either（或省略）",
        )

    created_from = normalize_timestamp(created_from, "created_from")
    created_to = normalize_timestamp(created_to, "created_to")
    if (
        created_from is not None
        and created_to is not None
        and created_from > created_to
    ):
        raise AuditError(
            "invalid_time_range",
            f"created_from（{created_from}）不能晚于 created_to（{created_to}）",
        )

    return AuditFilter(
        chain_id=chain_id,
        holder=holder,
        role=role if holder is not None else "either",
        created_from=created_from,
        created_to=created_to,
    )


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sign(payload_b64: str) -> str:
    mac = hmac.new(
        config.AUDIT_CURSOR_SECRET.encode("utf-8"),
        (_CURSOR_DOMAIN + payload_b64).encode("utf-8"),
        hashlib.sha256,
    )
    return _b64url_encode(mac.digest())


def encode_cursor(
    flt: AuditFilter,
    max_id: int,
    last_created_at: str,
    last_event_id: int,
) -> str:
    """生成携带过滤摘要、快照上界与末条排序键的签名不透明游标。"""
    payload = {
        "v": _CURSOR_VERSION,
        "filters": flt.summary(),
        "max_id": max_id,
        "last_created_at": last_created_at,
        "last_event_id": last_event_id,
    }
    payload_b64 = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    return f"{payload_b64}.{_sign(payload_b64)}"


def decode_cursor(cursor: str, flt: AuditFilter) -> tuple[int, str, int]:
    """校验并解码翻页游标，返回 (max_id, last_created_at, last_event_id)。

    任何篡改/伪造/结构问题都抛 400 invalid_cursor；游标内过滤摘要与本次
    查询参数不一致抛 400 cursor_filter_mismatch。调用方必须在首次查询之外
    的每次翻页中调用本函数，且不得因此回退为新的首次查询。
    """
    if not isinstance(cursor, str) or "." not in cursor:
        raise AuditError("invalid_cursor", "游标格式非法")
    payload_b64, _, sig_b64 = cursor.rpartition(".")
    if not payload_b64 or not sig_b64:
        raise AuditError("invalid_cursor", "游标格式非法")

    expected_sig = _sign(payload_b64)
    # 等长比较 + hmac.compare_digest，杜绝时序侧信道。
    if len(sig_b64) != len(expected_sig) or not hmac.compare_digest(
        sig_b64, expected_sig
    ):
        raise AuditError("invalid_cursor", "游标签名校验失败（已篡改或非本服务签发）")

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuditError("invalid_cursor", "游标载荷无法解析") from exc

    if not isinstance(payload, dict) or payload.get("v") != _CURSOR_VERSION:
        raise AuditError("invalid_cursor", "游标版本不支持")

    stored_filters = payload.get("filters")
    if not isinstance(stored_filters, dict):
        raise AuditError("invalid_cursor", "游标缺少过滤条件摘要")
    # 逐字段比对：摘要由服务端按同一归一化规则生成，JSON 原始键序无关。
    if stored_filters != flt.summary():
        raise AuditError(
            "cursor_filter_mismatch",
            "游标与本次过滤条件不符：翻页必须沿用首次查询的 chain_id / holder / "
            "role / created_from / created_to（limit 可在 1～100 间逐页调整）；"
            "过滤条件变化时请重新发起首次查询",
        )

    try:
        max_id = payload["max_id"]
        last_created_at = payload["last_created_at"]
        last_event_id = payload["last_event_id"]
    except KeyError as exc:
        raise AuditError("invalid_cursor", "游标缺少分页状态字段") from exc
    if (
        not isinstance(max_id, int)
        or isinstance(max_id, bool)
        or max_id < 0
        or not isinstance(last_event_id, int)
        or isinstance(last_event_id, bool)
        or last_event_id < 0
        or not isinstance(last_created_at, str)
        or not last_created_at
    ):
        raise AuditError("invalid_cursor", "游标分页状态字段非法")

    return max_id, last_created_at, last_event_id
