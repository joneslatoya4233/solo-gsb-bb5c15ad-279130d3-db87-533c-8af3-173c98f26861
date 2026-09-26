"""应用配置。"""
import os
from pathlib import Path

# 数据库文件路径（容器内默认 /data/handoff.db，可用环境变量覆盖）
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DB_PATH = Path(os.getenv("DB_PATH", str(DATA_DIR / "handoff.db")))

# 服务监听
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

# 审计检索翻页游标的 HMAC 签名密钥。
# 未设置（或显式置空）时使用内置开发默认值以保证「一键启动」开箱可用；
# docker-compose.yml 同样给出可覆盖的开发默认值。生产部署必须通过环境变量
# 覆盖为高强度随机密钥：游标为不透明令牌，签名密钥一旦更换，此前签发的
# next_cursor 立即失效（返回 400 invalid_cursor），需重新发起首次查询。
AUDIT_CURSOR_SECRET_DEFAULT = "dev-only-insecure-audit-cursor-secret-change-me"
AUDIT_CURSOR_SECRET = (
    os.getenv("AUDIT_CURSOR_SECRET") or AUDIT_CURSOR_SECRET_DEFAULT
)
