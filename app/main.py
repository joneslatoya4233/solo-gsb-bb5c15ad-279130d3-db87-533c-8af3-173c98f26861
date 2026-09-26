"""FastAPI 入口：多人文件交接留痕（哈希链）服务。"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Literal, Optional

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse

from . import config, database
from .audit import AuditError
from .schemas import (
    AuditEventsOut,
    BatchProofVerifyRequest,
    BatchProofVerifyResult,
    ChainOut,
    ChainSummary,
    CreateChainRequest,
    EventBatchProofOut,
    EventProofOut,
    HandoverRequest,
    HandoverResult,
    HealthOut,
    OfferCancelRequest,
    OfferCancelResult,
    OfferConfirmRequest,
    OfferConfirmResult,
    OfferCreateRequest,
    OfferOut,
    OfferReplaceRequest,
    OfferStatusOut,
    ProofVerifyRequest,
    ProofVerifyResult,
    SealCreateRequest,
    SealOut,
    SealReleaseRequest,
    VerifyResult,
    WitnessDecisionRequest,
    WitnessDecisionResult,
    WitnessStatusOut,
)
from .service import (
    AUDIT_LIMIT_MAX,
    AUDIT_LIMIT_MIN,
    ChainError,
    append_handover,
    cancel_offer,
    confirm_offer,
    create_chain,
    create_offer,
    create_seal,
    get_chain,
    get_event_proof,
    get_events_proof,
    get_latest_seal,
    get_offer,
    get_seal,
    get_witness_status,
    list_chains,
    record_witness_decision,
    release_seal,
    replace_offer,
    search_audit_events,
    verify_batch_proof,
    verify_chain,
    verify_event_proof,
)

logger = logging.getLogger("handoff-chain")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动即完成数据库初始化（建表 / 校验目录）
    database.init_db()
    if config.AUDIT_CURSOR_SECRET == config.AUDIT_CURSOR_SECRET_DEFAULT:
        logger.warning(
            "AUDIT_CURSOR_SECRET 未设置，正在使用内置开发默认密钥；"
            "生产部署必须通过环境变量覆盖（旧游标在换钥后立即失效）。"
        )
    yield


app = FastAPI(
    title="文件交接留痕服务",
    description="基于 SHA-256 哈希链的多人文件交接记录、查询与完整性校验。",
    version="1.7.0",
    lifespan=lifespan,
)


@app.exception_handler(ChainError)
async def chain_error_handler(request: Request, exc: ChainError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.code, "detail": exc.message},
    )


@app.exception_handler(AuditError)
async def audit_error_handler(request: Request, exc: AuditError) -> JSONResponse:
    # 审计检索的全部客户端错误（游标篡改/条件不符/参数非法）统一为 400，
    # 绝不因游标无效而静默回退为一次新查询。
    return JSONResponse(
        status_code=400,
        content={"error": exc.code, "detail": exc.message},
    )


@app.get("/health", response_model=HealthOut, tags=["meta"], summary="健康检查")
def health() -> HealthOut:
    return HealthOut(status="ok")


@app.post(
    "/chains",
    response_model=ChainOut,
    status_code=201,
    tags=["chains"],
    summary="创建交接链",
    description="提交文件 SHA-256 摘要与首位持有人，生成序号 0 的创世记录并返回其哈希。",
)
def api_create_chain(req: CreateChainRequest) -> ChainOut:
    return ChainOut(**create_chain(req.file_hash, req.first_holder))


@app.post(
    "/handovers",
    response_model=HandoverResult,
    status_code=201,
    tags=["chains"],
    summary="执行一次移交（原子追加）",
    description=(
        "必须携带当前链尾哈希 tail_hash、接收方 receiver 与一次性随机数 nonce。"
        "交出方由服务端按当前持有人确定。链尾不匹配或随机数重放返回 409，不产生分叉。"
    ),
)
def api_handover(req: HandoverRequest) -> HandoverResult:
    return HandoverResult(
        **append_handover(req.chain_id, req.tail_hash, req.receiver, req.nonce)
    )


@app.post(
    "/offers",
    response_model=OfferOut,
    status_code=201,
    tags=["offers"],
    summary="发起待接收移交邀约（可选 2～5 名见证人、可选撤销码）",
    description=(
        "以最新链尾 tail_hash 锁定邀约，指定 receiver、有效期（秒）与一次性确认码。"
        "服务端只保存确认码的 SHA-256 摘要，返回 offer_id 供接收方确认。"
        "可选提交 cancellation_code：服务端仅保存绑定 offer_id 做域分隔的 SHA-256 "
        "撤销码摘要，此后可凭码调用 POST /offers/{offer_id}/cancel 撤销或调用 "
        "POST /offers/{offer_id}/replace 原子替换；省略则创建不可撤销/不可替换"
        "的兼容旧行为邀约。"
        "可选提交 2～5 名见证人及通过阈值 witness_threshold：每位见证人获得一个"
        "独立一次性令牌（仅在本响应中明文返回一次，服务端只存其 SHA-256 摘要）。"
    ),
)
def api_create_offer(req: OfferCreateRequest) -> OfferOut:
    witnesses = (
        [{"name": w.name, "token": w.token} for w in req.witnesses]
        if req.witnesses
        else None
    )
    return OfferOut(
        **create_offer(
            req.chain_id,
            req.tail_hash,
            req.receiver,
            req.expires_in_seconds,
            req.confirmation_code,
            witnesses=witnesses,
            witness_threshold=req.witness_threshold,
            cancellation_code=req.cancellation_code,
        )
    )


@app.post(
    "/offers/{offer_id}/confirm",
    response_model=OfferConfirmResult,
    status_code=201,
    tags=["offers"],
    summary="确认邀约（原子追加移交事件）",
    description=(
        "接收方凭 offer_id 与一次性确认码确认。服务端在同一 SQLite 立即事务中校验"
        "邀约未过期、未使用、未撤销且链尾仍匹配；见证模式下还须无见证人拒绝且同意数达到"
        "阈值，然后才追加唯一移交事件并将邀约置为 accepted。过期、重复确认、"
        "见证拒绝、同意数不足、链尾已推进、邀约已撤销或已被替换均返回 409，不写事件。"
    ),
)
def api_confirm_offer(offer_id: str, req: OfferConfirmRequest) -> OfferConfirmResult:
    return OfferConfirmResult(**confirm_offer(offer_id, req.confirmation_code))


@app.post(
    "/offers/{offer_id}/cancel",
    response_model=OfferCancelResult,
    tags=["offers"],
    summary="凭一次性撤销码撤销邀约（不改动哈希链）",
    description=(
        "发起方凭 offer_id 与创建时可选提供的 cancellation_code 撤销邀约。服务端在"
        "同一 SQLite 立即事务中与接收方确认、见证人表态互斥地校验：邀约仍 pending、"
        "链尾未推进、未过期且无见证人拒绝，然后才将邀约置为 cancelled，绝不追加任何"
        "链上事件。撤销码错误返回 403 cancel_code_mismatch；邀约已 accepted、"
        "rejected、expired、terminated、cancelled、replaced，或创建时未提供撤销码"
        "（旧邀约），均返回 409 offer_not_cancellable 且不改写链。详情与见证查询会"
        "返回 cancelled 状态，但绝不返回撤销码摘要。"
    ),
)
def api_cancel_offer(offer_id: str, req: OfferCancelRequest) -> OfferCancelResult:
    return OfferCancelResult(**cancel_offer(offer_id, req.cancellation_code))


@app.post(
    "/offers/{offer_id}/replace",
    response_model=OfferOut,
    status_code=201,
    tags=["offers"],
    summary="凭原撤销码原子替换待处理邀约",
    description=(
        "发起方凭原邀约创建时提供的撤销码提交新邀约参数：新的 receiver、"
        "有效期 expires_in_seconds、一次性确认码 confirmation_code，以及可选的"
        "新撤销码 new_cancellation_code 与可选的全新见证配置（2～5 名见证人 + "
        "阈值）。服务端在同一个 SQLite 立即事务中依次确认原邀约仍 pending、"
        "未过期、锁定链尾未推进且无见证人拒绝、原撤销码摘要匹配，然后才将原"
        "邀约标记为 replaced 并创建锁定同一链尾的新邀约（replaces 指向原邀约）；"
        "任一校验失败整体回滚，绝不产生半替换。替换与确认、撤销、见证人表态"
        "互斥，竞争终态中至多一个成功。原撤销码错误返回 403 cancel_code_mismatch；"
        "非可替换状态（accepted / cancelled / replaced / expired / terminated / "
        "rejected，或原邀约创建时未提供撤销码）返回 409 offer_not_replaceable。"
        "新邀约的确认码/撤销码/见证令牌全部重新生成与旧凭证互不通用；响应与"
        "详情接口只暴露 replaces/replaced_by 关系，不泄露任何凭证摘要。"
    ),
)
def api_replace_offer(offer_id: str, req: OfferReplaceRequest) -> OfferOut:
    witnesses = (
        [{"name": w.name, "token": w.token} for w in req.witnesses]
        if req.witnesses
        else None
    )
    return OfferOut(
        **replace_offer(
            offer_id,
            req.cancellation_code,
            req.receiver,
            req.expires_in_seconds,
            req.confirmation_code,
            new_cancellation_code=req.new_cancellation_code,
            witnesses=witnesses,
            witness_threshold=req.witness_threshold,
        )
    )


@app.post(
    "/offers/{offer_id}/witness-decisions",
    response_model=WitnessDecisionResult,
    status_code=201,
    tags=["offers"],
    summary="见证人凭一次性令牌表态（同意 / 拒绝）",
    description=(
        "见证模式邀约的见证人凭创建时分发的独立一次性令牌表态 approved 或 rejected。"
        "服务端只保存令牌摘要，同一见证人至多表态一次（重复使用令牌返回 409，"
        "令牌错误返回 403）。任一拒绝使邀约终止；邀约过期、被撤销、被替换或链尾"
        "推进后表态返回 409。响应不含令牌摘要。"
    ),
)
def api_witness_decision(
    offer_id: str, req: WitnessDecisionRequest
) -> WitnessDecisionResult:
    return WitnessDecisionResult(
        **record_witness_decision(offer_id, req.token, req.decision)
    )


@app.get(
    "/offers/{offer_id}/witnesses",
    response_model=WitnessStatusOut,
    tags=["offers"],
    summary="查询见证邀约的见证人表态状态",
    description=(
        "返回见证邀约各见证人的表态结果与同意/拒绝/待表态计数、派生邀约状态，"
        "绝不返回令牌及其摘要。无见证邀约返回 404。"
    ),
)
def api_get_witness_status(offer_id: str) -> WitnessStatusOut:
    return WitnessStatusOut(**get_witness_status(offer_id))


@app.get(
    "/offers/{offer_id}",
    response_model=OfferStatusOut,
    tags=["offers"],
    summary="查询单个邀约状态",
    description=(
        "返回邀约状态（pending / accepted / expired / rejected / terminated / "
        "cancelled / replaced，后五者为派生或存储终态）、确认/见证结果与"
        "replaces / replaced_by 替换关系（各自只给 offer_id，可据此串联替换链），"
        "不含确认码、撤销码、令牌及其任何摘要；cancellable 仅表示该邀约创建时"
        "是否提供过撤销码。"
    ),
)
def api_get_offer(offer_id: str) -> OfferStatusOut:
    return OfferStatusOut(**get_offer(offer_id))


@app.get(
    "/chains",
    response_model=list[ChainSummary],
    tags=["chains"],
    summary="列出全部交接链",
)
def api_list_chains() -> list[ChainSummary]:
    return [ChainSummary(**c) for c in list_chains()]


@app.get(
    "/audit/events",
    response_model=AuditEventsOut,
    tags=["audit"],
    summary="交接事件审计检索（跨链、快照一致的签名游标翻页）",
    description=(
        "跨全部交接链检索创世与移交事件，结果按 (created_at, 事件数据库 id) "
        "全局升序返回。支持的过滤条件：\n"
        "- chain_id：限定单条链（可与其他条件组合）；\n"
        "- holder：按参与方标识过滤；配合 role 选择角色；\n"
        "- role=giver/receiver：仅匹配移交事件的交出方/接收方；role=either"
        "（默认）匹配任一参与方，**创世事件仅在 either 时按首位持有人 "
        "first_holder 匹配**（创世事件没有 giver/receiver 字段）；未提供 "
        "holder 时不能指定 giver/receiver（400 role_requires_holder）；\n"
        "- created_from / created_to：按 UTC ISO-8601 闭区间过滤事件 "
        "created_at（建议显式时区，无时区按 UTC 解释，秒精度比较）；\n"
        "- limit：每页条数 1～100（默认 50）。\n\n"
        "**快照与翻页**：首次查询（不带 cursor）在同一读事务内把当时最大事件 "
        "id 固定为快照上界 snapshot_max_id；后续即使有新移交追加，也只有 id "
        "不超过该上界的事件参与本次遍历，故翻页不会重复或漏项。next_cursor 是"
        "携带过滤条件摘要、快照上界与末条排序键的不透明令牌，以服务端 "
        "AUDIT_CURSOR_SECRET 做 HMAC-SHA256 签名；把它原样作为 cursor 参数"
        "传回即可。游标被篡改、签名失效或结构非法返回 400 invalid_cursor；"
        "游标与本次查询的过滤条件（chain_id/holder/role/created_from/"
        "created_to）不一致返回 400 cursor_filter_mismatch——两者都**不会**"
        "回退为一次新查询；limit 允许在 1～100 间逐页调整。无更多项时 "
        "next_cursor 为 null。"
    ),
)
def api_search_audit_events(
    chain_id: Optional[str] = Query(
        default=None,
        description="仅检索该交接链的事件；省略则跨全部链",
    ),
    holder: Optional[str] = Query(
        default=None,
        description="按参与方标识过滤；省略则返回全部事件（不按参与方过滤）",
    ),
    role: Literal["giver", "receiver", "either"] = Query(
        default="either",
        description=(
            "持有人角色：giver（交出方）/ receiver（接收方）/ either（任一，"
            "默认；创世事件仅在此值下按首位持有人匹配）"
        ),
    ),
    created_from: Optional[str] = Query(
        default=None,
        description="创建时间下界（含），UTC ISO-8601，如 2026-09-01T00:00:00+00:00",
    ),
    created_to: Optional[str] = Query(
        default=None,
        description="创建时间上界（含），UTC ISO-8601，如 2026-09-30T23:59:59+00:00",
    ),
    limit: int = Query(
        default=50,
        ge=AUDIT_LIMIT_MIN,
        le=AUDIT_LIMIT_MAX,
        description=f"每页条数（{AUDIT_LIMIT_MIN}～{AUDIT_LIMIT_MAX}，默认 50）",
    ),
    cursor: Optional[str] = Query(
        default=None,
        description="上一页响应中的 next_cursor；首次查询省略",
    ),
) -> AuditEventsOut:
    return AuditEventsOut(
        **search_audit_events(
            chain_id=chain_id,
            holder=holder,
            role=role,
            created_from=created_from,
            created_to=created_to,
            limit=limit,
            cursor=cursor,
        )
    )


@app.get(
    "/chains/{chain_id}",
    response_model=ChainOut,
    tags=["chains"],
    summary="查询链条（含全部事件）",
)
def api_get_chain(chain_id: str) -> ChainOut:
    return ChainOut(**get_chain(chain_id))


@app.get(
    "/chains/{chain_id}/verify",
    response_model=VerifyResult,
    tags=["chains"],
    summary="完整性校验",
    description="逐条重算哈希并校验前序指针，结果给出首个断裂序号 first_broken_seq。",
)
def api_verify_chain(chain_id: str) -> VerifyResult:
    return VerifyResult(**verify_chain(chain_id))


@app.get(
    "/chains/{chain_id}/events/{seq}/proof",
    response_model=EventProofOut,
    tags=["proofs"],
    summary="生成单个交接事件的 Merkle 包含证明（可选择披露）",
    description=(
        "根据该链**当前事件集合**为序号 seq 的事件生成 Merkle 包含证明。叶子为"
        ' SHA256("merkle-leaf:v1:" + 规范 JSON{chain_id,seq,event_hash})，'
        '绑定链、序号与事件哈希；内部节点为 SHA256("merkle-node:v1:" + 左 + 右)'
        "（左右均为定长 64 位十六进制），奇数层末节点与自身复制配对；单事件链"
        "根即叶子。响应返回事件、自叶子向根的左右方向兄弟路径 path、事件数"
        "event_count、同一读事务快照下的当前 tail_hash、merkle_root，以及"
        ' SHA256("merkle-snapshot:v1:" + 规范 JSON'
        "{chain_id,event_count,merkle_root,tail_hash}) 得到的 snapshot_digest。"
        "事件与链尾在同一读事务内取得；链条不存在返回 404，seq 越界返回 "
        "404 event_not_found。"
    ),
)
def api_get_event_proof(chain_id: str, seq: int) -> EventProofOut:
    return EventProofOut(**get_event_proof(chain_id, seq))


@app.get(
    "/chains/{chain_id}/events/proof",
    response_model=EventBatchProofOut,
    tags=["proofs"],
    summary="批量生成多个交接事件的 Merkle multiproof（可选择披露）",
    description=(
        "对去重且升序的 1～20 个序号（查询参数 seq 可重复传入）生成**一份**"
        " Merkle multiproof：事件集合与当前链尾在同一读事务内取得（同一快照），"
        "哈希规则与单事件证明一致（叶子绑定 chain_id/seq/event_hash，内部节点"
        '为 SHA256("merkle-node:v1:"+左+右)，奇数层末节点与自身复制配对）。'
        "响应返回被选事件（按 seq 升序，绝不包含未选择事件）、event_count、"
        "tail_hash、merkle_root、snapshot_digest，以及按 (level, index) 升序"
        "且不重复的最小 proof_nodes（level 0 为叶子层；奇数层自复制位置不产生"
        "证明节点）。去重后超过 20 个序号返回 400 too_many_seqs；链条不存在"
        "返回 404；任一序号越界（负数或不小于当前事件数）返回 404 "
        "event_not_found。"
    ),
)
def api_get_events_proof(
    chain_id: str,
    seq: list[int] = Query(
        ...,
        description=(
            "要证明的事件序号，可重复传入（如 ?seq=0&seq=3&seq=7）；"
            "服务端去重并升序排列，去重后 1～20 个"
        ),
    ),
) -> EventBatchProofOut:
    return EventBatchProofOut(**get_events_proof(chain_id, seq))


@app.post(
    "/proofs/verify",
    response_model=ProofVerifyResult,
    tags=["proofs"],
    summary="离线校验 Merkle 包含证明（不读取数据库）",
    description=(
        "仅依据请求体重算叶子（chain_id/seq/event_hash）、左右兄弟路径与"
        " snapshot_digest：按 event_count → seq → path → merkle_root → "
        "snapshot_digest 的顺序给出首个失败阶段 failed_stage，全部通过 valid "
        "才为 true。请求体与 GET 证明响应同构，可原样回填；event 中除 "
        "seq、event_hash 外的字段被忽略。本接口不读取数据库，可在任何离线"
        "环境复算。"
    ),
)
def api_verify_proof(req: ProofVerifyRequest) -> ProofVerifyResult:
    return ProofVerifyResult(
        **verify_event_proof(
            chain_id=req.chain_id,
            seq=req.event.seq,
            event_hash=req.event.event_hash,
            path=[step.model_dump() for step in req.path],
            event_count=req.event_count,
            tail_hash=req.tail_hash,
            merkle_root=req.merkle_root,
            snapshot_digest_claim=req.snapshot_digest,
        )
    )


@app.post(
    "/proofs/verify-batch",
    response_model=BatchProofVerifyResult,
    tags=["proofs"],
    summary="离线校验批量 Merkle multiproof（不读取数据库）",
    description=(
        "仅依据请求体按节点坐标重建 Merkle 根并重算 snapshot_digest：按 "
        "event_count → events → proof_nodes → merkle_root → snapshot_digest "
        "的顺序给出首个失败阶段 failed_stage，全部通过 valid 才为 true。"
        "重复或越界序号、缺失或多余节点、坐标冲突（重复坐标或与重算值不一致）"
        "以及不符合奇数层自复制规则的证明一律拒绝。请求体与批量证明响应同构，"
        "可原样回填；events 中除 seq、event_hash 外的字段被忽略。本接口不读取"
        "数据库，可在任何离线环境复算。"
    ),
)
def api_verify_batch_proof(req: BatchProofVerifyRequest) -> BatchProofVerifyResult:
    return BatchProofVerifyResult(
        **verify_batch_proof(
            chain_id=req.chain_id,
            events=[event.model_dump() for event in req.events],
            event_count=req.event_count,
            tail_hash=req.tail_hash,
            merkle_root=req.merkle_root,
            snapshot_digest_claim=req.snapshot_digest,
            proof_nodes=[node.model_dump() for node in req.proof_nodes],
        )
    )


@app.post(
    "/chains/{chain_id}/seals",
    response_model=SealOut,
    status_code=201,
    tags=["seals"],
    summary="对存在争议的交接链创建封存",
    description=(
        "持有人携带当前链尾 tail_hash、争议原因 reason、有效期 "
        "expires_in_seconds（秒，上限 30 天）与一次性解封码 release_code 创建封存。"
        "服务端只保存「绑定 seal_id 做域分隔」的 SHA-256 解封码摘要，明文绝不落库，"
        "且封存不追加任何哈希链事件。同一链同时只能有一个生效封存：重复封存返回 "
        "409 chain_seal_active；链尾不匹配返回 409 tail_mismatch；链条不存在返回 404。"
        "封存生效期间，直接移交（POST /handovers）以及邀约的创建、替换、确认都在"
        "各自现有 SQLite 立即事务内返回 409 chain_on_hold，且不写事件或新邀约；"
        "封存创建与这些操作并发时由立即事务与部分唯一索引保证只有一方成功。"
    ),
)
def api_create_seal(chain_id: str, req: SealCreateRequest) -> SealOut:
    return SealOut(
        **create_seal(
            chain_id,
            req.tail_hash,
            req.reason,
            req.expires_in_seconds,
            req.release_code,
        )
    )


@app.post(
    "/seals/{seal_id}/release",
    response_model=SealOut,
    tags=["seals"],
    summary="凭一次性解封码提前解封",
    description=(
        "持有人（或任何持有解封码的一方）凭 seal_id 与创建时提交的 "
        "release_code 提前解封。服务端在同一 SQLite 立即事务内校验封存仍 active、"
        "未过期且解封码摘要匹配，然后将封存置为 released 并记录 released_at，"
        "解封不追加任何链上事件。解封码错误返回 403 release_code_mismatch；封存不"
        "存在返回 404；已解封返回 409 seal_already_released；已过期返回 409 "
        "seal_expired（过期自动失效，无需再解封）。任何响应都不返回解封码摘要。"
    ),
)
def api_release_seal(seal_id: str, req: SealReleaseRequest) -> SealOut:
    return SealOut(**release_seal(seal_id, req.release_code))


@app.get(
    "/seals/{seal_id}",
    response_model=SealOut,
    tags=["seals"],
    summary="按封存 ID 查询封存状态",
    description=(
        "返回封存状态 active（生效中）/ released（已提前解封）/ expired（已过期"
        "自动失效，派生状态），以及原因 reason、锁定链尾 tail_hash 与创建时刻 "
        "created_at、到期时刻 expires_at、解封时刻 released_at；封存不存在返回 404。"
        "任何情况下都不返回解封码及其摘要。"
    ),
)
def api_get_seal(seal_id: str) -> SealOut:
    return SealOut(**get_seal(seal_id))


@app.get(
    "/chains/{chain_id}/seal",
    response_model=SealOut,
    tags=["seals"],
    summary="查询某条链最新的封存",
    description=(
        "返回该链最近一次封存的 active / released / expired 状态、原因与时间信息，"
        "绝不返回解封码摘要。链条不存在返回 404；该链从未有过封存返回 404 "
        "seal_not_found。"
    ),
)
def api_get_latest_seal(chain_id: str) -> SealOut:
    return SealOut(**get_latest_seal(chain_id))


def main() -> None:
    """本地直接运行入口（python -m app.main）。"""
    import uvicorn

    database.init_db()
    uvicorn.run("app.main:app", host=config.HOST, port=config.PORT)


if __name__ == "__main__":
    main()
