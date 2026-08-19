"""WebSocket endpoints for real-time exam monitoring and event streams."""

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.db.database import AsyncSessionLocal
from app.db.models import User
from app.services.exam_lifecycle_service import ExamLifecycleService
from app.services.websocket_manager import get_ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ws", tags=["WebSockets"])


async def _authenticate_ws(token: Optional[str], db: Optional[AsyncSession] = None) -> Optional[User]:
    """Validate JWT token and return User, or None if invalid."""
    if not token:
        return None
    try:
        payload = decode_access_token(token)
        if not payload:
            return None
        sub = payload.get("sub")
        username = payload.get("username")
        if not sub and not username:
            return None

        async def _find_user(s: AsyncSession):
            from sqlalchemy import or_
            conditions = []
            if sub:
                conditions.extend([User.id == sub, User.username == sub])
            if username:
                conditions.append(User.username == username)
            stmt = select(User).where(or_(*conditions))
            res = await s.execute(stmt)
            u = res.scalar_one_or_none()
            if u:
                _ = (u.id, u.username, u.role, u.email)
                s.expunge(u)
            return u

        if db is not None:
            return await _find_user(db)
        else:
            async with AsyncSessionLocal() as session:
                return await _find_user(session)
    except Exception as exc:
        logger.warning(f"WebSocket auth exception: {exc}")
        return None


@router.websocket("/exams/{exam_id}")
async def exam_realtime_stream(
    websocket: WebSocket,
    exam_id: str,
):
    """
    Real-Time WebSocket stream for Guardian Examination Monitoring:
    1. Authenticates connecting guardian/staff user via JWT token query param.
    2. Registers socket with WebSocketManager.
    3. Dispatches initial comprehensive state snapshot (`INIT_STATE`).
    4. Listens for client ping/pong keepalive messages.
    5. Disconnects cleanly on socket close or network error.
    """
    token = websocket.query_params.get("token")
    async with AsyncSessionLocal() as db:
        user = await _authenticate_ws(token, db)
        if not user:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid or missing authentication token")
            return

        # Check staff / guardian access
        allowed_roles = {"ADMIN", "EXAM_SETTER", "KEY_GUARDIAN", "GUARDIAN", "EXAM_CENTER", "AUDITOR"}
        if user.role not in allowed_roles:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Forbidden: Only examination guardians can monitor live dashboard")
            return

    ws_manager = get_ws_manager()
    await ws_manager.connect(websocket, exam_id)

    try:
        # Send initial full dashboard state snapshot
        async with AsyncSessionLocal() as db:
            initial_state = await ExamLifecycleService.get_full_dashboard_state(db, exam_id)
            await websocket.send_text(
                json.dumps(
                    {
                        "type": "INIT_STATE",
                        "exam_id": exam_id,
                        "payload": initial_state,
                    },
                    default=str,
                )
            )

        # Message loop (keepalive ping/pong)
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "PONG"}))
            elif data.startswith("{"):
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "REQUEST_STATE":
                        async with AsyncSessionLocal() as db:
                            curr_state = await ExamLifecycleService.get_full_dashboard_state(db, exam_id)
                            await websocket.send_text(
                                json.dumps(
                                    {
                                        "type": "STATE_UPDATE",
                                        "exam_id": exam_id,
                                        "payload": curr_state,
                                    },
                                    default=str,
                                )
                            )
                except Exception:
                    pass

    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket, exam_id)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        logger.warning(f"WebSocket error on exam_id={exam_id}: {exc}")
        await ws_manager.disconnect(websocket, exam_id)
