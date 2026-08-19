"""Student Examination Service implementing real candidate exam workflow.

Enforces:
- Server-authoritative timer and automatic expiration
- Secure server-side question scoring
- Zero leakage of correct answers
- Strict student isolation and assigned exam verification
"""

from datetime import datetime, timedelta, timezone
import json
from typing import Any, Dict, List, Optional
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models import AuditEvent, Exam, ExamStudent, Question, StudentExamSession, User
from app.schemas.student import (
    GuardianStudentItem,
    GuardianStudentStatsResponse,
    QuestionPublic,
    StudentExamSummary,
    StudentSessionDetail,
    StudentSubmissionResult,
)
from app.services.audit_service import AuditService


def _normalize_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure a datetime object is timezone-aware UTC for safe comparisons."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


DEFAULT_CYBERSECURITY_QUESTIONS = [
    {
        "question_number": 1,
        "question_text": "What is the foundational security principle of a Zero-Trust Architecture?",
        "options": [
            {"key": "A", "text": "Never Trust, Always Verify — continuous identity & integrity checks"},
            {"key": "B", "text": "Trust all internal network traffic once inside perimeter firewall"},
            {"key": "C", "text": "Authenticate users only at initial login and trust session indefinitely"},
            {"key": "D", "text": "Rely solely on IP address whitelisting for access control"},
        ],
        "correct_answer": "A",
        "marks": 1,
    },
    {
        "question_number": 2,
        "question_text": "In Shamir's (k, n) Threshold Secret Sharing scheme, what does the parameter 'k' represent?",
        "options": [
            {"key": "A", "text": "The total number of key shares generated"},
            {"key": "B", "text": "The minimum number of shares required to reconstruct the master secret"},
            {"key": "C", "text": "The length of the encryption key in bytes"},
            {"key": "D", "text": "The maximum number of malicious nodes tolerated"},
        ],
        "correct_answer": "B",
        "marks": 1,
    },
    {
        "question_number": 3,
        "question_text": "Which symmetric cipher mode provides authenticated encryption with associated data (AEAD)?",
        "options": [
            {"key": "A", "text": "AES-ECB (Electronic Codebook)"},
            {"key": "B", "text": "AES-CBC (Cipher Block Chaining)"},
            {"key": "C", "text": "AES-GCM (Galois/Counter Mode)"},
            {"key": "D", "text": "DES-OFB (Output Feedback)"},
        ],
        "correct_answer": "C",
        "marks": 1,
    },
    {
        "question_number": 4,
        "question_text": "Why does TrustGuard stage question paper payloads exclusively in volatile Ephemeral RAM?",
        "options": [
            {"key": "A", "text": "To prevent post-exam disk forensic extraction by auto-purging on completion"},
            {"key": "B", "text": "Because RAM storage is cheaper than permanent disk storage"},
            {"key": "C", "text": "To bypass the need for cryptographic encryption"},
            {"key": "D", "text": "To allow client browsers to cache questions offline"},
        ],
        "correct_answer": "A",
        "marks": 1,
    },
    {
        "question_number": 5,
        "question_text": "Which cryptographic hash standard produces a 256-bit fixed-length digest used for integrity manifests?",
        "options": [
            {"key": "A", "text": "MD5"},
            {"key": "B", "text": "SHA-1"},
            {"key": "C", "text": "SHA-256"},
            {"key": "D", "text": "CRC32"},
        ],
        "correct_answer": "C",
        "marks": 1,
    },
    {
        "question_number": 6,
        "question_text": "What type of attack involves intercepting valid authentication tokens and re-transmitting them to gain unauthorized access?",
        "options": [
            {"key": "A", "text": "SQL Injection"},
            {"key": "B", "text": "Replay Attack"},
            {"key": "C", "text": "Buffer Overflow"},
            {"key": "D", "text": "Cross-Site Scripting (XSS)"},
        ],
        "correct_answer": "B",
        "marks": 1,
    },
    {
        "question_number": 7,
        "question_text": "In Role-Based Access Control (RBAC), what primary factor governs access permissions to sensitive endpoints?",
        "options": [
            {"key": "A", "text": "The user's assigned role and associated permission bindings"},
            {"key": "B", "text": "The physical location and time of day of the client"},
            {"key": "C", "text": "The client device manufacturer and operating system"},
            {"key": "D", "text": "The network connection speed of the client"},
        ],
        "correct_answer": "A",
        "marks": 1,
    },
    {
        "question_number": 8,
        "question_text": "What is the purpose of an Initialization Vector (IV) / Nonce in AES encryption?",
        "options": [
            {"key": "A", "text": "It acts as the secret decryption password"},
            {"key": "B", "text": "It ensures that encrypting identical plaintexts produces distinct ciphertexts"},
            {"key": "C", "text": "It compresses large files before encryption"},
            {"key": "D", "text": "It signs the document with a digital certificate"},
        ],
        "correct_answer": "B",
        "marks": 1,
    },
    {
        "question_number": 9,
        "question_text": "Why must examination session timers be server-authoritative?",
        "options": [
            {"key": "A", "text": "To prevent students from altering local device clocks to artificially extend exam time"},
            {"key": "B", "text": "To reduce network traffic by not communicating with the client"},
            {"key": "C", "text": "To enable students to pause and resume exams at will"},
            {"key": "D", "text": "To automatically submit exams when the student's browser crashes"},
        ],
        "correct_answer": "A",
        "marks": 1,
    },
    {
        "question_number": 10,
        "question_text": "What security properties does an HMAC (Hash-based Message Authentication Code) verify?",
        "options": [
            {"key": "A", "text": "Confidentiality and compression only"},
            {"key": "B", "text": "Data integrity and authenticity using a shared secret key"},
            {"key": "C", "text": "Public key encryption and key distribution"},
            {"key": "D", "text": "Physical network link availability"},
        ],
        "correct_answer": "B",
        "marks": 1,
    },
    {
        "question_number": 11,
        "question_text": "What is the Principle of Least Privilege in enterprise cybersecurity?",
        "options": [
            {"key": "A", "text": "Users are granted the minimum level of access necessary to perform their specific duties"},
            {"key": "B", "text": "All users are given administrative access for maximum operational efficiency"},
            {"key": "C", "text": "Access rights are never revoked once granted"},
            {"key": "D", "text": "Security logs are disabled for lower-level employees"},
        ],
        "correct_answer": "A",
        "marks": 1,
    },
    {
        "question_number": 12,
        "question_text": "How does Multi-Guardian Quorum consensus prevent insider threats from leaking question papers?",
        "options": [
            {"key": "A", "text": "No single individual possesses the full decryption key; quorum release is required"},
            {"key": "B", "text": "It converts question papers into plaintext text files on disk"},
            {"key": "C", "text": "It requires physical paper printing before the exam starts"},
            {"key": "D", "text": "It eliminates the need for user passwords"},
        ],
        "correct_answer": "A",
        "marks": 1,
    },
    {
        "question_number": 13,
        "question_text": "What characterizes an immutable cryptographic audit log?",
        "options": [
            {"key": "A", "text": "An append-only structure where log entries are tamper-evident and cannot be silently altered"},
            {"key": "B", "text": "A temporary cache file deleted whenever a user logs out"},
            {"key": "C", "text": "A spreadsheet that can be updated by system administrators"},
            {"key": "D", "text": "Client-side browser history records"},
        ],
        "correct_answer": "A",
        "marks": 1,
    },
    {
        "question_number": 14,
        "question_text": "Which exam state must be reached before registered students are permitted to access questions?",
        "options": [
            {"key": "A", "text": "DRAFT"},
            {"key": "B", "text": "AWAITING_APPROVAL"},
            {"key": "C", "text": "AUTHORIZED / LIVE / UNLOCKED"},
            {"key": "D", "text": "REVOKED"},
        ],
        "correct_answer": "C",
        "marks": 1,
    },
    {
        "question_number": 15,
        "question_text": "What occurs when a candidate's server-authoritative timer reaches zero (session expires)?",
        "options": [
            {"key": "A", "text": "The session automatically transitions to EXPIRED and further answer submissions are rejected"},
            {"key": "B", "text": "The candidate is given an automatic 30-minute grace extension"},
            {"key": "C", "text": "The candidate's previous answers are immediately deleted"},
            {"key": "D", "text": "The examination restarts from question 1"},
        ],
        "correct_answer": "A",
        "marks": 1,
    },
    {
        "question_number": 16,
        "question_text": "In TLS/HTTPS protocol, what mechanism provides transport-layer confidentiality and authenticity?",
        "options": [
            {"key": "A", "text": "Asymmetric key exchange combined with authenticated symmetric session encryption"},
            {"key": "B", "text": "Plaintext TCP stream transmission with base64 encoding"},
            {"key": "C", "text": "Unencrypted UDP datagram broadcasts"},
            {"key": "D", "text": "Client-side HTML header validation"},
        ],
        "correct_answer": "A",
        "marks": 1,
    },
    {
        "question_number": 17,
        "question_text": "Why must ciphertext integrity be verified before attempting decryption?",
        "options": [
            {"key": "A", "text": "To detect tampering and prevent chosen-ciphertext attacks (e.g. padding oracle attacks)"},
            {"key": "B", "text": "To format the font family of the decrypted text"},
            {"key": "C", "text": "To calculate the final exam score"},
            {"key": "D", "text": "To verify the candidate's student ID"},
        ],
        "correct_answer": "A",
        "marks": 1,
    },
    {
        "question_number": 18,
        "question_text": "What severe vulnerability arises if correct answers are sent to the student's browser before submission?",
        "options": [
            {"key": "A", "text": "Inspection of browser memory or network payloads allows candidates to cheat effortlessly"},
            {"key": "B", "text": "It causes browser memory leaks on mobile devices"},
            {"key": "C", "text": "It invalidates the SSL certificate of the web server"},
            {"key": "D", "text": "It prevents the browser back button from functioning"},
        ],
        "correct_answer": "A",
        "marks": 1,
    },
    {
        "question_number": 19,
        "question_text": "How does TrustGuard ensure strict candidate session isolation between student1 and student2?",
        "options": [
            {"key": "A", "text": "By verifying the authenticated JWT user identity against the session's student_id on every operation"},
            {"key": "B", "text": "By allowing all students to share the same session ID token"},
            {"key": "C", "text": "By relying solely on IP address subnet checks"},
            {"key": "D", "text": "By saving answers to local browser storage only"},
        ],
        "correct_answer": "A",
        "marks": 1,
    },
    {
        "question_number": 20,
        "question_text": "In a 3-of-3 threshold consensus exam, how many key guardian approvals are strictly required to release the paper?",
        "options": [
            {"key": "A", "text": "1 approval"},
            {"key": "B", "text": "2 approvals"},
            {"key": "C", "text": "All 3 approvals (100% consensus)"},
            {"key": "D", "text": "0 approvals"},
        ],
        "correct_answer": "C",
        "marks": 1,
    },
]


class StudentService:

    @staticmethod
    async def ensure_exam_questions_seeded(db: AsyncSession, exam_id: str) -> List[Question]:
        """Ensure standard questions are seeded for the exam if none exist."""
        stmt = (
            select(Question)
            .where(Question.exam_id == exam_id)
            .order_by(Question.question_number.asc())
        )
        result = await db.execute(stmt)
        existing = list(result.scalars().all())

        if existing:
            return existing

        created = []
        for q_data in DEFAULT_CYBERSECURITY_QUESTIONS:
            q = Question(
                exam_id=exam_id,
                question_number=q_data["question_number"],
                question_text=q_data["question_text"],
                options=json.dumps(q_data["options"]),
                correct_answer=q_data["correct_answer"],
                marks=q_data["marks"],
            )
            db.add(q)
            created.append(q)

        await db.commit()
        for q in created:
            await db.refresh(q)
        return created

    @staticmethod
    async def get_student_exams(db: AsyncSession, student_user_id: str) -> List[StudentExamSummary]:
        """List exams assigned to the student with live session status."""
        # Query exams where student is registered
        stmt = (
            select(Exam)
            .join(ExamStudent, ExamStudent.exam_id == Exam.id)
            .where(ExamStudent.student_id == student_user_id)
            .order_by(Exam.scheduled_start.desc())
        )
        result = await db.execute(stmt)
        exams = result.scalars().all()

        summaries = []
        now = datetime.now(timezone.utc)

        for exam in exams:
            # Check student session
            s_stmt = select(StudentExamSession).where(
                StudentExamSession.exam_id == exam.id,
                StudentExamSession.student_id == student_user_id,
            )
            s_res = await db.execute(s_stmt)
            session = s_res.scalar_one_or_none()

            session_status = "NOT_STARTED"
            if session:
                if session.status == "IN_PROGRESS" and session.expires_at and now >= session.expires_at:
                    session.status = "EXPIRED"
                    await db.commit()
                    await db.refresh(session)
                session_status = session.status

            is_joinable = exam.status in ["AUTHORIZED", "UNLOCKED", "LIVE"] and session_status in ["NOT_STARTED", "IN_PROGRESS"]

            summaries.append(
                StudentExamSummary(
                    id=exam.id,
                    title=exam.title,
                    course_code=exam.course_code,
                    status=exam.status,
                    duration_minutes=exam.duration_minutes,
                    scheduled_start=exam.scheduled_start,
                    scheduled_end=exam.scheduled_end,
                    is_joinable=is_joinable,
                    session_status=session_status,
                )
            )

        return summaries

    @staticmethod
    async def join_or_start_session(
        db: AsyncSession, exam_id: str, student_user: User
    ) -> StudentSessionDetail:
        """
        Student joins/starts an examination session:
        1. Verifies student is enrolled in the exam (403 if not)
        2. Verifies exam is in authorized/released state (403/400 if not)
        3. Initializes or resumes server-authoritative timer
        4. Returns questions (with NO correct answers leaked!)
        """
        # 1. Fetch exam
        exam_stmt = (
            select(Exam)
            .where(Exam.id == exam_id)
            .options(
                selectinload(Exam.students),
                selectinload(Exam.questions),
            )
        )
        exam_res = await db.execute(exam_stmt)
        exam = exam_res.scalar_one_or_none()

        if not exam:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Examination '{exam_id}' not found",
            )

        # 2. Check student registration
        is_registered = any(s.student_id == student_user.id for s in exam.students)
        if not is_registered:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: Student '{student_user.username}' is not registered for this examination",
            )

        # 3. Check exam authorization status
        authorized_states = {"AUTHORIZED", "UNLOCKED", "LIVE", "COMPLETED", "READY"}
        if exam.status not in authorized_states:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Cannot join exam in '{exam.status}' state. Paper must be authorized and released by Key Guardians.",
            )

        # Ensure questions are seeded for this exam
        questions = await StudentService.ensure_exam_questions_seeded(db, exam.id)
        total_marks = sum(q.marks for q in questions)

        now = datetime.now(timezone.utc)

        # 4. Check existing session
        sess_stmt = select(StudentExamSession).where(
            StudentExamSession.exam_id == exam.id,
            StudentExamSession.student_id == student_user.id,
        )
        sess_res = await db.execute(sess_stmt)
        session = sess_res.scalar_one_or_none()

        if not session:
            # Create new session starting now with server-authoritative expiry
            expires_at = now + timedelta(minutes=exam.duration_minutes)
            session = StudentExamSession(
                exam_id=exam.id,
                student_id=student_user.id,
                status="IN_PROGRESS",
                started_at=now,
                expires_at=expires_at,
                max_score=total_marks,
                answers_json="{}",
            )
            db.add(session)
            await db.commit()
            await db.refresh(session)

            # Audit event
            await AuditService.log_event(
                db=db,
                action="STUDENT_JOINED_EXAM",
                exam_id=exam.id,
                actor_id=student_user.id,
                details={
                    "session_id": session.id,
                    "student_username": student_user.username,
                    "started_at": now.isoformat(),
                    "expires_at": expires_at.isoformat(),
                    "duration_minutes": exam.duration_minutes,
                },
            )
        else:
            # Session already exists — check timer expiry
            exp_utc = _normalize_utc(session.expires_at)
            if session.status == "IN_PROGRESS" and exp_utc:
                if now >= exp_utc:
                    session.status = "EXPIRED"
                    await db.commit()
                    await db.refresh(session)
            elif session.status == "NOT_STARTED":
                expires_at = now + timedelta(minutes=exam.duration_minutes)
                session.status = "IN_PROGRESS"
                session.started_at = now
                session.expires_at = expires_at
                await db.commit()
                await db.refresh(session)

        # Real-time WebSocket event broadcast to guardian dashboard
        try:
            from app.services.websocket_manager import get_ws_manager
            ws_manager = get_ws_manager()
            stats = await StudentService.get_guardian_student_stats(db, exam.id)
            await ws_manager.broadcast_to_exam(
                exam.id,
                "STUDENT_JOINED",
                {
                    "student_username": student_user.username,
                    "session_id": session.id,
                    "started_at": session.started_at.isoformat() if session.started_at else None,
                    "stats": stats.model_dump(),
                },
            )
            await ws_manager.broadcast_to_exam(exam.id, "STATS_UPDATED", stats.model_dump())
        except Exception:
            pass

        return StudentService._build_session_detail(session, exam, student_user, questions, now)

    @staticmethod
    async def get_session_state(
        db: AsyncSession, exam_id: str, student_user: User
    ) -> StudentSessionDetail:
        """Get current session state for the student, verifying expiry against server time."""
        exam_stmt = (
            select(Exam)
            .where(Exam.id == exam_id)
            .options(selectinload(Exam.questions))
        )
        exam_res = await db.execute(exam_stmt)
        exam = exam_res.scalar_one_or_none()

        if not exam:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Examination '{exam_id}' not found",
            )

        sess_stmt = select(StudentExamSession).where(
            StudentExamSession.exam_id == exam.id,
            StudentExamSession.student_id == student_user.id,
        )
        sess_res = await db.execute(sess_stmt)
        session = sess_res.scalar_one_or_none()

        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No active examination session found for this student. Please join the exam first.",
            )

        now = datetime.now(timezone.utc)

        # Check server-authoritative expiration
        exp_utc = _normalize_utc(session.expires_at)
        if session.status == "IN_PROGRESS" and exp_utc:
            if now >= exp_utc:
                session.status = "EXPIRED"
                await db.commit()
                await db.refresh(session)

        questions = await StudentService.ensure_exam_questions_seeded(db, exam.id)
        return StudentService._build_session_detail(session, exam, student_user, questions, now)

    @staticmethod
    async def save_answers(
        db: AsyncSession,
        session_id: str,
        student_user: User,
        answers: Dict[str, str],
    ) -> StudentSessionDetail:
        """Save intermediate answers. Rejects if session expired or not owned by student."""
        sess_stmt = (
            select(StudentExamSession)
            .where(StudentExamSession.id == session_id)
            .options(
                selectinload(StudentExamSession.exam).selectinload(Exam.questions)
            )
        )
        sess_res = await db.execute(sess_stmt)
        session = sess_res.scalar_one_or_none()

        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Exam session '{session_id}' not found",
            )

        # Strict session ownership check
        if session.student_id != student_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access Denied: You cannot modify another candidate's examination session",
            )

        if session.status == "SUBMITTED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Exam has already been submitted. No further answers can be recorded.",
            )

        now = datetime.now(timezone.utc)
        exp_utc = _normalize_utc(session.expires_at)

        # Check timer expiration
        if session.status == "EXPIRED" or (exp_utc and now >= exp_utc):
            session.status = "EXPIRED"
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Exam session has EXPIRED. No further answers can be submitted.",
            )

        # Merge answers
        current_answers = {}
        if session.answers_json:
            try:
                current_answers = json.loads(session.answers_json)
            except Exception:
                current_answers = {}

        current_answers.update(answers)
        session.answers_json = json.dumps(current_answers)
        await db.commit()
        await db.refresh(session)

        questions = session.exam.questions if session.exam else []
        return StudentService._build_session_detail(session, session.exam, student_user, questions, now)

    @staticmethod
    async def submit_exam(
        db: AsyncSession,
        session_id: str,
        student_user: User,
        final_answers: Optional[Dict[str, str]] = None,
    ) -> StudentSubmissionResult:
        """
        Finalize and submit student exam:
        - Strict session ownership
        - Idempotent duplicate submission handling
        - Server-authoritative expiration check
        - Secure server-side answer evaluation & scoring
        """
        sess_stmt = (
            select(StudentExamSession)
            .where(StudentExamSession.id == session_id)
            .options(
                selectinload(StudentExamSession.exam).selectinload(Exam.questions)
            )
        )
        sess_res = await db.execute(sess_stmt)
        session = sess_res.scalar_one_or_none()

        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Exam session '{session_id}' not found",
            )

        # Strict session ownership check
        if session.student_id != student_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access Denied: You cannot submit another candidate's examination session",
            )

        now = datetime.now(timezone.utc)

        # Idempotent duplicate submission handling
        if session.status == "SUBMITTED":
            saved_answers = json.loads(session.answers_json) if session.answers_json else {}
            return StudentSubmissionResult(
                session_id=session.id,
                exam_id=session.exam_id,
                student_id=student_user.id,
                status="SUBMITTED",
                submitted_at=session.submitted_at or now,
                answers_recorded=len(saved_answers),
                score=session.score,
                max_score=session.max_score,
                message=f"Exam already submitted previously at {(session.submitted_at or now).isoformat()}.",
            )

        # Expiration check
        exp_utc = _normalize_utc(session.expires_at)
        if session.status == "EXPIRED" or (exp_utc and now >= exp_utc):
            session.status = "EXPIRED"
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Exam session has EXPIRED. Submission is closed.",
            )

        # Merge final answers if supplied
        current_answers = {}
        if session.answers_json:
            try:
                current_answers = json.loads(session.answers_json)
            except Exception:
                current_answers = {}

        if final_answers:
            current_answers.update(final_answers)

        session.answers_json = json.dumps(current_answers)

        # Score evaluation securely server-side
        questions = await StudentService.ensure_exam_questions_seeded(db, session.exam_id)
        total_score = 0
        max_score = 0

        for q in questions:
            max_score += q.marks
            candidate_answer = current_answers.get(q.id)
            if candidate_answer and candidate_answer.strip().upper() == q.correct_answer.strip().upper():
                total_score += q.marks

        session.status = "SUBMITTED"
        session.submitted_at = now
        session.score = total_score
        session.max_score = max_score

        await db.commit()
        await db.refresh(session)

        # Audit event
        await AuditService.log_event(
            db=db,
            action="STUDENT_EXAM_SUBMITTED",
            exam_id=session.exam_id,
            actor_id=student_user.id,
            details={
                "session_id": session.id,
                "student_username": student_user.username,
                "answers_count": len(current_answers),
                "score": total_score,
                "max_score": max_score,
                "submitted_at": now.isoformat(),
            },
        )

        # Real-time WebSocket event broadcast to guardian dashboard
        try:
            from app.services.websocket_manager import get_ws_manager
            ws_manager = get_ws_manager()
            stats = await StudentService.get_guardian_student_stats(db, session.exam_id)
            await ws_manager.broadcast_to_exam(
                session.exam_id,
                "STUDENT_SUBMITTED",
                {
                    "student_username": student_user.username,
                    "session_id": session.id,
                    "score": total_score,
                    "max_score": max_score,
                    "submitted_at": now.isoformat(),
                    "stats": stats.model_dump(),
                },
            )
            await ws_manager.broadcast_to_exam(session.exam_id, "STATS_UPDATED", stats.model_dump())
        except Exception:
            pass

        return StudentSubmissionResult(
            session_id=session.id,
            exam_id=session.exam_id,
            student_id=student_user.id,
            status="SUBMITTED",
            submitted_at=now,
            answers_recorded=len(current_answers),
            score=total_score,
            max_score=max_score,
            message=f"Examination successfully submitted and recorded. Total score: {total_score}/{max_score}.",
        )

    @staticmethod
    async def get_guardian_student_stats(db: AsyncSession, exam_id: str) -> GuardianStudentStatsResponse:
        """
        Guardian view of candidate progress:
        - Registered students count
        - Currently writing count (IN_PROGRESS)
        - Submitted count (SUBMITTED)
        - Expired count (EXPIRED)
        """
        # Fetch registered students
        reg_stmt = (
            select(ExamStudent)
            .where(ExamStudent.exam_id == exam_id)
            .options(selectinload(ExamStudent.student))
        )
        reg_res = await db.execute(reg_stmt)
        registered_records = list(reg_res.scalars().all())

        # Fetch student sessions
        sess_stmt = (
            select(StudentExamSession)
            .where(StudentExamSession.exam_id == exam_id)
            .options(selectinload(StudentExamSession.student))
        )
        sess_res = await db.execute(sess_stmt)
        sessions = list(sess_res.scalars().all())

        session_map = {s.student_id: s for s in sessions}
        now = datetime.now(timezone.utc)

        # Check and update expired sessions
        for s in sessions:
            exp_utc = _normalize_utc(s.expires_at)
            if s.status == "IN_PROGRESS" and exp_utc and now >= exp_utc:
                s.status = "EXPIRED"
        await db.commit()

        student_items = []
        currently_writing = 0
        submitted_count = 0
        expired_count = 0

        for reg in registered_records:
            student_id = reg.student_id
            username = reg.student.username if reg.student else f"student_{student_id[:6]}"
            session = session_map.get(student_id)

            if session:
                st = session.status
                if st == "IN_PROGRESS":
                    currently_writing += 1
                elif st == "SUBMITTED":
                    submitted_count += 1
                elif st == "EXPIRED":
                    expired_count += 1

                student_items.append(
                    GuardianStudentItem(
                        student_id=student_id,
                        username=username,
                        status=st,
                        session_id=session.id,
                        started_at=session.started_at,
                        submitted_at=session.submitted_at,
                        score=session.score,
                    )
                )
            else:
                student_items.append(
                    GuardianStudentItem(
                        student_id=student_id,
                        username=username,
                        status="NOT_STARTED",
                        session_id=None,
                        started_at=None,
                        submitted_at=None,
                        score=None,
                    )
                )

        return GuardianStudentStatsResponse(
            exam_id=exam_id,
            registered_count=len(registered_records),
            currently_writing=currently_writing,
            submitted_count=submitted_count,
            expired_count=expired_count,
            students=student_items,
        )

    # ── Private Helpers ───────────────────────────────────────────────
    @staticmethod
    def _build_session_detail(
        session: StudentExamSession,
        exam: Exam,
        student_user: User,
        questions: List[Question],
        now: datetime,
    ) -> StudentSessionDetail:
        """Construct student view — ALWAYS strictly excludes correct_answer."""
        remaining_seconds = 0
        exp_utc = _normalize_utc(session.expires_at)
        if exp_utc and session.status == "IN_PROGRESS":
            delta = (exp_utc - now).total_seconds()
            remaining_seconds = max(0, int(delta))

        # Parse saved answers
        saved_answers = {}
        if session.answers_json:
            try:
                saved_answers = json.loads(session.answers_json)
            except Exception:
                saved_answers = {}

        # Transform questions to public schema (NO correct_answer!)
        public_questions = []
        for q in questions:
            opts = []
            if q.options:
                try:
                    opts = json.loads(q.options)
                except Exception:
                    opts = []
            public_questions.append(
                QuestionPublic(
                    id=q.id,
                    question_number=q.question_number,
                    question_text=q.question_text,
                    options=opts,
                    marks=q.marks,
                )
            )

        return StudentSessionDetail(
            session_id=session.id,
            exam_id=exam.id,
            exam_title=exam.title,
            course_code=exam.course_code,
            student_id=student_user.id,
            student_username=student_user.username,
            status=session.status,
            started_at=session.started_at,
            expires_at=session.expires_at,
            server_time=now,
            remaining_seconds=remaining_seconds,
            duration_minutes=exam.duration_minutes,
            submitted_at=session.submitted_at,
            score=session.score,
            max_score=session.max_score,
            saved_answers=saved_answers,
            questions=public_questions,
        )
