"""Pydantic schemas for the real student examination workflow.

CRITICAL SECURITY CONSTRAINT:
Correct answers are NEVER exposed in any student-facing response model.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class QuestionOption(BaseModel):
    key: str = Field(..., description="Option letter: A, B, C, D")
    text: str = Field(..., description="Option content")


class QuestionPublic(BaseModel):
    """Student view of a question — correct answer is strictly excluded."""
    id: str
    question_number: int
    question_text: str
    options: List[Dict[str, str]]
    marks: int = 1

    model_config = ConfigDict(from_attributes=True)


class StudentExamSummary(BaseModel):
    id: str
    title: str
    course_code: str
    status: str
    duration_minutes: int
    scheduled_start: datetime
    scheduled_end: datetime
    is_joinable: bool
    session_status: Optional[str] = "NOT_STARTED"

    model_config = ConfigDict(from_attributes=True)


class StudentSessionDetail(BaseModel):
    """Full session state returned to the student with server-authoritative timer."""
    session_id: str
    exam_id: str
    exam_title: str
    course_code: str
    student_id: str
    student_username: str
    status: str  # NOT_STARTED, IN_PROGRESS, SUBMITTED, EXPIRED
    started_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    server_time: datetime
    remaining_seconds: int
    duration_minutes: int
    submitted_at: Optional[datetime] = None
    score: Optional[int] = None
    max_score: Optional[int] = None
    saved_answers: Dict[str, str] = Field(default_factory=dict)
    questions: Optional[List[QuestionPublic]] = None

    model_config = ConfigDict(from_attributes=True)


class SaveAnswersRequest(BaseModel):
    answers: Dict[str, str] = Field(..., description="Map of question_id to chosen option key (e.g. {'Q1': 'A'})")


class SubmitExamRequest(BaseModel):
    answers: Optional[Dict[str, str]] = Field(default=None, description="Optional final answers map")


class StudentSubmissionResult(BaseModel):
    session_id: str
    exam_id: str
    student_id: str
    status: str
    submitted_at: datetime
    answers_recorded: int
    score: Optional[int] = None
    max_score: Optional[int] = None
    message: str


class GuardianStudentItem(BaseModel):
    student_id: str
    username: str
    status: str  # NOT_STARTED, IN_PROGRESS, SUBMITTED, EXPIRED
    session_id: Optional[str] = None
    started_at: Optional[datetime] = None
    submitted_at: Optional[datetime] = None
    score: Optional[int] = None


class GuardianStudentStatsResponse(BaseModel):
    exam_id: str
    registered_count: int
    currently_writing: int
    submitted_count: int
    expired_count: int
    students: List[GuardianStudentItem]
