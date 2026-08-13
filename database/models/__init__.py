"""
TrustGuard — ORM model registry.

Importing this package (or any symbol from it) ensures that every model
class is registered against ``Base.metadata`` before Alembic ``autogenerate``
or ``create_all()`` is invoked.

Usage in Alembic env.py::

    import database.models          # registers all models
    target_metadata = Base.metadata
"""
from database.models.user import User, Role, UserRole
from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment, FragmentStatus
from database.models.access import (
    AccessRequest,
    RequestType,
    RequestStatus,
    Approval,
    ApprovalDecision,
    AccessWindow,
    WindowStatus,
)
from database.models.audit import (
    AuditLog,
    AuditResult,
    ThreatEvent,
    ThreatEventType,
    ThreatSeverity,
)

__all__ = [
    # users
    "User",
    "Role",
    "UserRole",
    # papers
    "QuestionPaper",
    "PaperStatus",
    # fragments
    "PaperFragment",
    "FragmentStatus",
    # access
    "AccessRequest",
    "RequestType",
    "RequestStatus",
    "Approval",
    "ApprovalDecision",
    "AccessWindow",
    "WindowStatus",
    # audit
    "AuditLog",
    "AuditResult",
    "ThreatEvent",
    "ThreatEventType",
    "ThreatSeverity",
]
