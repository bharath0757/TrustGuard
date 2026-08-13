"""Initial schema: all TrustGuard tables, ENUMs, indexes, and constraints.

Creates 10 tables in FK-dependency order:
  1.  users
  2.  roles
  3.  user_roles
  4.  question_papers
  5.  paper_fragments
  6.  access_requests
  7.  approvals
  8.  access_windows
  9.  audit_logs
  10. threat_events

Revision ID: 0001
Revises:
Create Date: 2026-08-13
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


# ---------------------------------------------------------------------------
# ENUM type helpers
# ---------------------------------------------------------------------------

_ENUM_DEFINITIONS = {
    "paperstatus": [
        "CREATED", "PROTECTED", "FRAGMENTED", "AWAITING_APPROVAL",
        "AUTHORIZED", "ACTIVE", "EXPIRED", "COMPLETED",
    ],
    "fragmentstatus": ["PENDING", "STORED", "CORRUPTED", "DELETED"],
    "requesttype":   ["VIEW", "RECONSTRUCT", "EMERGENCY"],
    "requeststatus": ["PENDING", "APPROVED", "REJECTED", "EXPIRED", "WITHDRAWN"],
    "approvaldecision": ["APPROVED", "REJECTED"],
    "windowstatus":  ["SCHEDULED", "ACTIVE", "CLOSED", "REVOKED"],
    "auditresult":   ["SUCCESS", "FAILURE", "DENIED"],
    "threateventtype": [
        "UNAUTHORIZED_ACCESS", "INVALID_QUORUM", "INTEGRITY_FAILURE",
        "DENIED_OPERATION", "REPLAY_ATTEMPT", "BRUTE_FORCE",
    ],
    "threatseverity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
}


def _create_enums() -> None:
    """Create all PostgreSQL ENUM types."""
    for name, values in _ENUM_DEFINITIONS.items():
        pg_enum = postgresql.ENUM(*values, name=name, create_type=False)
        pg_enum.create(op.get_bind(), checkfirst=True)


def _drop_enums() -> None:
    """Drop all PostgreSQL ENUM types."""
    for name in reversed(list(_ENUM_DEFINITIONS.keys())):
        pg_enum = postgresql.ENUM(name=name, create_type=False)
        pg_enum.drop(op.get_bind(), checkfirst=True)


# ---------------------------------------------------------------------------
# upgrade
# ---------------------------------------------------------------------------

def upgrade() -> None:
    _create_enums()

    # ── 1. users ─────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("email",         sa.String(255), nullable=False),
        sa.Column(
            "password_hash",
            sa.String(255),
            nullable=False,
            comment="bcrypt / Argon2id hash — NEVER plaintext",
        ),
        sa.Column("full_name",     sa.String(255), nullable=False),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "is_system",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
            comment="True for non-human service accounts",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # ── 2. roles ──────────────────────────────────────────────────────────
    op.create_table(
        "roles",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "name",
            sa.String(50),
            nullable=False,
            comment="ADMIN | OFFICER | APPROVER | AUDITOR | SYSTEM",
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.UniqueConstraint("name", name="uq_roles_name"),
    )

    # ── 3. user_roles ─────────────────────────────────────────────────────
    op.create_table(
        "user_roles",
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE", name="fk_user_roles_user"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "role_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("roles.id", ondelete="CASCADE", name="fk_user_roles_role"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "granted_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL", name="fk_user_roles_granted_by"),
            nullable=True,
            comment="Which admin granted this role",
        ),
    )

    # ── 4. question_papers ────────────────────────────────────────────────
    op.create_table(
        "question_papers",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("exam_identifier", sa.String(100), nullable=False),
        sa.Column("paper_name",      sa.String(255), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(
                *_ENUM_DEFINITIONS["paperstatus"],
                name="paperstatus",
                create_type=False,
            ),
            nullable=False,
            server_default="CREATED",
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL", name="fk_papers_created_by"),
            nullable=True,
        ),
        sa.Column("protected_at",  sa.DateTime(timezone=True), nullable=True),
        sa.Column("fragmented_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at",  sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "integrity_hash",
            sa.String(128),
            nullable=True,
            comment="SHA-256/512 hex digest of original content manifest",
        ),
        sa.Column("total_fragments", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_question_papers_status",       "question_papers", ["status"])
    op.create_index("ix_question_papers_exam",         "question_papers", ["exam_identifier"])
    op.create_index("ix_question_papers_created_by",   "question_papers", ["created_by"])
    op.create_index(
        "ix_question_papers_status_exam",
        "question_papers",
        ["status", "exam_identifier"],
    )

    # ── 5. paper_fragments ────────────────────────────────────────────────
    op.create_table(
        "paper_fragments",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "paper_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "question_papers.id", ondelete="CASCADE",
                name="fk_fragments_paper",
            ),
            nullable=False,
        ),
        sa.Column("fragment_index", sa.SmallInteger(), nullable=False),
        sa.Column(
            "fragment_data",
            sa.LargeBinary(),
            nullable=False,
            comment="Raw ciphertext — NEVER plaintext content",
        ),
        sa.Column(
            "integrity_hash",
            sa.String(128),
            nullable=False,
            comment="Hash of fragment_data for tamper detection",
        ),
        sa.Column(
            "status",
            postgresql.ENUM(
                *_ENUM_DEFINITIONS["fragmentstatus"],
                name="fragmentstatus",
                create_type=False,
            ),
            nullable=False,
            server_default="PENDING",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "paper_id", "fragment_index",
            name="uq_paper_fragments_paper_index",
        ),
    )
    op.create_index("ix_paper_fragments_paper_id", "paper_fragments", ["paper_id"])

    # ── 6. access_requests ────────────────────────────────────────────────
    op.create_table(
        "access_requests",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "paper_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "question_papers.id", ondelete="CASCADE",
                name="fk_access_requests_paper",
            ),
            nullable=False,
        ),
        sa.Column(
            "requested_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "users.id", ondelete="RESTRICT",
                name="fk_access_requests_user",
            ),
            nullable=False,
        ),
        sa.Column(
            "request_type",
            postgresql.ENUM(
                *_ENUM_DEFINITIONS["requesttype"],
                name="requesttype",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            postgresql.ENUM(
                *_ENUM_DEFINITIONS["requeststatus"],
                name="requeststatus",
                create_type=False,
            ),
            nullable=False,
            server_default="PENDING",
        ),
        sa.Column(
            "required_approvals",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("2"),
            comment="Quorum threshold",
        ),
        sa.Column("reason",      sa.Text(), nullable=False),
        sa.Column("decided_at",  sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_access_requests_paper",        "access_requests", ["paper_id"])
    op.create_index("ix_access_requests_user",         "access_requests", ["requested_by"])
    op.create_index("ix_access_requests_status",       "access_requests", ["status"])
    op.create_index(
        "ix_access_requests_paper_status",
        "access_requests",
        ["paper_id", "status"],
    )

    # ── 7. approvals ──────────────────────────────────────────────────────
    op.create_table(
        "approvals",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "request_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "access_requests.id", ondelete="CASCADE",
                name="fk_approvals_request",
            ),
            nullable=False,
        ),
        sa.Column(
            "approved_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "users.id", ondelete="RESTRICT",
                name="fk_approvals_user",
            ),
            nullable=False,
        ),
        sa.Column(
            "decision",
            postgresql.ENUM(
                *_ENUM_DEFINITIONS["approvaldecision"],
                name="approvaldecision",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("reason",     sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "request_id", "approved_by",
            name="uq_approvals_request_approver",
        ),
    )
    op.create_index("ix_approvals_request",  "approvals", ["request_id"])
    op.create_index("ix_approvals_approver", "approvals", ["approved_by"])

    # ── 8. access_windows ─────────────────────────────────────────────────
    op.create_table(
        "access_windows",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "paper_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "question_papers.id", ondelete="CASCADE",
                name="fk_windows_paper",
            ),
            nullable=False,
        ),
        sa.Column(
            "request_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "access_requests.id", ondelete="CASCADE",
                name="fk_windows_request",
            ),
            nullable=False,
            unique=True,
            comment="One window per approved request",
        ),
        sa.Column("start_time",  sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time",    sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(
                *_ENUM_DEFINITIONS["windowstatus"],
                name="windowstatus",
                create_type=False,
            ),
            nullable=False,
            server_default="SCHEDULED",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "end_time > start_time",
            name="ck_access_windows_end_after_start",
        ),
        sa.UniqueConstraint("request_id", name="uq_access_windows_request"),
    )
    op.create_index("ix_access_windows_paper",  "access_windows", ["paper_id"])
    op.create_index("ix_access_windows_status", "access_windows", ["status"])
    op.create_index(
        "ix_access_windows_paper_status",
        "access_windows",
        ["paper_id", "status"],
    )
    op.create_index(
        "ix_access_windows_time_range",
        "access_windows",
        ["start_time", "end_time"],
    )

    # ── 9. audit_logs ─────────────────────────────────────────────────────
    # No updated_at — this table is append-only and immutable by design.
    op.create_table(
        "audit_logs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
            comment="Event timestamp — immutable",
        ),
        sa.Column(
            "actor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "users.id", ondelete="SET NULL",
                name="fk_audit_logs_actor",
            ),
            nullable=True,
        ),
        sa.Column(
            "actor_ip",
            postgresql.INET(),
            nullable=True,
            comment="Source IP address",
        ),
        sa.Column("action",      sa.String(100), nullable=False),
        sa.Column("target_type", sa.String(50),  nullable=True),
        sa.Column("target_id",   postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "result",
            postgresql.ENUM(
                *_ENUM_DEFINITIONS["auditresult"],
                name="auditresult",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("reason",     sa.Text(), nullable=True),
        sa.Column(
            "extra_data",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment="Arbitrary structured context",
        ),
    )
    op.create_index(
        "ix_audit_logs_timestamp_desc",
        "audit_logs",
        [sa.text("timestamp DESC")],
    )
    op.create_index("ix_audit_logs_actor_id",  "audit_logs", ["actor_id"])
    op.create_index("ix_audit_logs_action",    "audit_logs", ["action"])
    op.create_index(
        "ix_audit_logs_target",
        "audit_logs",
        ["target_type", "target_id"],
    )

    # ── 10. threat_events ─────────────────────────────────────────────────
    op.create_table(
        "threat_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "event_type",
            postgresql.ENUM(
                *_ENUM_DEFINITIONS["threateventtype"],
                name="threateventtype",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "severity",
            postgresql.ENUM(
                *_ENUM_DEFINITIONS["threatseverity"],
                name="threatseverity",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "actor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "users.id", ondelete="SET NULL",
                name="fk_threat_events_actor",
            ),
            nullable=True,
        ),
        sa.Column(
            "actor_ip",
            postgresql.INET(),
            nullable=True,
        ),
        sa.Column("target_type",  sa.String(50), nullable=True),
        sa.Column("target_id",    postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("description",  sa.Text(), nullable=False),
        sa.Column(
            "extra_data",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "resolved",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "resolved_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "users.id", ondelete="SET NULL",
                name="fk_threat_events_resolver",
            ),
            nullable=True,
        ),
    )
    op.create_index("ix_threat_events_timestamp",  "threat_events", ["timestamp"])
    op.create_index("ix_threat_events_event_type", "threat_events", ["event_type"])
    op.create_index("ix_threat_events_severity",   "threat_events", ["severity"])
    op.create_index("ix_threat_events_resolved",   "threat_events", ["resolved"])
    op.create_index("ix_threat_events_actor_id",   "threat_events", ["actor_id"])
    op.create_index(
        "ix_threat_events_target",
        "threat_events",
        ["target_type", "target_id"],
    )


# ---------------------------------------------------------------------------
# downgrade
# ---------------------------------------------------------------------------

def downgrade() -> None:
    # Drop in reverse FK-dependency order.
    op.drop_table("threat_events")
    op.drop_table("audit_logs")
    op.drop_table("access_windows")
    op.drop_table("approvals")
    op.drop_table("access_requests")
    op.drop_table("paper_fragments")
    op.drop_table("question_papers")
    op.drop_table("user_roles")
    op.drop_table("roles")
    op.drop_table("users")
    _drop_enums()
