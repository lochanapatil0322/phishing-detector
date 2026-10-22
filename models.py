from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base


def _now():
    return datetime.now(timezone.utc)


def _naive_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    scans: Mapped[list["Scan"]] = relationship(back_populates="user")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    input_type: Mapped[str] = mapped_column(String(10), default="url")
    input_text: Mapped[str] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(String(20))
    score: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    user: Mapped["User"] = relationship(back_populates="scans")
    reasons: Mapped[list["ScanReason"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanReason(Base):
    __tablename__ = "scan_reasons"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    reason_text: Mapped[str] = mapped_column(Text)

    scan: Mapped["Scan"] = relationship(back_populates="reasons")


class PasswordReset(Base):
    __tablename__ = "password_resets"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_naive_now)

class ThreatEntry(Base):
    __tablename__ = "threat_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    url_hash: Mapped[str] = mapped_column(String(64), index=True)
    url: Mapped[str] = mapped_column(Text)
    host: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(30), index=True)
    added_at: Mapped[datetime] = mapped_column(DateTime, default=_naive_now)


class DomainCache(Base):
    __tablename__ = "domain_cache"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    created_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=_naive_now)