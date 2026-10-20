from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    input_type: Mapped[str] = mapped_column(String(10), default="url")
    input_text: Mapped[str] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(String(20))
    score: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )

    reasons: Mapped[list["ScanReason"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScanReason(Base):
    __tablename__ = "scan_reasons"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    reason_text: Mapped[str] = mapped_column(Text)

    scan: Mapped["Scan"] = relationship(back_populates="reasons")