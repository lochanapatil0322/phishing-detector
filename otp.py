import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

import models
from auth import SECRET_KEY, hash_password

OTP_MINUTES = 10
MAX_ATTEMPTS = 5
RESEND_SECONDS = 60


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _hash_code(email: str, code: str) -> str:
    """Keyed hash: the database never stores the code itself."""
    return hmac.new(SECRET_KEY.encode(), f"{email}:{code}".encode(), hashlib.sha256).hexdigest()


def create_reset_code(db: Session, user: models.User):
    """Returns a fresh 6-digit code, or None if the user asked too recently."""
    last = (
        db.query(models.PasswordReset)
        .filter(models.PasswordReset.user_id == user.id)
        .order_by(models.PasswordReset.id.desc())
        .first()
    )
    if last and (_now() - last.created_at).total_seconds() < RESEND_SECONDS:
        return None

    # Cancel any older unused codes
    db.query(models.PasswordReset).filter(
        models.PasswordReset.user_id == user.id,
        models.PasswordReset.used.is_(False),
    ).update({"used": True})

    code = f"{secrets.randbelow(1_000_000):06d}"
    db.add(
        models.PasswordReset(
            user_id=user.id,
            code_hash=_hash_code(user.email, code),
            expires_at=_now() + timedelta(minutes=OTP_MINUTES),
        )
    )
    db.commit()
    return code


def reset_password_with_code(db: Session, email: str, code: str, new_password: str) -> bool:
    """True if the code was right and the password was changed."""
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return False

    record = (
        db.query(models.PasswordReset)
        .filter(models.PasswordReset.user_id == user.id, models.PasswordReset.used.is_(False))
        .order_by(models.PasswordReset.id.desc())
        .first()
    )
    if not record:
        return False

    if record.expires_at < _now() or record.attempts >= MAX_ATTEMPTS:
        record.used = True
        db.commit()
        return False

    record.attempts += 1
    if not hmac.compare_digest(record.code_hash, _hash_code(email, code)):
        if record.attempts >= MAX_ATTEMPTS:
            record.used = True          # too many wrong guesses: code is dead
        db.commit()
        return False

    record.used = True                  # single use
    user.password_hash = hash_password(new_password)
    db.commit()
    return True