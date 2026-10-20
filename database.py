from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# The database is a single file called phishing.db in the project folder
DATABASE_URL = "sqlite:///./phishing.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    """Opens a database session for one request, and always closes it after."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()