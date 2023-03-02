from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from config import Settings

setting = Settings()

SQLALCHEMY_DB_URL = f"postgresql://{setting.database_user}:\
{setting.database_password}@{setting.database_host}/{setting.database_name}"

engine = create_engine(SQLALCHEMY_DB_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
