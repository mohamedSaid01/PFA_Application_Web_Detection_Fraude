from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(50), nullable=False)  # Specify length, e.g., 50
    description = Column(String(255), nullable=True)  # Specify length, e.g., 255
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="logs")