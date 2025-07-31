from sqlalchemy import Column, Integer, String, Enum
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.enum.enums import Role, AnalystDepartment

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=True)  # Nullable pour les utilisateurs créés sans mot de passe
    firstName = Column(String, nullable=False)
    lastName = Column(String, nullable=False)
    phoneNumber = Column(String, nullable=True)
    department = Column(Enum(AnalystDepartment), nullable=False)
    role = Column(Enum(Role), default=Role.ANALYST, nullable=False)

    # Relation utilisant le nom de classe en string pour éviter l'import circulaire
    reset_tokens = relationship("ResetToken", back_populates="user")