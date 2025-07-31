from pydantic import BaseModel, EmailStr, validator
from typing import Optional
from app.models.enum.enums import Role, AnalystDepartment

class UserBase(BaseModel):
    email: EmailStr
    firstName: str
    lastName: str
    phoneNumber: Optional[str] = None
    department: AnalystDepartment
    role: Role = Role.ANALYST

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    phoneNumber: Optional[str] = None
    department: Optional[AnalystDepartment] = None
    role: Optional[Role] = None

class UserAdminCreate(BaseModel):
    email: EmailStr
    firstName: str
    lastName: str
    phoneNumber: Optional[str] = None
    department: AnalystDepartment
    role: Role = Role.ANALYST

class UserUpdateProfil(BaseModel):
    email: Optional[EmailStr] = None
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    phoneNumber: Optional[str] = None
    department: Optional[AnalystDepartment] = None

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
    confirm_new_password: str

    @validator("confirm_new_password")
    def passwords_match(cls, v, values, **kwargs):
        if "new_password" in values and v != values["new_password"]:
            raise ValueError("La confirmation du mot de passe ne correspond pas")
        return v

class ResetPassword(BaseModel):
    token: str
    new_password: str
    confirm_new_password: str

    @validator("confirm_new_password")
    def passwords_match(cls, v, values, **kwargs):
        if "new_password" in values and v != values["new_password"]:
            raise ValueError("La confirmation du mot de passe ne correspond pas")
        return v

class UserResponse(UserBase):
    id: int

    class Config:
        from_attributes = True