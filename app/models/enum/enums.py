from enum import Enum

class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"

class AnalystDepartment(str, Enum):
    IT = "IT"
    FINANCE = "Finance"
    HR = "HR"
    MARKETING = "Marketing"