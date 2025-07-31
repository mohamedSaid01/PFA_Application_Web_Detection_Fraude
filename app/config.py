import os
from datetime import timedelta

# Configuration JWT
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "votre_clé_secrète_par_défaut")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configuration SMTP
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "votre_email@gmail.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "votre_mot_de_passe")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Configuration DB
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_NAME = os.getenv("DB_NAME", "banque_db_pfa")
DB_PORT = int(os.getenv("DB_PORT", 3306))