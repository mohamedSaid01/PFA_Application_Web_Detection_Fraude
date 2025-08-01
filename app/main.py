from fastapi import FastAPI
from app.database import engine, test_connection
from app.models.users.user import Base
from app.routers.auth import router as auth_router
from app.routers.users import router as users_router
from app.routers.logs import router as logs_router

# Créer toutes les tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Application Bancaire - Détection des Fraudes",
    description="API pour la gestion des utilisateurs et la détection automatique des transactions frauduleuses.",
    version="1.0.0"
)

# Inclure les routeurs
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(logs_router)

# Tester la connexion à la base de données
test_connection()

@app.get("/")
def read_root():
    return {"message": "Bienvenue dans notre application bancaire de détection des fraudes !"}