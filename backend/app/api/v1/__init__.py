from fastapi import APIRouter
from app.api.v1.auth import router as auth_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.flows import router as flows_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.quarantine import router as quarantine_router
from app.api.v1.simulation import router as simulation_router
from app.api.v1.dbms import router as dbms_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(dashboard_router)
api_router.include_router(flows_router)
api_router.include_router(alerts_router)
api_router.include_router(quarantine_router)
api_router.include_router(simulation_router)
api_router.include_router(dbms_router)

__all__ = ["api_router"]
