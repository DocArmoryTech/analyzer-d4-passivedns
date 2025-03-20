# pdns/routes/info.py
from fastapi import APIRouter, Request, Depends
from ..main import limiter, get_database
from ..default.helpers import logger, get_remote_address
from ..schemas import InfoResponse
from ..db.base import Database

router = APIRouter(prefix="/info", tags=["info"])

@router.get("", response_model=InfoResponse)
@limiter.limit("100/minute")
async def get_info(request: Request, db: Database = Depends(get_database), auth=Depends(optional_auth)):
    stats = await db.get_stats()
    sensors = await db.get_sensors()
    rsensors = [{"sensor_id": sensor_id, "count": int(count)} for sensor_id, count in sensors]
    response = {"version": "git", "software": "analyzer-d4-passivedns", "stats": stats, "sensors": rsensors}
    logger.info({"endpoint": "/info", "client_ip": get_remote_address(request), "status": 200})
    return response