# pdns/routes/info.py
from fastapi import APIRouter, Request, Depends
from ..main import limiter, get_database
from ..default.helpers import logger, get_remote_address
from ..schemas import InfoResponse
from ..db.manager import DatabaseManager
from .. import __version__

router = APIRouter(prefix="/info", tags=["info"])


@router.get("", response_model=InfoResponse)
@limiter.limit("100/minute")
async def get_info(
    request: Request,
    db: DatabaseManager = Depends(get_database),
    auth=Depends(optional_auth),
):
    try:
        stats = await db.get_stats() or {}
        sensors = await db.get_sensors() or []
        rsensors = [
            {"sensor_id": sensor_id, "count": int(count)}
            for sensor_id, count in sensors
        ]
        response = {
            "version": __version__,
            "software": "analyzer-d4-passivedns",
            "stats": stats,
            "sensors": rsensors,
        }
        logger.info(
            {
                "endpoint": "/info",
                "client_ip": get_remote_address(request),
                "status": 200,
            }
        )
        return response
    except Exception as e:
        logger.error(
            {
                "endpoint": "/info",
                "client_ip": get_remote_address(request),
                "error": str(e),
            }
        )
        raise HTTPException(status_code=500, detail="Failed to retrieve info")
