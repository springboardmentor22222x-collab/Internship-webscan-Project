from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
from fastapi.responses import FileResponse, Response

from modules.crawler import WebCrawler
from modules.scanner import VulnerabilityScanner
from modules.ai_engine import AIVulnerabilityEngine
from modules.report_generator import ReportGenerator

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class ScanConfig(BaseModel):
    enable_sqli: bool = True
    enable_xss: bool = True
    enable_auth: bool = True
    enable_idor: bool = True
    enable_ai: bool = False

class ScanRequest(BaseModel):
    target_url: str
    config: ScanConfig

class VulnerabilityModel(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: str
    endpoint: str
    severity: str
    description: str
    evidence: str
    mitigation: str
    payload: Optional[str] = None

class ScanResultModel(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str
    status: str
    progress: int
    vulnerabilities: List[VulnerabilityModel]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    config: ScanConfig
    total_pages: int = 0
    scan_duration: Optional[float] = None

scans_storage = {}

@api_router.get("/")
async def root():
    return {"message": "WebScanPro API"}

@api_router.post("/scan/start")
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    
    scan_result = ScanResultModel(
        id=scan_id,
        target_url=scan_request.target_url,
        status="running",
        progress=0,
        vulnerabilities=[],
        config=scan_request.config
    )
    
    scans_storage[scan_id] = scan_result.model_dump()
    
    doc = scan_result.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.scans.insert_one(doc)
    
    background_tasks.add_task(perform_scan, scan_id, scan_request)
    
    return {"scan_id": scan_id, "status": "started"}

async def perform_scan(scan_id: str, scan_request: ScanRequest):
    import time
    start_time = time.time()
    
    try:
        crawler = WebCrawler(scan_request.target_url)
        scans_storage[scan_id]['progress'] = 10
        scans_storage[scan_id]['status'] = 'crawling'
        
        pages = await crawler.crawl()
        scans_storage[scan_id]['progress'] = 30
        scans_storage[scan_id]['total_pages'] = len(pages)
        
        scanner = VulnerabilityScanner(scan_request.config)
        scans_storage[scan_id]['status'] = 'scanning'
        scans_storage[scan_id]['progress'] = 40
        
        vulnerabilities = await scanner.scan(pages)
        scans_storage[scan_id]['progress'] = 70
        
        if scan_request.config.enable_ai:
            ai_engine = AIVulnerabilityEngine()
            scans_storage[scan_id]['status'] = 'ai_analysis'
            scans_storage[scan_id]['progress'] = 80
            
            enhanced_vulns = await ai_engine.analyze(vulnerabilities, pages)
            vulnerabilities = enhanced_vulns
        
        scans_storage[scan_id]['vulnerabilities'] = [v.model_dump() for v in vulnerabilities]
        scans_storage[scan_id]['progress'] = 100
        scans_storage[scan_id]['status'] = 'completed'
        scans_storage[scan_id]['scan_duration'] = time.time() - start_time
        
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": scans_storage[scan_id]}
        )
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        scans_storage[scan_id]['status'] = 'failed'
        scans_storage[scan_id]['error'] = str(e)
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"status": "failed", "error": str(e)}}
        )

@api_router.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    if scan_id in scans_storage:
        return scans_storage[scan_id]
    
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if scan:
        return scan
    
    raise HTTPException(status_code=404, detail="Scan not found")

@api_router.get("/scans")
async def get_all_scans():
    scans = await db.scans.find({}, {"_id": 0}).sort("timestamp", -1).to_list(100)
    return scans

@api_router.post("/report/generate/{scan_id}")
async def generate_report(scan_id: str, format: str = "pdf"):
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    generator = ReportGenerator()
    
    if format == "pdf":
        report_path = await generator.generate_pdf(scan)
        return FileResponse(
            report_path,
            media_type="application/pdf",
            filename=f"scan_report_{scan_id}.pdf"
        )
    elif format == "html":
        html_content = await generator.generate_html(scan)
        return Response(content=html_content, media_type="text/html")
    else:
        raise HTTPException(status_code=400, detail="Invalid format")

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()