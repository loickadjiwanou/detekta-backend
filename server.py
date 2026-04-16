from dotenv import load_dotenv
from pathlib import Path

# Load environment variables FIRST
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
import os
import logging

from app.database import connect_to_database, close_database_connection
from app.routers import auth_router, users_router, audits_router, reports_router, websocket_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Detekta API",
    description="Automated Security Audit Platform - See every flaw. Fix every risk.",
    version="1.0.0"
)

# CORS Configuration
allowed_origins = os.environ.get('CORS_ORIGINS', '*').split(',')
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers with /api prefix
app.include_router(auth_router, prefix="/api")
app.include_router(users_router, prefix="/api")
app.include_router(audits_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(websocket_router, prefix="/api")

@app.on_event("startup")
async def startup_event():
    """Initialize database connection and seed admin."""
    logger.info("Starting Detekta API...")
    db = await connect_to_database()
    logger.info("Detekta API started successfully")

@app.on_event("shutdown")
async def shutdown_event():
    """Close database connection."""
    logger.info("Shutting down Detekta API...")
    await close_database_connection()

@app.get("/")
async def root_redirect():
    """Welcome message for the root URL."""
    return {
        "message": "Welcome to Detekta API",
        "documentation": "/docs",
        "status": "operational"
    }

@app.get("/api/")
async def root():
    """Health check endpoint."""
    return {
        "message": "Detekta API",
        "version": "1.0.0",
        "status": "operational"
    }

@app.get("/api/health")
async def health_check():
    """Detailed health check."""
    return {
        "status": "healthy",
        "service": "detekta-api",
        "version": "1.0.0"
    }
