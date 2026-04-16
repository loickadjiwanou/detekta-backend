from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings

client: AsyncIOMotorClient = None
db = None

async def connect_to_database():
    global client, db
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.MONGODB_DB_NAME]
    
    # Create indexes
    await db.users.create_index("email", unique=True)
    await db.audits.create_index("user_id")
    await db.audits.create_index("status")
    await db.reports.create_index("audit_id", unique=True)
    await db.reports.create_index("user_id")
    await db.usage_logs.create_index("user_id")
    await db.login_attempts.create_index("identifier")
    await db.password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)
    
    return db

async def close_database_connection():
    global client
    if client:
        client.close()

def get_database():
    return db
