
from fastapi import FastAPI

app = FastAPI(
    title="VulnMap",
    description="Software Supply Chain Security Platform",
    version="0.1.0"
)

@app.get("/")
def home():
    return {
        "message": "Welcome to VulnMap!",
        "status": "running",
        "platform": "Software Supply Chain Security"
    }
