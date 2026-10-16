from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import httpx
import asyncio
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

app = FastAPI()

# Dang - CORS configuration
origins = ["https://mail.google.com"]

app.add_middleware(
    CORSMiddleware,
    allow_origins= origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"message": "FoxWatch backend is running!"}

# Dang - Define the request model for URL scanning
class URLRequest(BaseModel):
    url: str

#store api key in .env (make sure .env in .gitignore)
class Settings(BaseSettings):
    VT_API_KEY: str

    # extra="ignore" so other lines in .env don't crash startup
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache()
def get_settings():
    return Settings()
VTApiKey = get_settings().VT_API_KEY

# Dang - VirusTotal API integration
url = "https://www.virustotal.com/api/v3/urls"


@app.post("/scan-url")
async def virustotal_scan(url_to_scan: URLRequest):
    headers = {"accept": "application/json", "x-apikey": VTApiKey}

    async with httpx.AsyncClient(timeout=30) as client:
        # 1. Submit the URL
        submit = await client.post(url, headers=headers, data={"url": url_to_scan.url})
        if submit.status_code != 200:
            return {"ok": False, "status_code": submit.status_code, "error": submit.text}

        analysis_id = submit.json()["data"]["id"]

        # 2. Poll for the verdict (VirusTotal can queue new URLs for a while)
        for _ in range(6):
            await asyncio.sleep(10)
            result = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers
            )
            if result.status_code != 200:
                return {"ok": False, "status_code": result.status_code, "error": result.text}

            attrs = result.json()["data"]["attributes"]
            if attrs["status"] == "completed":
                stats = attrs["stats"]
                return {
                    "ok": True,
                    "url": url_to_scan.url,
                    "malicious": stats["malicious"],
                    "suspicious": stats["suspicious"],
                    "harmless": stats["harmless"],
                    "undetected": stats["undetected"],
                }

        return {"ok": False, "error": "Analysis timed out"}

# Dang - uvicorn server configuration
if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)