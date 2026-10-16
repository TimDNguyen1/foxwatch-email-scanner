from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
import uvicorn
import httpx
import asyncio

# Dang - Load environment variables from .env file
class Settings(BaseSettings):
    VT_API_KEY: str

    model_config = SettingsConfigDict(env_file=".env")

@lru_cache()
def get_settings():
    # Dang - Print a message indicating that settings are being loaded from the .env file
    print("Loading settings from .env file...")

    return Settings()

app = FastAPI()

# Dang - CORS configuration
origins = [ "http://localhost",
            "https://localhost",
            "http://localhost:3000",
            "https://localhost:3000",
            "http://127.0.0.1",
            "https://127.0.0.1",
            "http://127.0.0.1:3000",
            "https://127.0.0.1:3000",
            "https://mail.google.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins= origins,
    allow_origin_regex=r"^(moz|chrome)-extension://.*$",
    allow_credentials=False,
    allow_methods= ["*"],
    allow_headers= ["*"],
)

@app.get("/")
def home():
    return {"message": "FoxWatch backend is running!"}

# Dang - Define the request model for URL scanning
class URLRequest(BaseModel):
    url: str

# Dang - VirusTotal API integration
url = "https://www.virustotal.com/api/v3/urls"
VTApiKey = get_settings().VT_API_KEY

@app.post("/scan-url")
async def virustotal_scan(url_to_scan: URLRequest):
    headers = {"accept": "application/json",
               "x-apikey": VTApiKey
                }

    async with httpx.AsyncClient(timeout=30) as client:
        payload = {"url": url_to_scan.url}
        # 1. Submit the URL
        submit = await client.post(url, data=payload, headers=headers)
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