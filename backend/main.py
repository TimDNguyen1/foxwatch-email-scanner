from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import httpx
import os
import asyncio

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

# Dang - VirusTotal API integration
url = "https://www.virustotal.com/api/v3/urls"
VTApiKey = os.environ["VT_API_KEY"]

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
    uvicorn.run("main:app", host="localhost", port=3000, reload=True)