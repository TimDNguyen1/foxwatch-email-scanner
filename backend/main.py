from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import httpx

app = FastAPI()

# Dang - Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Dang - Allow all origins for testing purposes, needs to be replaced with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dang - Define the request model for URL scanning
class URLRequest(BaseModel):
    url: str

@app.get("/")
def home():
    return {"message": "FoxWatch backend is running!"}



# Dang - VirusTotal API integration
url = "https://www.virustotal.com/api/v3/urls"
VTApiKey = "f821ba9e12df3003de6f0b1c878bf5a52b05a67240d710adb1e7f2957a09ea5e"

@app.post("/scan-url")
async def virustotal_scan(url_to_scan: URLRequest):
    payload = {"url": url_to_scan}
    headers = {
        "accept": "application/json",
        "x-apikey": VTApiKey,
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=payload, headers=headers)

    if response.status_code == 200:
        return {"message": "Request successful!", "data": response.json()}
    else:
        return {"message": "Request failed", "status_code": response.status_code, "error": response.text}
