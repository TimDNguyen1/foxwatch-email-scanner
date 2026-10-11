from fastapi import FastAPI
import requests



app = FastAPI()

@app.get("/")
def home():
    return {"message": "FoxWatch backend is running!"}


# Dang - VirusTotal API integration
url = "https://www.virustotal.com/api/v3/urls"
VTApiKey = "f821ba9e12df3003de6f0b1c878bf5a52b05a67240d710adb1e7f2957a09ea5e"

def virustotal_scan(url_to_scan: str):
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
