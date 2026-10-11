from fastapi import FastAPI
import requests



app = FastAPI()

@app.get("/")
def home():
    return {"message": "FoxWatch backend is running!"}

url = "https://www.virustotal.com/api/v3/urls"

payload = {"url": "string"}
headers = {
    "accept": "application/json",
    "x-apikey": "f821ba9e12df3003de6f0b1c878bf5a52b05a67240d710adb1e7f2957a09ea5e",
    "content-type": "application/x-www-form-urlencoded"
}

respone = requests.post(url, data=payload, headers=headers)

print(respone.text)