from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# -------------------------
#  CORS EINSTELLUNGEN
#  Damit dein Frontend mit Backend sprechen darf
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # erlaubt alle Frontends
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
#  TEST-ROUTE (läuft!)
# -------------------------
@app.get("/status")
def status():
    return {"message": "Safety360 Backend läuft!"}


# -------------------------
#  DATEI-UPLOAD (NEU)
# -------------------------
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    content = await file.read()
    file_size = len(content)

    return {
        "filename": file.filename,
        "size": file_size,
        "message": "Datei erfolgreich empfangen!"
    }
