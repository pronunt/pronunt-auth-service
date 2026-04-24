from fastapi import FastAPI

app = FastAPI(title="pronunt-auth-service")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

