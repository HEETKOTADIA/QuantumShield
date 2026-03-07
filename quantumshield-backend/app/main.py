from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    status_router,
    kemtls_router,
    oidc_router,
    benchmark_router,
    scanner_router,
    crypto_router,
)

app = FastAPI(
    title="QuantumShield",
    description="Post-Quantum Secure OpenID Connect using KEMTLS",
    version="1.0.0",
)

# Disable CORS. Do not remove this for full-stack development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Include routers
app.include_router(status_router)
app.include_router(kemtls_router)
app.include_router(oidc_router)
app.include_router(benchmark_router)
app.include_router(scanner_router)
app.include_router(crypto_router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
