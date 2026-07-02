from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from jose import jwt, JWTError, ExpiredSignatureError
import logging

# ── Assignment constants ────────────────────────────────────────────────────
ISSUER   = "https://idp.exam.local"
AUDIENCE = "tds-vhy5lzec.apps.exam.local"
ALGORITHM = "RS256"

# IdP public key (RS256) – provided verbatim by the assignment
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

# ── App setup ───────────────────────────────────────────────────────────────
app = FastAPI(title="OAuth JWT Verifier")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TokenRequest(BaseModel):
    token: str


@app.post("/verify")
async def verify_token(body: TokenRequest):
    """
    Validates a JWT and returns structured claims or 401.

    Checks:
      - RS256 signature against the IdP public key
      - iss == https://idp.exam.local
      - aud == tds-vhy5lzec.apps.exam.local
      - exp is in the future
    """
    try:
        claims = jwt.decode(
            body.token,
            PUBLIC_KEY,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )

        logger.info("Token valid for sub=%s", claims.get("sub"))

        return JSONResponse(
            status_code=200,
            content={
                "valid": True,
                "email": claims.get("email", ""),
                "sub":   claims.get("sub", ""),
                "aud":   claims.get("aud", ""),
            },
        )

    except ExpiredSignatureError:
        logger.warning("Token rejected: expired")
        return JSONResponse(status_code=401, content={"valid": False})

    except JWTError as exc:
        logger.warning("Token rejected: %s", str(exc))
        return JSONResponse(status_code=401, content={"valid": False})

    except Exception as exc:
        logger.error("Unexpected error: %s", str(exc))
        return JSONResponse(status_code=401, content={"valid": False})


@app.get("/")
async def health():
    return {"status": "ok", "service": "oauth-verifier"}
