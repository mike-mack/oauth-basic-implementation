from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import httpx
import secrets
import base64
from urllib.parse import urlencode, quote

app = FastAPI()

# Setup Templates and Static Files
# Equivalent to: app.set('views', 'files/client')
templates = Jinja2Templates(directory="files/client")
app.mount("/static", StaticFiles(directory="files/client"), name="static")

# Authorization server information
auth_server = {
    "authorization_endpoint": "http://localhost:9001/authorize",
    "token_endpoint": "http://localhost:9001/token"
}

# Client information
client = {
    "client_id": "oauth-client-1",
    "client_secret": "oauth-client-secret-1",
    "redirect_uris": ["http://localhost:9000/callback"]
}

protected_resource = "http://localhost:9002/resource"

# Global state (Note: In production, use a session/database instead)
state = None
access_token = None
scope = None

def encode_client_credentials(client_id: str, client_secret: str):
    """Replaces encodeClientCredentials helper"""
    credentials = f"{quote(client_id)}:{quote(client_secret)}"
    return base64.b64encode(credentials.encode()).decode()

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "access_token": access_token, 
        "scope": scope
    })

@app.get("/authorize")
async def authorize():
    """Send the user to the authorization server"""
    global state
    state = secrets.token_urlsafe(16)
    
    params = {
        "response_type": "code",
        "client_id": client["client_id"],
        "redirect_uri": client["redirect_uris"][0],
        "state": state
    }
    
    auth_url = f"{auth_server['authorization_endpoint']}?{urlencode(params)}"
    return RedirectResponse(auth_url)

@app.get("/callback")
async def callback(request: Request, code: str = None, error: str = None, state_in: str = None):
    """Parse the response and exchange code for a token"""
    global access_token, scope
    
    if error:
        raise HTTPException(status_code=400, detail=f"Auth error: {error}")
    
    # Simple state validation
    if state_in != state:
        raise HTTPException(status_code=400, detail="State mismatch")

    # Exchange code for token using httpx
    async with httpx.AsyncClient() as http_client:
        headers = {
            "Authorization": f"Basic {encode_client_credentials(client['client_id'], client['client_secret'])}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": client["redirect_uris"][0]
        }
        
        response = await http_client.post(auth_server["token_endpoint"], data=data, headers=headers)
        
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data.get("access_token")
            scope = token_data.get("scope")
            return RedirectResponse(url="/")
        else:
            raise HTTPException(status_code=response.status_code, detail="Could not fetch token")

@app.get("/fetch_resource")
async def fetch_resource():
    """Use the access token to call the resource server"""
    if not access_token:
        raise HTTPException(status_code=400, detail="No access token")

    async with httpx.AsyncClient() as http_client:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = await http_client.get(protected_resource, headers=headers)
        return response.json()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=9000)
