import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv
from services.azure_clients import (
    check_postgres,
    check_storage,
    check_keyvault,
    check_vm,
)

# Load environment variables
load_dotenv()

app = FastAPI(title="Azure DR Mock App")

# Setup templates
templates = Jinja2Templates(directory="templates")

# Configuration
KV_URL = os.getenv("AZURE_KEYVAULT_URL")
STORAGE_URL = os.getenv("AZURE_STORAGE_ACCOUNT_URL")
PG_CONN_STR = os.getenv("POSTGRES_CONNECTION_STRING")
CHECK_VM = os.getenv("CHECK_VM", "false").lower() == "true"
VM_HOST = os.getenv("AZURE_VM_HOST")


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/settings")
def get_settings():
    """
    Returns current application settings.
    """
    return {"check_vm": CHECK_VM, "vm_host": VM_HOST}


@app.get("/api/health")
def health_check():
    """
    Checks the health of all dependent Azure services.
    """
    postgres_result = (
        check_postgres(PG_CONN_STR)
        if PG_CONN_STR
        else {
            "status": "unknown",
            "message": "Not Configured",
            "resource_name": "Not configured",
        }
    )
    storage_result = (
        check_storage(STORAGE_URL)
        if STORAGE_URL
        else {
            "status": "unknown",
            "message": "Not Configured",
            "resource_name": "Not configured",
        }
    )
    keyvault_result = (
        check_keyvault(KV_URL)
        if KV_URL
        else {
            "status": "unknown",
            "message": "Not Configured",
            "resource_name": "Not configured",
        }
    )

    vm_result = None
    if CHECK_VM and VM_HOST:
        vm_result = check_vm(VM_HOST)
    elif CHECK_VM and not VM_HOST:
        vm_result = {
            "status": "unknown",
            "message": "Host not configured",
            "resource_name": "Not configured",
        }

    # Determine overall app health
    all_results = [postgres_result, storage_result, keyvault_result]
    if vm_result:
        all_results.append(vm_result)

    all_up = all(r["status"] == "up" for r in all_results if r["status"] != "unknown")

    response = {
        "postgres": postgres_result,
        "storage": storage_result,
        "keyvault": keyvault_result,
        "overall": "healthy" if all_up else "degraded",
    }

    if vm_result:
        response["vm"] = vm_result

    return response


@app.get("/api/resources")
def get_resources():
    """
    Returns the list of Azure resources configured for this project.
    """
    import re

    resources = []

    # PostgreSQL
    pg_name = "Not configured"
    pg_configured = False
    if PG_CONN_STR:
        pg_configured = True
        match = re.search(r"host=([^\s;]+)", PG_CONN_STR)
        if match:
            pg_name = match.group(1)
        else:
            match = re.search(r"@([^:/]+)", PG_CONN_STR)
            if match:
                pg_name = match.group(1)
    resources.append({"type": "postgres", "name": pg_name, "configured": pg_configured})

    # Storage
    storage_name = "Not configured"
    storage_configured = False
    if STORAGE_URL:
        storage_configured = True
        match = re.search(r"https://([^.]+)\.blob\.core\.windows\.net", STORAGE_URL)
        storage_name = match.group(1) if match else STORAGE_URL
    resources.append(
        {"type": "storage", "name": storage_name, "configured": storage_configured}
    )

    # Key Vault
    kv_name = "Not configured"
    kv_configured = False
    if KV_URL:
        kv_configured = True
        match = re.search(r"https://([^.]+)\.vault\.azure\.net", KV_URL)
        kv_name = match.group(1) if match else KV_URL
    resources.append({"type": "keyvault", "name": kv_name, "configured": kv_configured})

    # VM
    if CHECK_VM:
        vm_name = VM_HOST or "Not configured"
        if vm_name.startswith("/subscriptions/"):
            # Extract just the VM name from the Resource ID
            vm_name = vm_name.split("/")[-1]

        resources.append(
            {
                "type": "vm",
                "name": vm_name,
                "configured": bool(VM_HOST),
            }
        )

    return resources


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
