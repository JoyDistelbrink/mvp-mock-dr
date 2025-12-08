import time
import logging
from azure.identity import (
    AzureCliCredential,
    ChainedTokenCredential,
    ManagedIdentityCredential,
)
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient
import psycopg2

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Cache the credential to avoid re-authenticating on every request
_cached_credential = None


def get_credential():
    """
    Returns a cached Azure credential.
    Uses AzureCliCredential first (fast for local dev), then ManagedIdentity (for Azure).
    This avoids the slow DefaultAzureCredential chain that tries multiple methods.
    """
    global _cached_credential
    if _cached_credential is None:
        _cached_credential = ChainedTokenCredential(
            AzureCliCredential(),
            ManagedIdentityCredential(),
        )
    return _cached_credential


def extract_postgres_host(connection_string: str) -> str:
    """Extract host from postgres connection string."""
    import re

    # Try to match host= pattern
    match = re.search(r"host=([^\s;]+)", connection_string)
    if match:
        return match.group(1)
    # Try postgresql:// URL format
    match = re.search(r"@([^:/]+)", connection_string)
    if match:
        return match.group(1)
    return "PostgreSQL"


def check_postgres(connection_string: str):
    """
    Checks connectivity to PostgreSQL using a connection string.
    Returns a dict with status and latency/error.
    """
    resource_name = extract_postgres_host(connection_string)
    start_time = time.time()
    try:
        # Connect with a short timeout to fail fast during DR tests
        conn = psycopg2.connect(connection_string, connect_timeout=3)
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()
        latency = (time.time() - start_time) * 1000
        return {
            "status": "up",
            "latency_ms": round(latency, 2),
            "message": "Connected",
            "resource_name": resource_name,
        }
    except Exception as e:
        logger.error(f"Postgres check failed: {str(e)}")
        return {
            "status": "down",
            "latency_ms": 0,
            "message": str(e),
            "resource_name": resource_name,
        }


# Cache clients to avoid recreating on every request
_cached_blob_client = None
_cached_keyvault_client = None


def extract_storage_account_name(account_url: str) -> str:
    """Extract storage account name from URL."""
    import re

    match = re.search(r"https://([^.]+)\.blob\.core\.windows\.net", account_url)
    if match:
        return match.group(1)
    return account_url


def check_storage(account_url: str):
    """
    Checks connectivity to Azure Blob Storage using Managed Identity.
    """
    global _cached_blob_client
    resource_name = extract_storage_account_name(account_url)
    start_time = time.time()
    try:
        # Reuse cached client if URL matches
        if (
            _cached_blob_client is None
            or _cached_blob_client.account_name not in account_url
        ):
            credential = get_credential()
            _cached_blob_client = BlobServiceClient(
                account_url=account_url,
                credential=credential,
                connection_timeout=5,
                read_timeout=5,
            )
        # Use get_account_information() - single lightweight API call
        _cached_blob_client.get_account_information()
        latency = (time.time() - start_time) * 1000
        return {
            "status": "up",
            "latency_ms": round(latency, 2),
            "message": "Connected",
            "resource_name": resource_name,
        }
    except Exception as e:
        logger.error(f"Storage check failed: {str(e)}")
        return {
            "status": "down",
            "latency_ms": 0,
            "message": str(e),
            "resource_name": resource_name,
        }


def extract_keyvault_name(vault_url: str) -> str:
    """Extract key vault name from URL."""
    import re

    match = re.search(r"https://([^.]+)\.vault\.azure\.net", vault_url)
    if match:
        return match.group(1)
    return vault_url


def check_keyvault(vault_url: str):
    """
    Checks connectivity to Azure Key Vault using Managed Identity.
    """
    global _cached_keyvault_client
    resource_name = extract_keyvault_name(vault_url)
    start_time = time.time()
    try:
        # Reuse cached client if URL matches
        if (
            _cached_keyvault_client is None
            or vault_url not in _cached_keyvault_client.vault_url
        ):
            credential = get_credential()
            _cached_keyvault_client = SecretClient(
                vault_url=vault_url,
                credential=credential,
            )
        for _ in _cached_keyvault_client.list_properties_of_secrets():
            break
        latency = (time.time() - start_time) * 1000
        return {
            "status": "up",
            "latency_ms": round(latency, 2),
            "message": "Connected",
            "resource_name": resource_name,
        }
    except Exception as e:
        logger.error(f"Key Vault check failed: {str(e)}")
        return {
            "status": "down",
            "latency_ms": 0,
            "message": str(e),
            "resource_name": resource_name,
        }
