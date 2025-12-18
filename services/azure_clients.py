import time
import logging
import os
from azure.identity import (
    AzureCliCredential,
    ChainedTokenCredential,
    ManagedIdentityCredential,
)
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
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

        # Extract simple name for Azure lookup (e.g. 'ubsmock' from 'ubsmock.postgres.database.azure.com')
        simple_name = resource_name.split(".")[0]
        region = get_azure_region(
            simple_name, "Microsoft.DBforPostgreSQL/flexibleServers"
        )
        if region == "Unknown":
            # Fallback to searching by name only if type mismatch
            region = get_azure_region(simple_name)

        return {
            "status": "up",
            "latency_ms": round(latency, 2),
            "message": "Connected",
            "resource_name": resource_name,
            "region": region,
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
_cached_region = {}


def get_azure_region(resource_name: str, resource_type: str = None) -> str:
    """
    Dynamically fetches the Azure region for a resource using the Management SDK.
    """
    cache_key = f"{resource_name}:{resource_type}" if resource_type else resource_name
    if cache_key in _cached_region:
        return _cached_region[cache_key]

    try:
        credential = get_credential()

        # 1. Get Subscription ID (if not in env)
        subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
        if not subscription_id:
            sub_client = SubscriptionClient(credential)
            # Use the first subscription found
            for sub in sub_client.subscriptions.list():
                subscription_id = sub.subscription_id
                break

        if not subscription_id:
            logger.warning("No subscription ID found, cannot fetch region.")
            return "Unknown"

        # 2. Find the resource
        resource_client = ResourceManagementClient(credential, subscription_id)
        # Filter by name and optionally type
        query = f"name eq '{resource_name}'"
        if resource_type:
            query += f" and resourceType eq '{resource_type}'"

        resources = list(resource_client.resources.list(filter=query))

        if resources:
            # Azure returns region like 'switzerlandnorth', we format it nicely
            raw_region = resources[0].location
            # Simple formatting: 'switzerlandnorth' -> 'Switzerland North'
            # This is a heuristic, for perfect mapping we'd need a lookup table
            formatted_region = raw_region.title()
            # Handle common cases where spaces are missing in the raw value
            if "north" in raw_region:
                formatted_region = formatted_region.replace("north", " North")
            if "west" in raw_region:
                formatted_region = formatted_region.replace("west", " West")
            if "east" in raw_region:
                formatted_region = formatted_region.replace("east", " East")
            if "south" in raw_region:
                formatted_region = formatted_region.replace("south", " South")
            if "central" in raw_region:
                formatted_region = formatted_region.replace("central", " Central")

            _cached_region[cache_key] = formatted_region.strip()
            return _cached_region[cache_key]

    except Exception as e:
        logger.warning(f"Failed to fetch region for {resource_name}: {e}")

    return "Unknown"


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
        info = _cached_blob_client.get_account_information()
        latency = (time.time() - start_time) * 1000

        # Dynamically fetch region
        region = get_azure_region(resource_name, "Microsoft.Storage/storageAccounts")

        return {
            "status": "up",
            "latency_ms": round(latency, 2),
            "message": "Connected",
            "resource_name": resource_name,
            "region": region,
            "sku": info.get("sku_name"),
            "kind": info.get("account_kind"),
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

        region = get_azure_region(resource_name, "Microsoft.KeyVault/vaults")

        return {
            "status": "up",
            "latency_ms": round(latency, 2),
            "message": "Connected",
            "resource_name": resource_name,
            "region": region,
        }
    except Exception as e:
        logger.error(f"Key Vault check failed: {str(e)}")
        return {
            "status": "down",
            "latency_ms": 0,
            "message": str(e),
            "resource_name": resource_name,
        }


def check_vm(host: str):
    """
    Checks connectivity to a VM using ICMP ping.
    """
    import subprocess
    import platform

    start_time = time.time()
    try:
        # Determine ping command based on OS
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "1", host]

        # Run ping command
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2
        )

        if result.returncode == 0:
            latency = (time.time() - start_time) * 1000

            # Try to fetch region if it looks like an Azure resource name (not an IP)
            region = "Unknown"
            if not host.replace(".", "").isdigit():
                region = get_azure_region(host, "Microsoft.Compute/virtualMachines")

            return {
                "status": "up",
                "latency_ms": round(latency, 2),
                "message": "Connected",
                "resource_name": host,
                "region": region,
            }
        else:
            return {
                "status": "down",
                "latency_ms": 0,
                "message": "Ping failed",
                "resource_name": host,
            }
    except Exception as e:
        logger.error(f"VM check failed: {str(e)}")
        return {
            "status": "down",
            "latency_ms": 0,
            "message": str(e),
            "resource_name": host,
        }
