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
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
import psycopg2
from ping3 import ping

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
        region, region_error = get_azure_region(
            simple_name, "Microsoft.DBforPostgreSQL/flexibleServers"
        )
        if region == "Unknown":
            # Fallback to searching by name only if type mismatch
            region, region_error = get_azure_region(simple_name)

        return {
            "status": "up",
            "latency_ms": round(latency, 2),
            "message": "Connected",
            "resource_name": resource_name,
            "region": region,
            "region_error": region_error,
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


def get_azure_region(
    resource_name: str, resource_type: str | None = None
) -> tuple[str, str | None]:
    """
    Dynamically fetches the Azure region for a resource using the Management SDK.
    Returns a tuple of (region, error_message).
    """
    cache_key = f"{resource_name}:{resource_type}" if resource_type else resource_name
    if cache_key in _cached_region:
        return _cached_region[cache_key], None

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
            return "Unknown", "No subscription ID found"

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
            if not raw_region:
                return "Unknown", "Region property is empty"

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
            return _cached_region[cache_key], None

        return "Unknown", "Resource not found"

    except Exception as e:
        logger.warning(f"Failed to fetch region for {resource_name}: {e}")
        return "Unknown", str(e)


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
        region, region_error = get_azure_region(
            resource_name, "Microsoft.Storage/storageAccounts"
        )

        return {
            "status": "up",
            "latency_ms": round(latency, 2),
            "message": "Connected",
            "resource_name": resource_name,
            "region": region,
            "region_error": region_error,
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

        region, region_error = get_azure_region(
            resource_name, "Microsoft.KeyVault/vaults"
        )

        return {
            "status": "up",
            "latency_ms": round(latency, 2),
            "message": "Connected",
            "resource_name": resource_name,
            "region": region,
            "region_error": region_error,
        }
    except Exception as e:
        logger.error(f"Key Vault check failed: {str(e)}")
        return {
            "status": "down",
            "latency_ms": 0,
            "message": str(e),
            "resource_name": resource_name,
        }


def resolve_vm_details(resource_id: str) -> tuple[str, str, str]:
    """
    Resolves VM private IP and region from a Resource ID.
    """
    try:
        # Parse Resource ID
        # /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}
        parts = resource_id.split("/")
        if len(parts) < 9:
            raise ValueError("Invalid Resource ID format")

        subscription_id = parts[2]
        resource_group = parts[4]
        vm_name = parts[8]

        credential = get_credential()

        # Get VM details
        compute_client = ComputeManagementClient(credential, subscription_id)
        vm = compute_client.virtual_machines.get(resource_group, vm_name)

        # Get Region
        raw_region = vm.location
        if not raw_region:
            region = "Unknown"
        else:
            formatted_region = raw_region.title()
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
            region = formatted_region.strip()

        # Get Network Interface
        profile = vm.network_profile
        if not profile or not profile.network_interfaces:
            raise ValueError("VM has no network interfaces")

        nic_id = profile.network_interfaces[0].id
        if not nic_id:
            raise ValueError("NIC ID is missing")
        nic_name = nic_id.split("/")[-1]

        network_client = NetworkManagementClient(credential, subscription_id)
        nic = network_client.network_interfaces.get(resource_group, nic_name)

        if not nic.ip_configurations:
            raise ValueError("NIC has no IP configurations")

        private_ip = nic.ip_configurations[0].private_ip_address
        if not private_ip:
            raise ValueError("NIC has no private IP")

        return private_ip, region, vm_name

    except Exception as e:
        logger.error(f"Failed to resolve VM details: {e}")
        raise


def check_vm(resource_id_or_host: str):
    """
    Checks connectivity to a VM using ICMP ping via ping3.
    Accepts either a hostname/IP or an Azure Resource ID.
    """
    start_time = time.time()
    host = resource_id_or_host
    region = "Unknown"
    region_error = None
    display_name = resource_id_or_host

    try:
        # If it looks like a Resource ID, resolve it
        if resource_id_or_host.startswith("/subscriptions/"):
            try:
                host, region, display_name = resolve_vm_details(resource_id_or_host)
            except Exception as e:
                return {
                    "status": "down",
                    "latency_ms": 0,
                    "message": f"Resolution failed: {str(e)}",
                    "resource_name": (
                        resource_id_or_host.split("/")[-1]
                        if "/" in resource_id_or_host
                        else resource_id_or_host
                    ),
                    "region": "Unknown",
                    "region_error": str(e),
                }

        # Try to fetch region if it looks like an Azure resource name (not an IP) and we haven't already
        if (
            region == "Unknown"
            and not host.replace(".", "").isdigit()
            and not host[0].isdigit()
        ):
            region, region_error = get_azure_region(
                host, "Microsoft.Compute/virtualMachines"
            )

        # ping returns delay in seconds, or None on timeout, or False on error
        delay_s = ping(host, timeout=2)

        if delay_s is not None and delay_s is not False:
            latency_ms = delay_s * 1000

            return {
                "status": "up",
                "latency_ms": round(latency_ms, 2),
                "message": "Connected",
                "resource_name": display_name,
                "region": region,
                "region_error": region_error,
            }
        else:
            return {
                "status": "down",
                "latency_ms": 0,
                "message": "Request timed out" if delay_s is None else "Ping failed",
                "resource_name": display_name,
                "region": region,
                "region_error": region_error,
            }
    except Exception as e:
        logger.error(f"VM check failed: {str(e)}")
        return {
            "status": "down",
            "latency_ms": 0,
            "message": str(e),
            "resource_name": display_name,
            "region": region,
            "region_error": region_error or str(e),
        }
