# Developer Agent Guide for octoDNS Azure Provider

This repository contains the Azure provider for octoDNS. It enables planning, syncing, and applying DNS record states to Azure DNS Zones and configuring dynamic routing profiles via Azure Traffic Manager.

> [!IMPORTANT]
> **Core Workflow and Guidelines**
>
> All agents working on this repository must read and follow the general instructions and workflow guidelines defined in the core octoDNS `AGENTS.md` file.
> - **Local check**: Look for the file at `../octodns/AGENTS.md`.
> - **Remote check**: If the local file is not available, fetch it from GitHub: [octoDNS Core AGENTS.md](https://github.com/octodns/octodns/raw/refs/heads/main/AGENTS.md).
>
> You must align your code structure, style, pull request guidelines, and overall development workflows with the instructions specified there.

## Repository & Module Information

### Key Components

- **Provider Class**: [AzureProvider](file:///home/ross/octodns/octodns-azure/octodns_azure/__init__.py) (defined in [octodns_azure/__init__.py](file:///home/ross/octodns/octodns-azure/octodns_azure/__init__.py)). This is the core provider communicating with Azure Resource Manager APIs using SDK clients:
  - `DnsManagementClient`: For standard public DNS Zones.
  - `PrivateDnsManagementClient`: For Azure Private DNS Zones.
  - `TrafficManagerManagementClient`: For routing dynamic profiles.
- **Authentication**: Authentication is handled through `azure-identity`. It supports client secret credential authentication (`ClientSecretCredential`) or developer login credential authentication (`AzureCliCredential`).
- **Private Zone Support**: Plans and syncs to private zones when the `private` config option is enabled.

### Key Workflows & Features

1. **Supported Record Types**: `A`, `AAAA`, `CAA`, `CNAME`, `MX`, `NS`, `PTR`, `SRV`, `TXT`.
2. **Dynamic Routing Support**: Fully supported (`SUPPORTS_DYNAMIC=True`, `SUPPORTS_GEO=True`) via integration with Azure Traffic Manager (ATM):
   - Geolocation routing (geographic mappings mapping back to ATM geographic endpoints).
   - Priority routing.
   - Weighted routing.
   - Subnet-based routing (`SUPPORTS_DYNAMIC_SUBNETS=True`).
   - Endpoint health monitoring (configurable interval, protocol, port, path, tolerated failures, and timeout).
3. **Pool Value Status**: Supported (`SUPPORTS_POOL_VALUE_STATUS=True`).

## Development & Testing

- **Setup Script**: Run `./script/bootstrap` to create a virtual environment, install runtime and development dependencies (including `black`, `isort`, `pyflakes`, and `pytest`), and configure pre-commit hooks.
- **Test Suite**: Run unit tests using `pytest` via `./script/test` (or `pytest tests/`). Test files are located in [tests/](file:///home/ross/octodns/octodns-azure/tests).
- **Code Coverage**: Verify code coverage using `./script/coverage`.

## Key Constraints & Behaviors

- **Python Version**: Targets Python `>=3.9`.
- **Formatting**: Code formatting is enforced via `black` (version `>=26.0.0,<27.0.0`) and `isort`.
