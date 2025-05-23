# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This NetBox module is part of the OSISM Container Image Inventory Reconciler. It integrates with NetBox API to generate Ansible inventory files and dnsmasq configurations based on device information stored in NetBox.

## Architecture

### Core Components

1. **main.py** - Entry point that orchestrates the inventory generation process
2. **config.py** - Configuration management using dynaconf for environment variables
3. **netbox_client.py** - NetBox API client wrapper using pynetbox
4. **inventory_manager.py** - Manages inventory file generation and writing
5. **device_mapping.py** - Maps devices to Ansible inventory groups based on roles
6. **data_extractor.py** - Extracts various data types from NetBox devices
7. **dnsmasq_manager.py** - Generates dnsmasq DHCP configurations
8. **utils.py** - Logging utilities

### Key Data Flow

1. Configuration loaded from environment variables via dynaconf
2. NetBox client connects and fetches devices with specific tags
3. Devices filtered by maintenance status and provision state
4. Device data extracted (config_context, primary_ip, custom fields)
5. Devices mapped to inventory groups based on roles
6. Inventory files written to `/inventory.pre/`
7. Dnsmasq configurations generated for OOB management

## Environment Variables

- `NETBOX_API` - NetBox API URL (required)
- `NETBOX_TOKEN` - Authentication token (via env or `/run/secrets/NETBOX_TOKEN`)
- `NETBOX_DATA_TYPES` - Comma-separated data types to extract (default: "primary_ip,config_context")
- `NETBOX_IGNORED_ROLES` - Device roles to skip (default: "housing,pdu,other,oob")
- `NETBOX_ROLE_MAPPING` - JSON mapping of device roles to inventory groups
- `IGNORE_SSL_ERRORS` - Skip SSL verification (default: true)
- `INVENTORY_PATH` - Output path for inventory files (default: "/inventory.pre")

## Device Selection Logic

### Devices are selected if:
- Tagged with "managed-by-osism" AND status is "active"
- NOT in maintenance mode (custom field)
- For devices also tagged with "managed-by-ironic": provision_state must be "active"

### Role Mapping
Devices are assigned to Ansible groups based on their NetBox role:
- Default: devices go to "generic" group
- Custom mapping via NETBOX_ROLE_MAPPING environment variable
- Example: `{"compute": ["compute", "generic"], "storage": ["storage", "ceph"]}`

## Output Files

### Inventory Structure
- `/inventory.pre/20-netbox` - Main inventory file with host groups
- `/inventory.pre/host_vars/{device}/` - Per-device configuration
  - `999-netbox-config-context.yml` - Device config context
  - `999-netbox-ansible.yml` - Ansible connection info (ansible_host)
  - `999-netbox-netplan.yml` - Netplan parameters (if configured)
  - `999-netbox-frr.yml` - FRR parameters (if configured)

### Dnsmasq Files
- `/inventory.pre/group_vars/manager/999-netbox-dnsmasq.yml` - OOB device configurations
- `/inventory.pre/group_vars/manager/999-netbox-dnsmasq-dhcp-range.yml` - DHCP ranges

## Common Development Tasks

### Running the Module
```bash
python main.py
```

### Required Dependencies
- pynetbox - NetBox API client
- loguru - Logging framework  
- dynaconf - Configuration management
- jinja2 - Template engine
- pyyaml - YAML processing

### Adding New Data Types
1. Add extraction method to `DeviceDataExtractor` class
2. Update `extract_all_data()` method
3. Add file suffix mapping in `InventoryManager._write_data_to_file()`
4. Update NETBOX_DATA_TYPES environment variable documentation

### Debugging
- Set `LOGURU_LEVEL=DEBUG` for verbose logging
- Check NetBox connection with retry logic in `netbox_client.py`
- Verify device tags and custom fields match expected values