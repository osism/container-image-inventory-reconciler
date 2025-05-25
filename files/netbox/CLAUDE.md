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
- `NETBOX_DATA_TYPES` - Comma-separated data types to extract (default: "primary_ip,config_context,netplan_parameters")
- `NETBOX_IGNORED_ROLES` - Device roles to skip (default: "housing,pdu,other,oob")
- `NETBOX_ROLE_MAPPING` - JSON mapping of device roles to inventory groups
- `NETBOX_FILTER_INVENTORY` - JSON filter for device selection (default: `{"status": "active", "tag": "managed-by-osism"}`)
- `IGNORE_SSL_ERRORS` - Skip SSL verification (default: true)
- `INVENTORY_PATH` - Output path for inventory files (default: "/inventory.pre")
- `DEFAULT_MTU` - Default MTU value for interfaces without explicit MTU (default: 9100)
- `DEFAULT_LOCAL_AS_PREFIX` - Default local AS prefix for FRR configuration (default: 42)
- `INVENTORY_RECONCILER_MODE` - Operating mode for the reconciler: "manager" or "metalbox" (default: "manager")

## Device Selection Logic

### Devices are selected if:
- They match the filter criteria specified in `NETBOX_FILTER_INVENTORY` (default: status="active" AND tag="managed-by-osism")
- NOT in maintenance mode (custom field)
- For devices also tagged with "managed-by-ironic": provision_state must be "active"

### Custom Filter Examples
- Single filter (dictionary): `{"status": "active", "tag": "managed-by-osism", "device_type": "server"}`
- Filter by site: `{"status": "active", "tag": "managed-by-osism", "site": "datacenter-1"}`
- Filter by multiple tags: `{"status": "active", "tag": ["managed-by-osism", "production"]}`
- Multiple filters (list of dictionaries): `[{"status": "active", "tag": "managed-by-osism", "site": "dc1"}, {"status": "active", "tag": "managed-by-osism", "site": "dc2"}]`
  - When using a list, devices matching ANY filter will be included (OR operation)
  - Duplicate devices are automatically removed

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

### Netplan Configuration
The `999-netbox-netplan.yml` file contains netplan_parameters which can be:
- **Manual configuration**: If the `netplan_parameters` custom field is set on the device, its content is used directly
- **Automatic generation**: If no manual configuration exists, netplan_parameters are automatically generated from:
  - **Interface Requirements**: All interfaces must have the `managed-by-osism` tag to be included
  - **Regular interfaces**: Interfaces with the tag, a MAC address AND a label
    - The label becomes the interface name in Netplan
    - MTU is set from the interface's MTU value in NetBox, or uses the default (9100, configurable via DEFAULT_MTU)
  - **Dummy0 interface**: If an interface named "dummy0" exists with the tag
    - All IPv4 and IPv6 addresses assigned to it are included
    - The interface is listed in `network_dummy_interfaces`
  - **VLAN interfaces**: Virtual interfaces (type=virtual) with the tag, untagged VLAN and parent interface
    - The label (or name if no label) becomes the VLAN interface name
    - The VLAN ID is extracted from the untagged VLAN
    - The parent interface's label (or name) is used as the link
    - All IPv4 and IPv6 addresses assigned to the VLAN interface are included
  - Example output:
    ```yaml
    network_dummy_interfaces:
      - dummy0
    network_ethernets:
      leaf1:
        match:
          macaddress: "aa:bb:cc:dd:ee:ff"
        set-name: leaf1
        mtu: 9100
      dummy0:
        addresses:
          - 192.168.45.123/32
          - 2001:db8:85a3::8a2e:370:7334/128
    network_vlans:
      vlan100:
        id: 100
        link: oob1
        addresses:
          - 172.16.10.5/20
    ```

### FRR Configuration
The `999-netbox-frr.yml` file contains frr_parameters which can be:
- **Manual configuration**: If the `frr_parameters` custom field is set on the device, its content is used directly
- **Automatic generation**: If no manual configuration exists, frr_parameters are automatically generated from:
  - **AS Number**: Calculated from dummy0 IPv4 address (prefix + 3rd octet padded + 4th octet padded)
    - Example: 192.168.45.123 with prefix 42 → 42045123
    - Can be overridden with `frr_local_as` custom field
  - **Loopback addresses**: IPv4 and IPv6 addresses from dummy0 interface
  - **Uplinks**: Interfaces with `managed-by-osism` tag and label connected to switches
    - Switch device roles are configurable via FRR_SWITCH_ROLES
    - Remote AS calculated from connected switch's dummy0 IPv4 or `frr_local_as` field
  - Example output:
    ```yaml
    frr_parameters:
      frr_local_as: 42045123
      frr_loopback_v4: 192.168.45.123
      frr_loopback_v6: 2001:db8:85a3::8a2e:370:7334
      frr_uplinks:
        - interface: leaf1
          remote_as: 42042100
        - interface: leaf2
          remote_as: 42042101
    ```

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