# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.20251130.0] - 2025-11-30

### Dependencies
- ghcr.io/astral-sh/uv 0.9.11 → 0.9.13

## [v0.20251125.0] - 2025-11-25

### Added
- Site-based inventory grouping for devices by their NetBox site assignment (`site-{site_slug}` groups)
- `metalbox.osism.xyz` as additional dynamic host entry in Metalbox Mode
- `frr_local_pref` custom field support for FRR uplinks with conflict resolution (uses higher value when both local and remote interfaces have the field set)
- `netplan_parameters` custom field support for loopback0 interfaces
- Support for cached AS numbers from `frr_parameters` custom field to avoid recalculation
- Empty groups initialization from `NETBOX_ROLE_MAPPING` to allow referencing groups without errors

### Changed
- Filter out-of-band (mgmt_only) interfaces from netplan configuration for non-metalbox nodes
- Terminology change from "cache" to "write" for parameter storage operations

### Fixed
- VRF generation timing in netplan extractor to ensure VRFs only reference validated interfaces
- FRR remote AS lookup in manager mode by adding API fallback when bulk_loader has no cached data for remote devices

### Removed
- `FLUSH_CACHE` environment variable and persistent caching logic for custom field parameters
- OpenContainers Annotations of type URL (`org.opencontainers.image.documentation`, `org.opencontainers.image.url`) from container build labels

### Dependencies
- python 3.13-alpine → 3.14-alpine
- ghcr.io/astral-sh/uv 0.9.7 → 0.9.11

## [v0.20251101.0] - 2025-11-01

### Added
- Parallel device processing with configurable concurrency using ThreadPoolExecutor
- Automatic retry with exponential backoff for transient API failures
- New configuration options: PARALLEL_PROCESSING_ENABLED, MAX_WORKERS, MAX_RETRIES, RETRY_DELAY, RETRY_BACKOFF, API_TIMEOUT

### Changed
- Batched bulk loading for interfaces and IP addresses to minimize API calls (90-100x reduction)
- BulkDataLoader now required throughout the codebase for optimized API access

### Removed
- File-based cache system (WRITE_CACHE functionality and file_cache.py module)

### Dependencies
- ghcr.io/astral-sh/uv 0.9.5 → 0.9.7

## [v0.20251029.0] - 2025-10-29

### Added
- VRF support to netplan parameters - automatic VRF configuration generation when NetBox interfaces are assigned to VRFs, including table ID extraction from VRF name convention (vrfXX pattern) and proper netplan structure generation

## [v0.20251028.0] - 2025-10-28

### Added
- Metalbox mode now additionally fetches devices with role=metalbox regardless of normal filter criteria
- Switch dnsmasq parameter aggregation for metalbox mode - switches with managed-by-metalbox tag are included in dnsmasq configuration
- DNSMASQ_SWITCH_ROLES environment variable for configuring which device roles are considered switches for dnsmasq operations
- `netbox` target to change.sh script for updating netbox files from the repository
- Support for generating dnsmasq MAC entries for switches without IP addresses

### Changed
- Switches are now excluded from FRR/Netplan parameter generation - they only receive dnsmasq parameters
- Management-only interfaces (mgmt_only=True) are now excluded from FRR BGP uplink detection
- Metalbox dnsmasq_parameters custom field now stores only switch device parameters, excluding the metalbox's own parameters
- Dnsmasq entry collection now uses dictionary-based deduplication to prevent duplicate entries on repeated runs

### Fixed
- Fixed duplicate dnsmasq entries accumulating in metalbox mode on repeated runs
- Fixed dnsmasq_interfaces being reset to empty list in cache, causing VLAN interfaces to be lost on subsequent runs
- Fixed gnmic parameters not being generated for switch devices in metalbox mode

### Dependencies
- ghcr.io/astral-sh/uv 0.8.22 → 0.9.5
- ansible-core 2.19.2 → 2.19.3
- dynaconf 3.2.11 → 3.2.12

## [v0.20250927.0] - 2025-09-27

### Changed
- Rename 50-infrastruture → 50-infrastructure (fix typo in inventory filename)

### Dependencies
- ghcr.io/astral-sh/uv 0.8.19 → 0.8.22

## [v0.20250920.0] - 2025-09-20

### Dependencies
- ghcr.io/astral-sh/uv 0.8.17 → 0.8.19

## [v0.20250914.0] - 2025-09-14

### Added
- Container image signing with cosign in Zuul build pipeline
- Configurable IPv6 address (fd33:fd0e:2aee::42/128) for metalbox loopback0 interfaces via DEFAULT_METALBOX_IPV6 parameter
- INVENTORY_IGNORE_PROVISION_STATE configuration option to bypass provision state filter for Ironic devices
- INVENTORY_IGNORE_MAINTENANCE_STATE configuration option to bypass maintenance state filter for devices
- Support for _segment_default_mtu in device config context for per-device/per-segment MTU configuration

### Changed
- Disabled interfaces now handled differently: FRR excludes them completely, Netplan includes them with activation-mode "off"
- NETBOX_TOKEN, NETBOX_API, and INVENTORY_RECONCILER_MODE settings now explicitly converted to strings with whitespace stripping

### Fixed
- IPv6 networks now skipped in dnsmasq DHCP configuration generation

### Dependencies
- ansible-core 2.18.6 → 2.19.2
- ghcr.io/astral-sh/uv 0.7.20 → 0.8.17

## [v0.20250711.0] - 2025-07-11

### Added
- GNMI host vars support for metalbox-managed switches with `managed-by-metalbox` tag
- GNMI parameter collection and writing for metalbox mode with new GnmicManager component
- DHCP option 3 (Gateway) for VLANs in routed VLAN groups in metalbox mode
- DHCP option 42 (NTP) for VLANs in metalbox mode
- Default DHCP tag `ironic` for devices with `managed-by-ironic` tag
- `INVENTORY_FROM_NETBOX` environment variable to control inventory file writing
- Metalbox mode support for FRR and Netplan parameter caching in NetBox custom fields

### Changed
- FRR and Netplan parameters are now always generated for all managed nodes regardless of mode
- Use `set:` instead of `tag:` syntax for dnsmasq dhcp-mac directives (device type slugs and custom DHCP tags)
- Check for `routed` substring in VLAN group names instead of exact match
- Use tag slug instead of tag name for `managed-by-ironic` detection
- Dnsmasq variables in metalbox mode now use `__metalbox` postfix notation
- Metalbox devices always get config_context written to host_vars
- Renamed GNMI extractor to Gnmic for consistency
- Standardized GnmicExtractor initialization pattern to match other extractors by accepting api, netbox_client, and file_cache parameters in constructor

### Fixed
- Correct dnsmasq dhcp-mac syntax from `tag:` to `set:` for device type slugs
- Trailing colon removed from completion log message in prepare-vars.py
- OOB IP extraction in GNMI extractor now uses proper interface detection via mgmt_only flag and managed-by-osism tag instead of name-pattern matching

### Dependencies
- ghcr.io/astral-sh/uv 0.7.8 → 0.7.20

## [v0.20250530.0] - 2025-05-30

### Added
- Support for extracting specific NetBox custom fields (frr_parameters, netplan_parameters) into dedicated inventory files via `NETBOX_DATA_TYPES` environment variable
- Configurable device filtering via `NETBOX_FILTER_INVENTORY` environment variable for flexible device selection based on status, tags, device type, site, or other NetBox attributes
- Support for multiple device filters in `NETBOX_FILTER_INVENTORY` using a list of filter dictionaries with OR operation and automatic duplicate removal
- Device role-based group assignment with configurable role mappings via `NETBOX_ROLE_MAPPING` environment variable
- Generation of dnsmasq DHCP host configurations for devices with OOB management interfaces
- Generation of dnsmasq DHCP ranges for OOB networks with managed-by-osism tag
- Support for dnsmasq_dhcp_macs parameter based on device type slugs
- Support for dnsmasq_dhcp_tag custom field to override device type for DHCP MAC tagging
- Automatic netplan parameters generation from NetBox interface data with support for both regular and loopback interfaces
- Automatic FRR parameters generation with configurable switch roles and AS number calculation
- New environment variables: `DEFAULT_MTU` for interface MTU configuration, `DEFAULT_LOCAL_AS_PREFIX` for FRR AS prefix, `FRR_SWITCH_ROLES` for configurable switch device roles
- Modular extractor classes (`BaseExtractor`, `ConfigContextExtractor`, `CustomFieldExtractor`, `NetplanExtractor`, `PrimaryIPExtractor`, `FRRExtractor`) following single responsibility principle
- Caching of auto-generated dnsmasq parameters (dnsmasq_dhcp_hosts, dnsmasq_dhcp_macs) in the dnsmasq_parameters custom field
- Persistent file-based caching for custom field values with `WRITE_CACHE` configuration option
- `FLUSH_CACHE` environment variable to force regeneration of cached custom field values
- Link-local IPv6 and DHCP disable for interfaces connected to switches without IP addresses
- Metalbox dummy interface with IP address 192.168.42.10/24 for devices with metalbox role in metalbox mode
- dnsmasq_interfaces parameter for metalbox mode to collect virtual interfaces with untagged VLANs
- dnsmasq_dynamic_hosts parameter for metalbox mode with entries for OOB networks
- VLAN tags to DHCP host entries in metalbox mode (format: "mac,hostname,ip,set:vlanXXX")
- dnsmasq_dhcp_options parameter for VLAN-specific DNS servers in metalbox mode
- VLAN interfaces now inherit MTU from parent interface instead of always using the default
- IPv4 and IPv6 addresses now included for regular interfaces in netplan configuration
- Support for interface-specific netplan_parameters custom field that gets merged into interface configuration
- CLAUDE.md documentation file for Claude Code guidance when working with the NetBox module

### Changed
- Moved yq from runtime dependency to build-time dependency only
- Refactored render-python-requirements.py with improved error handling, type hints, and modular functions
- Refactored generate-clustershell-ansible-file.py with better code organization and security improvements
- Refactored handle-inventory-overwrite.py with improved logging and modular functions
- Refactored merge-ansible-cfg.py with comprehensive error handling and validation
- Refactored move-group-vars.py with type hints and better file handling
- Modernized generate-inventory-from-netbox.py with pathlib for improved cross-platform compatibility
- Modernized merge-ansible-cfg.py with pathlib
- Split monolithic NetBox inventory generation script into modular structure with separate modules: config.py, netbox_client.py, data_extractor.py, inventory_manager.py, device_mapping.py, dnsmasq_manager.py, and utils.py
- Split monolithic dnsmasq_manager.py into modular components (base, interface_handler, dhcp_config, manager_mode, metalbox_mode, manager)
- Refactored NetBox client into modular architecture with separate modules for base classes, caching, connection management, exceptions, device filtering, and interface handling
- Inventory manager refactored into modular components (base, data_cache, file_writer, host_group_writer, manager)
- Refactored `config.py` to extract default values to module-level constants and fix mutable default arguments using dataclass field factories
- Split monolithic `DeviceDataExtractor` with static methods into smaller, focused extractor classes
- Device group assignment now uses device roles instead of tags
- Default behavior adds devices only to the 'generic' group instead of role-specific groups
- Metalbox role devices are now always assigned to generic, manager, and control groups, ignoring NETBOX_ROLE_MAPPING
- Configuration management now uses dynaconf for environment variables
- Primary IP extraction now prioritizes IPv4 over IPv6 addresses
- Renamed ROLE_MAPPING environment variable to NETBOX_ROLE_MAPPING
- Rename loopback0 interface throughout the codebase (previously dummy0)
- Replace network_dummy_interfaces list with network_dummy_devices dictionary for more consistent netplan configuration structure
- Change default AS prefix from 42 to 4200 for FRR configuration
- Interface fetching in netplan extractor now uses proper API filtering by `device_id`
- IP address fetching for loopback0 interfaces now uses API filters
- Tag filtering now uses slugs instead of names for consistency
- Netplan parameters are now written directly without wrapper in YAML output
- Skip provision state check for ironic devices in metalbox mode
- Require Celery for operation (removed crontab/crond support)
- Dnsmasq configuration keys now use inventory hostname instead of device name
- DHCP range format changed from "start,end,mask,static" to "start,static,mask,12h" with network address and 12-hour lease time
- Dynamic host entry format in metalbox mode changed to "metalbox,ip,vlanVLAN_ID"
- DHCP options in metalbox mode now filtered to only include VLANs whose prefix has managed-by-osism tag
- Data extraction logging now uses device name instead of inventory hostname
- Improved file cache behavior to always read from existing cache file regardless of `WRITE_CACHE` setting
- Improved logging in handle-inventory-overwrite.py to track removed groups
- Removed file path from logging in generate-clustershell-ansible-file.py
- Cleaned up redundant "NetBox" prefix in logging messages
- Refreshed Zuul secrets

### Fixed
- Primary IP address extraction now correctly strips CIDR notation
- Dynaconf envvar_prefix configuration corrected to False
- Templates path configuration now correctly defaults to `/netbox/templates/`
- Inventory file merger regex handling for proper INI format output
- Respect inventory_hostname custom field in dnsmasq parameter file paths
- ModuleNotFoundError for ABC module (incorrect import statement)
- Dynamic host entry format in metalbox mode now correctly uses VLAN ID
- Duplicate "vlan" prefix in metalbox dynamic host entries that caused entries like "vlanvlan123"

### Removed
- NetBox synchronization functionality (import-netbox playbook, sync scripts, ansible collection requirements)
- yq Python package dependency
- Crontab and crond support (CELERY environment variable no longer used)

### Dependencies
- ghcr.io/astral-sh/uv 0.6.13 → 0.7.8
- ansible-core 2.18.4 → 2.18.6
- pynetbox 7.4.1 → 7.5.0
- dynaconf 3.2.11 (new)

## [v0.20250408.0] - 2025-04-08

### Changed
- Use dtrack.osism.tech instead of osism.dtrack.regio.digital for dependency tracking
- Only checkout specific tags when not building latest version
- Decouple the image build from the old OSISM X.Y.Z release scheme
- Use uv instead of pip for Python package management
- Remove v prefix from version tags

### Fixed
- Fix typo in git checkout command (`chechkout` → `checkout`)

### Dependencies
- ansible-core 2.18.1 → 2.18.4
- jinja2 3.1.5 → 3.1.6
- netbox.netbox 3.20.0 → 3.21.0
- ghcr.io/astral-sh/uv 0.6.12 → 0.6.13
