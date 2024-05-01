import sys

from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
from ansible.vars.manager import VariableManager
from loguru import logger
import yaml

GROUP_CEPH_MON = "ceph-mon"
GROUP_CEPH_RGW = "ceph-rgw"

level = "INFO"
log_fmt = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | "
    "<level>{message}</level>"
)

logger.remove()
logger.add(sys.stdout, format=log_fmt, level=level, colorize=True)

loader = DataLoader()
inventory = InventoryManager(loader=loader, sources=["/inventory/hosts.yml"])

variable_manager = VariableManager(loader=loader, inventory=inventory)

groups = inventory.get_groups_dict()

if GROUP_CEPH_RGW in groups:
    result = []
    for host in groups[GROUP_CEPH_RGW]:
        result.append(
            {
                "host": str(host),
                "ip": "{{ "
                + f"hostvars['{host}']['radosgw_address'] | default(hostvars['{host}']['ansible_host'])"
                + " }}",
                "port": 8081,
            }
        )

    logger.info("Writing 050-kolla-ceph-rgw-hosts.yml with ceph_rgw_hosts")
    with open("/inventory.pre/group_vars/all/050-kolla-ceph-rgw-hosts.yml", "w+") as fp:
        dump = yaml.dump({"ceph_rgw_hosts": result})
        fp.write(dump)

if GROUP_CEPH_MON in groups:
    result = []
    for host in groups[GROUP_CEPH_MON]:
        result.append(
            "{{ "
            + f"hostvars['{host}']['monitor_address'] | default(hostvars['{host}']['ansible_host'])"
            + " }}",
        )

    logger.info("Writing 050-infrastructure-cephclient-mons.yml with cephclient_mons")
    with open(
        "/inventory.pre/group_vars/all/050-infrastructure-cephclient-mons.yml", "w+"
    ) as fp:
        dump = yaml.dump({"cephclient_mons": result})
        fp.write(dump)

# Make the fsid from the Ceph environment available as ceph_cluster_fsid for all environments.
try:
    with open("/opt/configuration/environments/ceph/configuration.yml", "r") as fp:
        data = yaml.full_load(fp)
        if "fsid" in data:
            fsid = data["fsid"]

            logger.info("Writing 050-ceph-cluster-fsid.yml with ceph_cluster_fsid")
            with open(
                "/inventory.pre/group_vars/all/050-ceph-cluster-fsid.yml", "w+"
            ) as fp:
                dump = yaml.dump({"ceph_cluster_fsid": fsid})
                fp.write(dump)
# There are deployments without Ceph environments.
except FileNotFoundError:
    pass
