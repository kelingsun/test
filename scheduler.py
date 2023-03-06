import datetime
import threading
import time
from typing import Dict

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.schedulers.blocking import BlockingScheduler
from retrying import retry

from rapidsnail.slug.constants import (
    ScanConfigEnum,
    AwsConfigEnum,
    YAML_FILES_PATH,
    SCAN_TRACKING_FILE,
    ScheduleConfigEnum,
    MetricsEnum,
    StigConfigEnum,
    NetscanTypesEnum,
    AdhocScanVars,
)
from rapidsnail.slug.helpers import (
    get_scheduled_agent_scan_group_name,
    get_scheduled_scan_name,
    get_netscan_scan_name,
    delete_files,
    get_scan_name,
    clear_scan_tracking,
    validate_scan_tracking_file,
    get_scan_records_for_manager,
    get_netscan_suffix,
    get_agent_scan_group_name,
    get_fd_name,
    get_standard_linux_stig_scan_name,
    get_tailored_linux_stig_scan_name,
    get_standard_amazon_stig_scan_name,
    get_linux_stig_scan_group_name,
    get_amazon_stig_scan_group_name,
    get_scan_names_from_records,
    get_targeted_netscan_suffix,
    get_targeted_netscan_scan_name,
    parse_cidr_block_from_bom,
)
from rapidsnail.slug.s3_client import S3Client
from rapidsnail.slug.sc_client import ScClient
from rapidsnail.slug.sc_poller import SCPoller
from rapidsnail.slug.slug import Slug
from rapidsnail.utils.adhoc_scan_poller import AdhocScanPoller
from rapidsnail.utils.logger import rs_log
from rapidsnail.utils.property_namespace import PropertyNamespace
from rapidsnail.utils.thread_config import manager_locks
from rapidsnail.slug.monitor import ServiceMonitor, Metric

LOGGER = rs_log(__name__)
current_sc_import_required = False


def get_slug_object(site, site_cfg, argus_client):
    host = site_cfg.get("vnscanam", dict()).get("nessus_host")
    if host not in manager_locks:
        manager_locks[host] = threading.Lock()
    LOGGER.info(f"Acquiring lock on manager : {site}, {host}")
    manager_locks[host].acquire()
    property_namespace = PropertyNamespace.get_instance()
    scan_target = Slug(
        site,
        site_cfg,
        is_falcon=property_namespace.is_falcon,
        argus_client=argus_client,
    )
    return scan_target


def site_control(
    site: str, site_cfg, property_namespace, argus_client: ServiceMonitor
) -> None:
    """
    Helper method for controlling the operations to be performed on each individual site by slug_control method.
    :param site: Name of the site
    :param site_cfg: Site Configs
    :param property_namespace: property namespace instance
    :param argus_client: Argus client to pass forward to the Slug object.
    """
    host = site_cfg.get("vnscanam", dict()).get("nessus_host")

    scan_target = get_slug_object(
        site=site, site_cfg=site_cfg, argus_client=argus_client
    )

    scan_target.nessus_login()

    max_scans_for_manager: int = site_cfg.get("vnscanam", dict()).get(
        ScanConfigEnum.MAX_SCANS_PER_MANAGER.value,
        ScanConfigEnum.DEFAULT_MAX_SCANS_PER_MANAGER.value,
    )
    LOGGER.info(f"Maximum of {max_scans_for_manager} scans can run on : {host}")

    minor_bu = site_cfg.get("vnscanam", dict()).get("minor_bu", site)
    major_bu = site_cfg.get("vnscanam", dict()).get("major_bu", property_namespace.env)

    running_scans = get_scan_names_from_records(
        file_name=SCAN_TRACKING_FILE, manager_host=host
    )

    running_scans |= scan_target.get_running_scans()
    LOGGER.info(f"{len(running_scans)} are running on the manager {host}")
    if len(running_scans) >= max_scans_for_manager:
        LOGGER.info(
            f"{len(running_scans)} already running on manager {host}. Cannot launch more scans"
        )
        argus_client.add_metric((MetricsEnum.BU_SCANNED.value, 0))
        return

    max_scans_for_bu: int = site_cfg.get("vnscanam", dict()).get(
        ScanConfigEnum.MAX_SCANS_FOR_BU.value,
        ScanConfigEnum.DEFAULT_MAX_SCANS_FOR_BU.value,
    )
    running_scan_for_bu: int = 0
    for scan in running_scans:
        if site in scan:
            running_scan_for_bu = running_scan_for_bu + 1
    if running_scan_for_bu >= max_scans_for_bu:
        LOGGER.info(
            f"{len(running_scans)} Scans for {site} are already running on manager {host}."
            f" Cannot launch more scans"
        )
        argus_client.add_metric((MetricsEnum.BU_SCANNED.value, 0))
        return

    agent_group_to_scan_name: Dict[str, str] = dict()
    new_scans = max_scans_for_manager - len(running_scans)
    count: int = 1
    suffix: int = 1
    while count <= new_scans:
        scan_name = get_scan_name(
            site_cfg.get("scan_config", dict()),
            major_bu=major_bu,
            minor_bu=minor_bu,
            scan_number=suffix,
            is_falcon=property_namespace.is_falcon,
        )
        if (
            scan_name not in running_scans
            and scan_name + "_rescanned" not in running_scans
        ):
            agent_group_name = get_agent_scan_group_name(site, group_number=suffix)
            agent_group_to_scan_name.update({agent_group_name: scan_name})
            count += 1
        else:
            LOGGER.info(f"{scan_name} is already running. Choosing a different name.")
        suffix += 1
    LOGGER.info(
        f"Available agent scan groups for site: {site} are {agent_group_to_scan_name.keys()}"
    )
    populated_scan_groups = scan_target.populate_agent_scan_groups(
        agent_group_to_scan_name
    )
    if populated_scan_groups:
        LOGGER.info(
            f"Populated agent scan groups for site: {site} are {populated_scan_groups}"
        )
        for scan_group in populated_scan_groups:
            scan_name = agent_group_to_scan_name.get(scan_group)
            LOGGER.info(f"Creating scan {scan_name} for agent group {scan_group}")
            scan_target.create_scan(scan_name, scan_group)
            LOGGER.info(f"Starting scan {scan_name} for agent group {scan_group}")
            scan_target.start_scan(scan_name)
            scan_target.track_scan_data(scan_name)
            argus_client.add_metric((MetricsEnum.BU_SCANNED.value, 1))
    else:
        LOGGER.info(
            f"No agents left to scan in last 24 hours on site {site}, env:{property_namespace.env}"
        )
        argus_client.add_metric((MetricsEnum.BU_SCANNED.value, 0))


def slug_control(site):
    """
    This function is the main entry point for Rapidsnail in orchestrating scans.
    Slug control looks at the @{SCAN_TRACKING_FILE} file and based on that file decides for each Nessus Manager
    (site) linked to the security center (env):
        * If there is an entry for a site in the scan tracking file:
            * If this scan's end-time is in the past, export the scan, upload to s3, and then create a new scan
            * If this scan's end-time is in the future, just log and continue to next scan.
        * If there isn't an entry for this site in the scan tracking file:
            * Start a new scan from scratch
    """
    host = None
    try:
        validate_scan_tracking_file()
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client({"site": site})

        site_cfg = property_namespace.site_to_site_cfg_map.get(site)
        host = site_cfg.get("vnscanam", dict()).get("nessus_host")
        if host not in manager_locks:
            manager_locks[host] = threading.Lock()
        site_control(site, site_cfg, property_namespace, argus_client)
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 1))
        argus_client.add_metric((MetricsEnum.ORCHESTRATION_SUCCESS.value, 1))
        argus_client.push_metrics()
    except Exception as error:
        LOGGER.error(f"Error {error} encountered for site {site} for host {host}")
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 0))
        argus_client.add_metric((MetricsEnum.ORCHESTRATION_SUCCESS.value, 0))
        argus_client.push_metrics()
        # Not re-raising the error here, since doing so will prevent scheduling for the next site.
        LOGGER.error(
            f"Nessus Managers: {host} specified for site {site} encountered failure"
        )
        LOGGER.error(f"Error {error} encountered for site {site}")
    finally:
        if host and manager_locks[host].locked():
            LOGGER.info(f"Releasing lock on manager : {site}, {host}")
            manager_locks[host].release()


def run_scheduled_scan(
    site,
):
    try:
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client({"site": site})
        run_scheduled_scan_util(site)
    except Exception as e:
        LOGGER.error(
            f"Encountered error {e} on site {site} while running scheduled scan."
        )
        argus_client.add_metric((MetricsEnum.SCHEDULED_SUCCESS, 0))
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 0))
        argus_client.push_metrics()


@retry(
    stop_max_attempt_number=3,
    retry_on_exception=lambda e: True,
    wait_exponential_multiplier=PropertyNamespace.get_instance().retry_exponential_multiplier,
)
def run_scheduled_scan_util(
    site,
):
    try:
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client({"site": site})
        site_cfg = property_namespace.site_to_site_cfg_map.get(site)
        host = site_cfg.get("vnscanam", dict()).get("nessus_host")
        schedule_config = site_cfg.get("scheduled_config", dict())
        if not schedule_config:
            return
        validate_scan_tracking_file()
        scan_target = get_slug_object(
            site=site, site_cfg=site_cfg, argus_client=argus_client
        )
        scan_target.nessus_login()
        minor_bu = site_cfg.get("vnscanam", dict()).get("minor_bu", site)
        major_bu = site_cfg.get("vnscanam", dict()).get(
            "major_bu", property_namespace.env
        )
        agent_group_name = get_scheduled_agent_scan_group_name(site, 1)
        group_id = scan_target.clear_scan_group(agent_scan_group_name=agent_group_name)
        parent_agent_group_names = schedule_config.get(
            ScanConfigEnum.PARENT_AGENT_GROUP_NAME.value, ""
        )
        if parent_agent_group_names:
            agents = scan_target.get_from_parent_agent_groups(parent_agent_group_names)
        else:
            agents = scan_target.get_agents()
        ids = [agent["id"] for agent in agents]
        scan_target.populate_agent_group(group_id=group_id, agent_ids=ids)
        parent_scan_name = schedule_config.get(
            ScanConfigEnum.PARENT_SCAN_NAME.value, ""
        )
        scan_name = get_scheduled_scan_name(
            major_bu=major_bu,
            minor_bu=minor_bu,
            number=1,
            parent_scan_name=parent_scan_name,
        )
        scan_target.scan_config = schedule_config
        LOGGER.info(f"Creating scan {scan_name} for agent group {agent_group_name}")
        scan_target.create_scan(scan_name=scan_name, agent_group_name=agent_group_name)
        LOGGER.info(f"Starting scan {scan_name} for agent group {agent_group_name}")
        scan_target.start_scan(scan_name)
        scan_target.track_scan_data(scan_name)
        argus_client.add_metric((MetricsEnum.SCHEDULED_SUCCESS, 1))
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 1))
        argus_client.push_metrics()
    finally:
        if manager_locks[host].locked():
            LOGGER.info(f"Releasing lock on manager : {site}, {host}")
            manager_locks[host].release()


def check_and_export_scans():
    try:
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client()
        for site, site_cfg in property_namespace.site_to_site_cfg_map.items():
            try:
                LOGGER.info(f"Checking and exporting for {site}")
                host = site_cfg.get("vnscanam", dict()).get("nessus_host")
                scan_records: list = get_scan_records_for_manager(
                    host, SCAN_TRACKING_FILE
                )
                scan_target = get_slug_object(site, site_cfg, argus_client=argus_client)
                LOGGER.info(f"Logging in to nessus host {host} for exporting..")
                scan_target.nessus_login()
                for scan_record in scan_records:
                    if site != scan_record["site"]:
                        LOGGER.info(f"Scan {scan_record['scan_name']} is running.. ")
                        #       running_scans.add(scan_record["scan_name"])
                        continue
                    if scan_record and int(
                        datetime.datetime.utcnow().timestamp()
                    ) < int(scan_record["end_time"]):
                        # don't do anything if there is already a scan running/in pending state for the current site.
                        LOGGER.info(
                            f"Scan with uuid: {scan_record['uuid']} running on"
                            f" {site} is supposed to finish later at "
                            f"{datetime.datetime.utcfromtimestamp(int(scan_record['end_time']))}"
                        )
                        #      running_scans.add(scan_record["scan_name"])
                        continue

                    if scan_record and int(
                        datetime.datetime.utcnow().timestamp()
                    ) >= int(scan_record["end_time"]):
                        LOGGER.info(
                            f"Time to export scan with uuid: {scan_record['uuid']} from site {site}"
                        )
                        exported_scan_files = scan_target.export_scan(
                            scan_record.get("scan_id"), scan_record.get("uuid")
                        )
                        if not exported_scan_files:
                            # Not all scans complete within the expected end time, irrespective of the number of agents
                            # linked for scanning. Hence, make sure the exported_scan_file method returns a value.
                            LOGGER.warning(
                                f"{site}: Could not export scan with {scan_record.get('uuid', 'N/A')} uuid."
                            )
                            #         running_scans.add(scan_record["scan_name"])
                            continue

                        LOGGER.info(
                            f"The scan for site {site} with uuid {scan_record['uuid']} is exported to location {exported_scan_files.keys()}"
                        )
                        s3_proxy = property_namespace.env_config.get(
                            AwsConfigEnum.SFDC_SERVICES.value, dict()
                        ).get(AwsConfigEnum.S3_PROXY.value)
                        s3_targets = property_namespace.env_config.get(
                            AwsConfigEnum.AWS_SERVICES.value, list()
                        )
                        if (
                            property_namespace.is_falcon
                            and property_namespace.fi_name
                            in property_namespace.overridden_s3_mapping
                        ):
                            s3_targets = property_namespace.overridden_s3_mapping.get(
                                property_namespace.fi_name
                            )

                        for target in s3_targets:
                            for (
                                exported_scan_file,
                                metadata,
                            ) in exported_scan_files.items():
                                scan_target.upload_data(
                                    exported_scan_file,
                                    s3_proxy,
                                    target.get(AwsConfigEnum.S3_BUCKET.value),
                                    target.get(AwsConfigEnum.S3_SCAN_PATH.value),
                                    target.get(AwsConfigEnum.S3_REGION.value),
                                    metadata=metadata,
                                )
                        delete_files(exported_scan_files.keys())
                        clear_scan_tracking(site=site, uuid=scan_record["uuid"])
                        scan_target.delete_scan_history(scan_record["scan_name"])
                        if property_namespace.sc_import_required:
                            LOGGER.info(f"Enqueuing site {site} for SC agent Sync.")
                            property_namespace.queue_for_sc.enqueue(site)
                        argus_client.add_metric(
                            (MetricsEnum.CHECK_AND_EXPORT.value, 1),
                            additional_tags={"site": site},
                        )
                        argus_client.add_metric(
                            (MetricsEnum.OVERALL_SUCCESS.value, 1),
                            additional_tags={"site": site},
                        )
                        argus_client.push_metrics()
            except Exception as e:
                LOGGER.error(
                    f"Encountered error {e} while trying to export scans from manager {host}"
                )
                argus_client.add_metric(
                    metric=(MetricsEnum.CHECK_AND_EXPORT.value, 0),
                    additional_tags={"site": site},
                )
                argus_client.add_metric(
                    (MetricsEnum.OVERALL_SUCCESS.value, 0),
                    additional_tags={"site": site},
                )
                argus_client.push_metrics()
            finally:
                if manager_locks[host].locked():
                    LOGGER.info(f"Releasing lock on manager : {site}, {host}")
                    manager_locks[host].release()

    except Exception as e:
        LOGGER.error(f"Encountered error {e} while trying to export scans.")


def run_network_scan(site):
    try:
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client(
            {
                "site": site,
            }
        )
        run_network_scan_util(
            site,
        )
    except Exception as e:
        LOGGER.error(
            f"Encountered error {e} on site {site} while running network scan."
        )
        argus_client.add_metric((MetricsEnum.NETSCAN_SUCCESS, 0))
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 0))
        argus_client.push_metrics()


@retry(
    stop_max_attempt_number=3,
    retry_on_exception=lambda e: True,
    wait_exponential_multiplier=PropertyNamespace.get_instance().retry_exponential_multiplier,
)
def run_network_scan_util(
    site,
):
    try:
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client(
            {
                "site": site,
            }
        )
        site_cfg = property_namespace.site_to_site_cfg_map.get(site)
        netscan_config = site_cfg.get("netscan_config", dict())
        host = site_cfg.get("vnscanam", dict()).get("nessus_host")
        if not netscan_config:
            return

        validate_scan_tracking_file()
        scan_target = get_slug_object(
            site=site, site_cfg=site_cfg, argus_client=argus_client
        )
        LOGGER.info(f"Logging in to nessus host for netscanning..")
        scan_target.nessus_login()
        max_scans_for_manager: int = netscan_config.get(
            ScanConfigEnum.MAX_SCANS_PER_MANAGER.value,
            ScanConfigEnum.DEFAULT_MAX_SCANS_PER_MANAGER.value,
        )
        all_running = get_scan_names_from_records(
            file_name=SCAN_TRACKING_FILE, manager_host=host
        )
        running_netscans = set()
        for scan in all_running:
            if get_netscan_suffix() in scan:
                running_netscans.add(scan)
        LOGGER.info(
            f"{len(running_netscans)} network scans are running on the manager {host} .."
        )
        if len(running_netscans) >= max_scans_for_manager:
            LOGGER.info(
                f"{len(running_netscans)} network scans already running on manager {host}"
                f" . Cannot launch more scanners"
            )
            LOGGER.info(f"Releasing lock on manager : {site}, {host}")
            manager_locks[host].release()
            return

        minor_bu = site_cfg.get("vnscanam", dict()).get("minor_bu", site)
        major_bu = site_cfg.get("vnscanam", dict()).get(
            "major_bu", property_namespace.env
        )

        scanners = scan_target.get_scanners()
        LOGGER.info(f"Got scanners : {scanners}")
        running_scans = len(running_netscans)
        for scanner in scanners:
            if running_scans >= max_scans_for_manager:
                LOGGER.info(f"Number of Running network scans is {running_scans}..")
                break
            scanner_name = scanner.get("name")
            scan_name = get_netscan_scan_name(
                major_bu=major_bu, minor_bu=minor_bu, scanner=scanner_name
            )
            LOGGER.info(f"Checking eligibilty of scan {scan_name} for network scan..")
            if scan_target.is_eligible_for_netscan(scan_name):
                fd_name = get_fd_name(scanner_name)
                scan_target.create_network_scan(
                    scan_name=scan_name, scanner_id=scanner.get("id"), fd_name=fd_name
                )
                LOGGER.info(f"Starting network scan {scan_name} ")
                scan_target.start_scan(scan_name)
                scan_target.track_scan_data(scan_name, scan_config=netscan_config)
                running_scans += 1
        argus_client.add_metric((MetricsEnum.NETSCAN_SUCCESS, 1))
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 1))
        argus_client.push_metrics()
    finally:
        if manager_locks[host].locked():
            LOGGER.info(f"Releasing lock on manager : {site}, {host}")
            manager_locks[host].release()


def run_targeted_network_scan(site):
    try:
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client({"site": site})
        site_cfg = property_namespace.site_to_site_cfg_map.get(site)
        netscan_config = site_cfg.get(
            ScanConfigEnum.TARGETED_NETSCAN_CONFIG.value, dict()
        )
        process_network_scan(
            site,
            netscan_config,
            NetscanTypesEnum.TARGETED_NETSCAN.value,
            get_targeted_netscan_suffix(),
            (MetricsEnum.NETSCAN_SUCCESS, 1),
        )
    except Exception as e:
        LOGGER.error(
            f"Encountered error {e} on site {site} while running targeted network scan."
        )
        argus_client.add_metric((MetricsEnum.TARGETED_NETSCAN_SUCCESS, 0))
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 0))
        argus_client.push_metrics()


@retry(
    stop_max_attempt_number=3,
    retry_on_exception=lambda e: True,
    wait_exponential_multiplier=PropertyNamespace.get_instance().retry_exponential_multiplier,
)
def process_network_scan(
    site, netscan_config, scan_type_name, netscan_suffix, netscan_metric: Metric
):
    # This function can be used to process both current netscan and targeted netscan.
    # W-12406119 has been created to ensure future refractoring for code reusability.
    # Added nescan_metric and other parameters to avoid tight coupling with any scan type.

    try:
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client({"site": site})
        site_cfg = property_namespace.site_to_site_cfg_map.get(site)
        host = site_cfg.get("vnscanam", dict()).get("nessus_host")
        if not netscan_config:
            return

        validate_scan_tracking_file()
        scan_target = get_slug_object(
            site=site, site_cfg=site_cfg, argus_client=argus_client
        )

        LOGGER.info(f"Logging in to nessus host for netscanning..")
        scan_target.nessus_login()
        max_scans_for_manager: int = netscan_config.get(
            ScanConfigEnum.MAX_SCANS_PER_MANAGER.value,
            ScanConfigEnum.DEFAULT_MAX_SCANS_PER_MANAGER.value,
        )
        all_running = get_scan_names_from_records(
            file_name=SCAN_TRACKING_FILE, manager_host=host
        )
        running_netscans = set()
        for scan in all_running:
            if netscan_suffix in scan:
                running_netscans.add(scan)
        LOGGER.info(
            f"{len(running_netscans)} {scan_type_name}s are running on the manager {host} .."
        )

        if len(running_netscans) >= max_scans_for_manager:
            LOGGER.info(
                f"{len(running_netscans)} {scan_type_name}s already running on manager {host}"
                f" . Cannot launch more scanners"
            )
            LOGGER.info(f"Releasing lock on manager : {site}, {host}")
            manager_locks[host].release()
            return

        minor_bu = site_cfg.get("vnscanam", dict()).get("minor_bu", site)
        major_bu = site_cfg.get("vnscanam", dict()).get(
            "major_bu", property_namespace.env
        )

        scanners = scan_target.get_scanners()
        LOGGER.info(f"Got scanners : {scanners}")
        running_scans = len(running_netscans)
        for scanner in scanners:
            if running_scans >= max_scans_for_manager:
                LOGGER.info(f"Number of Running {scan_type_name}s is {running_scans}..")
                break
            scanner_name = scanner.get("name")
            if scan_type_name == NetscanTypesEnum.TARGETED_NETSCAN.value:
                scan_name = get_targeted_netscan_scan_name(
                    major_bu=major_bu, minor_bu=minor_bu, scanner=scanner_name
                )
            else:
                scan_name = get_netscan_scan_name(
                    major_bu=major_bu, minor_bu=minor_bu, scanner=scanner_name
                )

            LOGGER.info(f"Checking eligibilty of scan {scan_name} for network scan..")
            if scan_target.is_eligible_for_netscan(scan_name, netscan_config):
                fd_name = get_fd_name(scanner_name)
                scan_target.create_network_scan(
                    scan_name=scan_name, scanner_id=scanner.get("id"), fd_name=fd_name
                )
                LOGGER.info(f"Starting {scan_type_name} {scan_name} ")
                scan_target.start_scan(scan_name)
                scan_target.track_scan_data(scan_name, scan_config=netscan_config)
                running_scans += 1
        argus_client.add_metric(netscan_metric)
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 1))
        argus_client.push_metrics()
    finally:
        if manager_locks[host].locked():
            LOGGER.info(f"Releasing lock on manager : {site}, {host}")
            manager_locks[host].release()


def run_stig_standard_linux_scan(
    site,
):
    try:
        argus_client = PropertyNamespace.get_instance().get_argus_client({"site": site})
        run_stig_standard_linux_scan_util(site)
    except Exception as e:
        LOGGER.error(
            f"Encountered error {e} on site {site} while running standard linux stig scan."
        )
        argus_client.add_metric((MetricsEnum.STANDARD_LINUX_STIG_SUCCESS, 0))
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 0))
        argus_client.push_metrics()


@retry(
    stop_max_attempt_number=3,
    retry_on_exception=lambda e: True,
    wait_exponential_multiplier=PropertyNamespace.get_instance().retry_exponential_multiplier,
)
def run_stig_standard_linux_scan_util(
    site,
):
    try:
        LOGGER.info(f"Starting Standard Linux Stig scan on site : {site}")
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client({"site": site})

        site_cfg = property_namespace.site_to_site_cfg_map.get(site)
        host = site_cfg.get("vnscanam", dict()).get("nessus_host")

        stig_linux_standard_config = site_cfg.get(
            StigConfigEnum.STIG_LINUX_STANDARD_CONFIG.value, dict()
        )

        if not stig_linux_standard_config:
            return

        validate_scan_tracking_file()
        scan_target = get_slug_object(
            site=site, site_cfg=site_cfg, argus_client=argus_client
        )
        scan_target.nessus_login()
        minor_bu = site_cfg.get("vnscanam", dict()).get("minor_bu", site)
        major_bu = site_cfg.get("vnscanam", dict()).get(
            "major_bu", property_namespace.env
        )
        scan_name = get_standard_linux_stig_scan_name(
            major_bu=major_bu, minor_bu=minor_bu, number=1
        )
        agent_group_name = get_linux_stig_scan_group_name(site, 1)

        process_stig_scan(
            stig_linux_standard_config,
            agent_group_name,
            scan_name,
            scan_target,
            StigConfigEnum.STIG_FILTER_NAME.value,
            StigConfigEnum.STIG_LINUX_FILTER_VALUE.value,
        )
        LOGGER.info(f"Completed Standard Linux Stig scan on site : {site}")
        argus_client.add_metric((MetricsEnum.STANDARD_LINUX_STIG_SUCCESS, 1))
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 1))
        argus_client.push_metrics()
    finally:
        if manager_locks[host].locked():
            LOGGER.info(f"Releasing lock on manager : {site}, {host}")
            manager_locks[host].release()


def run_stig_tailored_linux_scan(
    site,
):
    try:
        argus_client = PropertyNamespace.get_instance().get_argus_client({"site": site})
        run_stig_tailored_linux_scan_util(site)
    except Exception as e:
        LOGGER.error(
            f"Encountered error {e} on site {site} while running tailored linux stig scan."
        )
        argus_client.add_metric((MetricsEnum.TAILORED_LINUX_STIG_SUCCESS, 0))
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 0))
        argus_client.push_metrics()


@retry(
    stop_max_attempt_number=3,
    retry_on_exception=lambda e: True,
    wait_exponential_multiplier=PropertyNamespace.get_instance().retry_exponential_multiplier,
)
def run_stig_tailored_linux_scan_util(
    site,
):
    try:
        LOGGER.info(f"Starting Tailored Linux Stig scan on site : {site}")
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client({"site": site})
        site_cfg = property_namespace.site_to_site_cfg_map.get(site)
        host = site_cfg.get("vnscanam", dict()).get("nessus_host")

        stig_linux_tailored_config = site_cfg.get(
            StigConfigEnum.STIG_LINUX_TAILORED_CONFIG.value, dict()
        )

        if not stig_linux_tailored_config:
            return

        validate_scan_tracking_file()
        scan_target = get_slug_object(
            site=site, site_cfg=site_cfg, argus_client=argus_client
        )
        scan_target.nessus_login()
        minor_bu = site_cfg.get("vnscanam", dict()).get("minor_bu", site)
        major_bu = site_cfg.get("vnscanam", dict()).get(
            "major_bu", property_namespace.env
        )
        scan_name = get_tailored_linux_stig_scan_name(
            major_bu=major_bu, minor_bu=minor_bu, number=1
        )
        agent_group_name = get_linux_stig_scan_group_name(site, 1)
        process_stig_scan(
            stig_linux_tailored_config,
            agent_group_name,
            scan_name,
            scan_target,
            StigConfigEnum.STIG_FILTER_NAME.value,
            StigConfigEnum.STIG_LINUX_FILTER_VALUE.value,
        )
        LOGGER.info(f"Completed Tailored Linux Stig scan on site : {site}")
        argus_client.add_metric((MetricsEnum.TAILORED_LINUX_STIG_SUCCESS, 1))
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 1))
        argus_client.push_metrics()
    finally:
        if manager_locks[host].locked():
            LOGGER.info(f"Releasing lock on manager : {site}, {host}")
            manager_locks[host].release()


def run_stig_standard_amazon_scan(
    site,
):
    try:
        argus_client = PropertyNamespace.get_instance().get_argus_client({"site": site})
        run_stig_standard_amazon_scan_util(site)
    except Exception as e:
        LOGGER.error(
            f"Encountered error {e} on site {site} while running standard amazon stig scan."
        )
        argus_client.add_metric((MetricsEnum.STANDARD_AMZ_STIG_SUCCESS, 0))
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 0))
        argus_client.push_metrics()


@retry(
    stop_max_attempt_number=3,
    retry_on_exception=lambda e: True,
    wait_exponential_multiplier=PropertyNamespace.get_instance().retry_exponential_multiplier,
)
def run_stig_standard_amazon_scan_util(
    site,
):
    try:
        LOGGER.info(f"Starting Standard Amazon Stig scan on site : {site}")
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client({"site": site})
        site_cfg = property_namespace.site_to_site_cfg_map.get(site)
        host = site_cfg.get("vnscanam", dict()).get("nessus_host")

        stig_amz_standard_config = site_cfg.get(
            StigConfigEnum.STIG_AMAZON_STANDARD_CONFIG.value, dict()
        )

        if not stig_amz_standard_config:
            return

        validate_scan_tracking_file()
        scan_target = get_slug_object(
            site=site, site_cfg=site_cfg, argus_client=argus_client
        )
        scan_target.nessus_login()
        minor_bu = site_cfg.get("vnscanam", dict()).get("minor_bu", site)
        major_bu = site_cfg.get("vnscanam", dict()).get(
            "major_bu", property_namespace.env
        )
        scan_name = get_standard_amazon_stig_scan_name(
            major_bu=major_bu, minor_bu=minor_bu, number=1
        )
        agent_group_name = get_amazon_stig_scan_group_name(site, 1)
        process_stig_scan(
            stig_amz_standard_config,
            agent_group_name,
            scan_name,
            scan_target,
            StigConfigEnum.STIG_FILTER_NAME.value,
            StigConfigEnum.STIG_AMAZON_FILTER_VALUE.value,
        )
        LOGGER.info(f"Completed Standard Amazon Stig scan on site : {site}")
        argus_client.add_metric((MetricsEnum.TAILORED_LINUX_STIG_SUCCESS, 1))
        argus_client.add_metric((MetricsEnum.OVERALL_SUCCESS, 1))
        argus_client.push_metrics()
    finally:
        if manager_locks[host].locked():
            LOGGER.info(f"Releasing lock on manager : {site}, {host}")
            manager_locks[host].release()


def process_stig_scan(
    stig_scan_cfg, agent_group_name, scan_name, scan_target, filter_name, filter_val
):
    group_id = scan_target.clear_scan_group(agent_scan_group_name=agent_group_name)
    agent_ids = scan_target.filter_agents_using_query(filter_name, filter_val)
    scan_target.populate_agent_group(group_id=group_id, agent_ids=agent_ids)

    scan_target.scan_config = stig_scan_cfg
    LOGGER.info(f"Creating stig scan: {scan_name} for agent group {agent_group_name}")
    scan_target.create_scan(scan_name=scan_name, agent_group_name=agent_group_name)
    LOGGER.info(f"Starting stig scan: {scan_name} for agent group {agent_group_name}")
    scan_target.start_scan(scan_name)
    scan_target.track_scan_data(scan_name)


def delete_offline_agents_job(site):
    try:
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client({"site": site})
        delete_offline_agents_job_util(site)
    except Exception as e:
        LOGGER.error(
            f"Encountered error {e} on site {site} while running network scan."
        )
        argus_client.add_metric((MetricsEnum.DELETE_OFFLINE_AGENTS_SUCCESS, 0))
        argus_client.push_metrics()


@retry(
    stop_max_attempt_number=3,
    retry_on_exception=lambda e: True,
    wait_exponential_multiplier=PropertyNamespace.get_instance().retry_exponential_multiplier,
)
def delete_offline_agents_job_util(site):
    try:
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client({"site": site})
        site_cfg = property_namespace.site_to_site_cfg_map.get(site)
        host = site_cfg.get("vnscanam", dict()).get("nessus_host")
        delete_offline_agents = site_cfg.get("vnscanam", dict()).get(
            ScanConfigEnum.DELETE_OFFLINE_AGENTS.value,
            ScanConfigEnum.DELETE_OFFLINE_AGENTS_DEFAULT.value,
        )
        if not delete_offline_agents:
            return
        scan_target = get_slug_object(
            site=site, site_cfg=site_cfg, argus_client=argus_client
        )
        LOGGER.info(f"Logging in to nessus host for deleting offline agents..")
        scan_target.nessus_login()
        agents = scan_target.get_offline_agents()
        ids = [agent["id"] for agent in agents]
        scan_target.delete_agents(agent_ids=ids)
        argus_client.add_metric((MetricsEnum.DELETE_OFFLINE_AGENTS_SUCCESS, 1))
        argus_client.push_metrics()
    finally:
        if manager_locks[host].locked():
            LOGGER.info(f"Releasing lock on manager : {site}, {host}")
            manager_locks[host].release()


def heartbeat_monitor():
    """This orchestration job controls the metrics exporting"""
    LOGGER.info("Heartbeat Job Running")
    property_namespace = PropertyNamespace.get_instance()
    argus_client = property_namespace.get_argus_client(
        {"datacenter": property_namespace.sc_datacenter}
    )
    argus_client.add_metric(("heartbeat", 100))
    argus_client.push_metrics()


def _update_site_configs():
    try:
        LOGGER.info(f"Updating env and sites configs..")
        property_namespace = PropertyNamespace.get_instance()
        yaml_locations = property_namespace.yaml_locations
        if not yaml_locations:
            LOGGER.info(f"No yaml locations found.. Not updating the configs")
            return
        vault_manager = property_namespace.get_vault_manager()
        s3_client = S3Client(
            is_falcon=property_namespace.is_falcon, vault_manager=vault_manager
        )

        s3_proxy = property_namespace.env_config.get(
            AwsConfigEnum.SFDC_SERVICES.value, dict()
        ).get(AwsConfigEnum.S3_PROXY.value)

        s3_client.download_dir(
            s3_proxy=s3_proxy,
            s3_bucket=yaml_locations.get(AwsConfigEnum.S3_BUCKET.value),
            s3_path=yaml_locations.get(AwsConfigEnum.S3_FILES_PATH.value),
            s3_region=yaml_locations.get(AwsConfigEnum.S3_REGION.value),
            local_path=YAML_FILES_PATH,
        )
        LOGGER.info(
            f"Downloaded latest yamls from s3, " f"proceeding to updating configs"
        )
        property_namespace.update_configs()
    except Exception as e:
        LOGGER.error(f"Encountered error {e} while updating site configs..")


@retry(wait_fixed=60 * 5 * 1000)
def initialize():
    try:
        property_namespace = PropertyNamespace.get_instance()
        executors = {"default": ThreadPoolExecutor(property_namespace.thread_count)}
        scheduler = BlockingScheduler(executors=executors)
        LOGGER.info(
            f"Thread count: {property_namespace.thread_count} , "
            f"Schedule Interval: {property_namespace.schedule_interval} minutes"
        )
        if not property_namespace.sites:
            sc_client = ScClient(property_namespace.get_argus_client())
            property_namespace.site_to_site_cfg_map = (
                sc_client.get_agent_managers_site_configs()
            )

        _update_rapidsnail_jobs(scheduler)
        yaml_locations = property_namespace.yaml_locations
        if not property_namespace.is_falcon and yaml_locations:
            LOGGER.info(f"Adding update rapidsnail jobs interval job..")
            scheduler.add_job(
                update_jobs,
                "interval",
                (scheduler,),
                minutes=30,
                next_run_time=datetime.datetime.now() + datetime.timedelta(seconds=5),
            )

        LOGGER.info(f"Adding check and export interval job..")
        scheduler.add_job(check_and_export_scans, "interval", minutes=30)
        LOGGER.info(f"Adding heartbeat interval job..")
        scheduler.add_job(heartbeat_monitor, "interval", minutes=5)

        if property_namespace.adhoc_configs:
            for adhoc_config in property_namespace.adhoc_configs:
                if adhoc_config.get("enabled", True):
                    LOGGER.info(f"Creating adhoc poller for conf: {adhoc_config}..")
                    env_key = adhoc_config.get(AdhocScanVars.ADHOC_ENV_KEY.value, "")
                    adhoc_scanner = AdhocScanPoller(
                        property_namespace.env,
                        adhoc_config,
                        property_namespace.get_argus_client(
                            tags={AdhocScanVars.ADHOC_ENV_KEY.value: env_key}
                        ),
                    )
                    adhoc_scanner.start()
                else:
                    LOGGER.info(f"Adhoc poller {adhoc_config} is not enabled..")
        else:
            LOGGER.info(f"No Queue provided for adhoc scanning.")
        scheduler.start()
    except Exception as er:
        LOGGER.error(f"Fatal error: {er}")
        raise


def update_jobs(scheduler):
    try:
        property_namespace = PropertyNamespace.get_instance()
        argus_client = property_namespace.get_argus_client()
        _update_site_configs()
        _update_rapidsnail_jobs(scheduler)
        _remove_old_site_jobs(scheduler)
        argus_client.add_metric((MetricsEnum.UPDATE_JOBS_SUCCESS, 1))
        argus_client.push_metrics()
    except Exception as e:
        LOGGER.error(
            f"Encountered exception {e} while trying to update rapidsnail jobs."
        )
        argus_client.add_metric((MetricsEnum.UPDATE_JOBS_SUCCESS, 0))
        argus_client.push_metrics()


def _update_rapidsnail_jobs(scheduler):
    property_namespace = PropertyNamespace.get_instance()
    counter = 1
    first_runtime_delta = 5
    hour_val = 1
    minute_val = 1
    for site in property_namespace.site_to_site_cfg_map:
        if counter % property_namespace.thread_count == 0:
            first_runtime_delta += 5
        if minute_val > 55:
            hour_val += 1
            minute_val = 1
        _update_rapidsnail_agent_scan(
            scheduler=scheduler, site=site, first_runtime_delta=first_runtime_delta
        )
        _update_netscan_jobs(
            scheduler=scheduler, site=site, first_runtime_delta=first_runtime_delta
        )

        _update_scheduled_scan_jobs(
            scheduler=scheduler, site=site, hour_val=hour_val, minute_val=minute_val
        )
        _update_delete_offline_agents_job(scheduler=scheduler, site=site)

        if property_namespace.is_falcon:
            _update_stig_linux_standard_scan_jobs(
                scheduler=scheduler, site=site, hour_val=hour_val, minute_val=minute_val
            )
            _update_stig_linux_tailored_scan_jobs(
                scheduler=scheduler, site=site, hour_val=hour_val, minute_val=minute_val
            )
            _update_stig_amazon_standard_scan_jobs(
                scheduler=scheduler, site=site, hour_val=hour_val, minute_val=minute_val
            )
            _update_targeted_netscan_jobs(
                scheduler=scheduler, site=site, first_runtime_delta=first_runtime_delta
            )

        counter += 1
        minute_val += 1
    global current_sc_import_required
    if property_namespace.sc_import_required and not current_sc_import_required:
        LOGGER.info(f"Adding sc_poller thead..")
        sc_poller = SCPoller(
            queue=property_namespace.queue_for_sc,
            argus_client=property_namespace.get_argus_client(),
        )
        sc_poller.start()
        current_sc_import_required = True
    if not property_namespace.sc_import_required:
        current_sc_import_required = False


def _update_rapidsnail_agent_scan(scheduler, site, first_runtime_delta):
    property_namespace = PropertyNamespace.get_instance()
    scan_job_id = f"{site}_scan"
    site_cfg = property_namespace.site_to_site_cfg_map.get(site)
    scan_config = site_cfg.get("scan_config", dict())
    if scan_config:
        LOGGER.info(
            f"Adding scan job for site {site} with time delta {first_runtime_delta}"
        )
        scheduler.add_job(
            slug_control,
            "interval",
            (site,),
            minutes=property_namespace.schedule_interval,
            next_run_time=datetime.datetime.now()
            + datetime.timedelta(minutes=first_runtime_delta),
            replace_existing=True,
            id=scan_job_id,
        )
    elif scheduler.get_job(scan_job_id):
        LOGGER.info(f"Removing job {scan_job_id}..")
        scheduler.remove_job(scan_job_id)


def _update_netscan_jobs(scheduler, site, first_runtime_delta):
    netscan_job_id = f"{site}_netscan"
    property_namespace = PropertyNamespace.get_instance()
    site_cfg = property_namespace.site_to_site_cfg_map.get(site)
    netscan_config = site_cfg.get("netscan_config", dict())
    if netscan_config:
        load_bom_for_netscan(netscan_config)
        LOGGER.info(f"Adding network scanning for site {site}")
        scheduler.add_job(
            run_network_scan,
            "interval",
            (site,),
            minutes=30,
            next_run_time=datetime.datetime.now()
            + datetime.timedelta(minutes=first_runtime_delta),
            replace_existing=True,
            id=netscan_job_id,
        )
    elif scheduler.get_job(netscan_job_id):
        LOGGER.info(f"Removing job {netscan_job_id}..")
        scheduler.remove_job(netscan_job_id)


def _update_targeted_netscan_jobs(scheduler, site, first_runtime_delta):
    targeted_netscan_job_id = f"{site}_targeted_netscan"
    property_namespace = PropertyNamespace.get_instance()
    site_cfg = property_namespace.site_to_site_cfg_map.get(site)
    targeted_netscan_config = site_cfg.get(
        ScanConfigEnum.TARGETED_NETSCAN_CONFIG.value, dict()
    )
    if targeted_netscan_config:
        LOGGER.info(f"Adding targeted network scanning for site {site}")
        scheduler.add_job(
            run_targeted_network_scan,
            "interval",
            (site,),
            minutes=30,
            next_run_time=datetime.datetime.now()
            + datetime.timedelta(minutes=first_runtime_delta),
            replace_existing=True,
            id=targeted_netscan_job_id,
        )
    elif scheduler.get_job(targeted_netscan_job_id):
        LOGGER.info(f"Removing job {targeted_netscan_job_id}..")
        scheduler.remove_job(targeted_netscan_job_id)


def load_bom_for_netscan(netscan_config):
    property_namespace = PropertyNamespace.get_instance()
    bom_file_path = netscan_config.get(ScanConfigEnum.DERIVED_BOM_FILE.value)
    if property_namespace.is_falcon and bom_file_path is not None:
        # Parse the derived BOM and create mapping between FD name and target IP range.
        parse_cidr_block_from_bom(
            argus_client=property_namespace.get_argus_client(),
            bom_file_path=bom_file_path,
        )


def _update_scheduled_scan_jobs(scheduler, site, hour_val, minute_val):
    scheduled_job_id = f"{site}_schedule"
    property_namespace = PropertyNamespace.get_instance()
    site_cfg = property_namespace.site_to_site_cfg_map.get(site)
    schedule_config = site_cfg.get("scheduled_config", dict())
    if schedule_config:
        LOGGER.info(f"Adding cron job for site {site}..")
        days = schedule_config.get(
            ScheduleConfigEnum.DAYS.value, ScheduleConfigEnum.DAYS_DEFAULT.value
        )
        scheduler.add_job(
            run_scheduled_scan,
            "cron",
            (site,),
            day_of_week=days,
            hour=hour_val,
            minute=minute_val,
            replace_existing=True,
            id=scheduled_job_id,
        )
    elif scheduler.get_job(scheduled_job_id):
        LOGGER.info(f"Removing job {scheduled_job_id}..")
        scheduler.remove_job(scheduled_job_id)


def _update_delete_offline_agents_job(scheduler, site, first_runtime_delta=10):
    property_namespace = PropertyNamespace.get_instance()
    delete_offline_agents_id = f"{site}_delete_offline_agents"
    site_cfg = property_namespace.site_to_site_cfg_map.get(site)
    delete_offline_agents = site_cfg.get("vnscanam", dict()).get(
        ScanConfigEnum.DELETE_OFFLINE_AGENTS.value,
        ScanConfigEnum.DELETE_OFFLINE_AGENTS_DEFAULT.value,
    )
    if delete_offline_agents and scheduler.get_job(delete_offline_agents_id) is None:
        interval_hours = site_cfg.get("vnscanam", dict()).get(
            ScanConfigEnum.DELETE_OFFLINE_AGENTS_INTERVAL_HOURS.value,
            ScanConfigEnum.DELETE_OFFLINE_AGENTS_INTERVAL_HOURS_DEFAULT.value,
        )
        LOGGER.info(
            f"Adding delete offline agents job for site {site} with interval hours : {interval_hours}"
        )

        scheduler.add_job(
            delete_offline_agents_job,
            "interval",
            (site,),
            hours=interval_hours,
            next_run_time=datetime.datetime.now()
            + datetime.timedelta(minutes=first_runtime_delta),
            replace_existing=True,
            id=delete_offline_agents_id,
        )
    elif (
        not delete_offline_agents
        and scheduler.get_job(delete_offline_agents_id) is not None
    ):
        LOGGER.info(f"Removing job {delete_offline_agents_id}..")
        scheduler.remove_job(delete_offline_agents_id)


def _update_stig_linux_standard_scan_jobs(scheduler, site, hour_val, minute_val):
    stig_linux_standard_scan_job_id = f"{site}_stig_linux_standard_scan"
    property_namespace = PropertyNamespace.get_instance()
    site_cfg = property_namespace.site_to_site_cfg_map.get(site)
    stig_linux_standard_config = site_cfg.get(
        StigConfigEnum.STIG_LINUX_STANDARD_CONFIG.value, dict()
    )
    if stig_linux_standard_config:
        LOGGER.info(f"Adding cron job for stig linux standard scan for site {site}..")
        days = stig_linux_standard_config.get(
            ScheduleConfigEnum.DAYS.value,
            StigConfigEnum.LINUX_STANDARD_DAYS_DEFAULT.value,
        )
        scheduler.add_job(
            run_stig_standard_linux_scan,
            "cron",
            (site,),
            day_of_week=days,
            hour=hour_val,
            minute=minute_val,
            replace_existing=True,
            id=stig_linux_standard_scan_job_id,
        )
    elif scheduler.get_job(stig_linux_standard_scan_job_id):
        LOGGER.info(f"Removing job {stig_linux_standard_scan_job_id}..")
        scheduler.remove_job(stig_linux_standard_scan_job_id)


def _update_stig_linux_tailored_scan_jobs(scheduler, site, hour_val, minute_val):
    stig_linux_tailored_scan_job_id = f"{site}_stig_linux_tailored_scan"
    property_namespace = PropertyNamespace.get_instance()
    site_cfg = property_namespace.site_to_site_cfg_map.get(site)
    stig_linux_tailored_config = site_cfg.get(
        StigConfigEnum.STIG_LINUX_TAILORED_CONFIG.value, dict()
    )
    if stig_linux_tailored_config:
        LOGGER.info(f"Adding cron job for stig linux tailored scan for site {site}..")
        days = stig_linux_tailored_config.get(
            ScheduleConfigEnum.DAYS.value,
            StigConfigEnum.LINUX_TAILORED_DAYS_DEFAULT.value,
        )
        scheduler.add_job(
            run_stig_tailored_linux_scan,
            "cron",
            (site,),
            day_of_week=days,
            hour=hour_val,
            minute=minute_val,
            replace_existing=True,
            id=stig_linux_tailored_scan_job_id,
        )
    elif scheduler.get_job(stig_linux_tailored_scan_job_id):
        LOGGER.info(f"Removing job {stig_linux_tailored_scan_job_id}..")
        scheduler.remove_job(stig_linux_tailored_scan_job_id)


def _update_stig_amazon_standard_scan_jobs(scheduler, site, hour_val, minute_val):
    stig_amazon_standard_scan_job_id = f"{site}_stig_amazon_standard_scan"
    property_namespace = PropertyNamespace.get_instance()
    site_cfg = property_namespace.site_to_site_cfg_map.get(site)
    stig_amz_standard_config = site_cfg.get(
        StigConfigEnum.STIG_AMAZON_STANDARD_CONFIG.value, dict()
    )
    if stig_amz_standard_config:
        LOGGER.info(f"Adding cron job for stig amazon standard scan for site {site}..")
        days = stig_amz_standard_config.get(
            ScheduleConfigEnum.DAYS.value,
            StigConfigEnum.AMAZON_STANDARD_DAYS_DEFAULT.value,
        )
        scheduler.add_job(
            run_stig_standard_amazon_scan,
            "cron",
            (site,),
            day_of_week=days,
            hour=hour_val,
            minute=minute_val,
            replace_existing=True,
            id=stig_amazon_standard_scan_job_id,
        )
    elif scheduler.get_job(stig_amazon_standard_scan_job_id):
        LOGGER.info(f"Removing job {stig_amazon_standard_scan_job_id}..")
        scheduler.remove_job(stig_amazon_standard_scan_job_id)


def _remove_old_site_jobs(scheduler):
    property_namespace = PropertyNamespace.get_instance()
    removed_job_ids = []
    for job in scheduler.get_jobs():
        job_id = job.id
        if "_" not in job_id:
            continue
        site_name = job_id.rsplit("_")[0]
        LOGGER.info(f"Checking if {site_name} is present in property_namespace")
        if not property_namespace.site_to_site_cfg_map.get(site_name):
            removed_job_ids.append(job_id)
    for job_id in removed_job_ids:
        LOGGER.info(f"Removing job {job_id}..")
        scheduler.remove_job(job_id)
