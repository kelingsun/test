import csv
import os.path
import time
import urllib
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Set
from rapidsnail.utils.nessus_manager import NessusManager as Nessus
from rapidsnail.slug.abstract_nessus_client import AbstractNessusClient

from rapidsnail.slug.constants import (
    MetricsEnum,
    ScanTypeEnum,
    ScanConfigEnum,
    SCAN_TRACKING_FILE,
    SiteConfigEnum,
    ADHOC_SCAN_TRACKING_FILE,
    POLICIES_PATH,
    AUDIT_FILES_PATH,
    NetscanTypesEnum,
    ScanReportMetadataParams,
)
from rapidsnail.slug.helpers import get_falcon_env_vars, clear_scan_tracking, parse_response, get_fd_name, \
    get_fd_target_ip_range, get_targeted_netscan_suffix
from rapidsnail.slug.monitor import ServiceMonitor
from rapidsnail.slug.s3_client import S3Client
from rapidsnail.utils.constants import ValidRunningScanStateEnum, VaultKeysEnum

from rapidsnail.utils.logger import rs_log
from rapidsnail.utils.thread_config import file_locks


class Slug(AbstractNessusClient):
    """
    Class Slug: This class is designed to provide continuous Scanning
    using a yaml configured site design to Nessus at Salesforce.
    param site: the site (logical grouping) you want to perform coninuous scanning on
    """

    site: str = None
    nessus_host: str = None
    nessus_port: str = None
    # This is the path to the scan tracking csv, as scans complete this file tracks if they've been uploaded before
    rescanned_agent_flex_point = None

    def __init__(
        self,
        site: str,
        site_cfg,
        is_falcon: bool = False,
        argus_client: ServiceMonitor = None,
    ):
        super().__init__(is_falcon=is_falcon, argus_client=argus_client)

        # site and env specific configurations are loaded from this file.
        self.site = site
        self.site_cfg = site_cfg
        self.vnscanam_cfg = self.site_cfg.get("vnscanam", dict())
        self.scan_config = self.site_cfg.get("scan_config", dict())
        if "repository_name" in self.vnscanam_cfg:
            self.repository_name = self.vnscanam_cfg["repository_name"]
        else:
            self.repository_name = None

        self.major_bu = self.vnscanam_cfg.get("major_bu", self.env)
        self.minor_bu = self.vnscanam_cfg.get("minor_bu", self.site)
        if is_falcon:
            self.minor_bu, _, _ = get_falcon_env_vars()
        self.nessus_host = self.vnscanam_cfg.get("nessus_host")
        self.nessus_port = str(self.vnscanam_cfg.get("nessus_port"))
        self.argus_client.add_tags(additional_tags={"site": self.site})
        self.LOGGER = rs_log(__name__, self.site)

    def nessus_login(self):
        """
        Function to create a login to the Nessus Manager
        param site: a site specified in the config file to login.
        This allows all of the other functions to work with a single login
        """
        username: str = ""
        password: str = ""
        try:
            username = self.vault_manager.get_secret(VaultKeysEnum.USER_NAME.value)
            password = self.vault_manager.get_secret(VaultKeysEnum.PASSWORD.value)
            self._login_with_username_password(username, password)
        except Exception as err:
            self.LOGGER.warning(
                f"{self.site} : Encountered error {err} while trying to login to nessus"
            )
            self.argus_client.add_metric((MetricsEnum.NESSUS_LOGIN, 0))
            raise err

    def _login_with_username_password(self, username: str, password: str):
        # Connects and logs into Nessus
        try:
            cert = False
            # Not using verify for falcon as we use "localhost" as nessus manager name
            # and cert verification with this name will always fail

            if not self.is_falcon:
                cert = self.root_ca_file_path
            self.nessus = Nessus(self.nessus_host, self.nessus_port, verify=cert)
            self.nessus.login(username=username, password=password)
            # Adding this api call to ensure that login is successful and we're able to call APIs.
            self.get_folder_id()
            self.argus_client.add_metric(MetricsEnum.NESSUS_LOGIN)
            self.LOGGER.info(f"Successfully logged into {self.nessus_host} ")
        except Exception as err:
            self.LOGGER.error(f"Failed to Login to Nessus Manager {self.site} {err}")
            raise err

    def delete_agents(self, agent_ids):
        try:
            if not agent_ids:
                self.LOGGER.info(f"No agents to delete.")
                self.argus_client.add_metric(
                    (MetricsEnum.DELETED_AGENTS_COUNT.value, 0)
                )
                return
            self.nessus.delete("agents", json={"ids": agent_ids})
            self.LOGGER.info(f"Deleted {len(agent_ids)} offline agents..")
            self.argus_client.add_metric(
                (MetricsEnum.DELETED_AGENTS_COUNT.value, len(agent_ids))
            )
        except Exception as e:
            self.LOGGER.error(
                f"Encountered exception {e} while trying to delete offline agents"
            )
            raise e

    def get_agents(self, **kwargs):
        """
        This function will return a json blob of all the agent data
        """
        try:
            self.LOGGER.info(f"Going to pull agents data from {self.site}")
            agents = self.nessus.get("agents", **kwargs).json()
            agents_list = agents.get("agents")
            agents_list = agents_list if agents_list else list()
            return agents_list
        except Exception as err:
            self.LOGGER.error(f"Failed to pull agents data from {self.site}. {err}")
            raise err

    def get_ids_from_agents(self, agent_names: list):
        """
        This function return the list of Ids for a given set of agent names.

        :param agent_names: List of agent names
        :type agent_names: list

        :return Returns list of agent ids.
        :rtype: list
        """
        ctr = 0
        params = "filter.search_type=or"
        for agent in agent_names:
            if not isinstance(agent, str):
                self.LOGGER.warning(
                    f"Ignoring agent {agent} as it is not in str format."
                )
                continue
            url_safe_query = self.get_filter_query("name", agent, "eq", ctr)
            params = params + f"&{url_safe_query}"
            ctr += 1
        if ctr == 0:
            return []
        return self.get_agents_using_query(params)

    def get_filter_query(
        self, filter_name: str, filter_value: str, quality_value: str, ctr
    ):
        filter_query = {
            f"filter.{ctr}.filter": f"{filter_name}",
            f"filter.{ctr}.quality": f"{quality_value}",
            f"filter.{ctr}.value": f"{filter_value}",
        }
        url_safe_query = urllib.parse.urlencode(filter_query)
        return url_safe_query

    def get_agents_using_query(self, params: str):
        self.LOGGER.info(f"Getting agent id using query {params}")
        # Get query to nessus to fetch the filtered agents.
        agents_found = self.get_agents(params=params)
        ids = []
        for agent in agents_found:
            if "id" in agent:
                ids.append(agent["id"])
        return ids

    def get_offline_agents(self):
        self.LOGGER.info(f"Getting offline agents...")
        params = "filter.search_type=and"
        offline_agents_query = self.get_filter_query(
            filter_name="status", filter_value="offline", quality_value="eq", ctr=0
        )
        params = params + f"&{offline_agents_query}"
        offline_agents = self.get_agents(params=params)
        return offline_agents

    def get_available_agents_ip_using_query(self,):
        # This function returns the list of available agents IP for targeted netscans.
        # It will not be required after integration with SAI API (W-12356317)

        self.LOGGER.info(f"Getting IP's for available agents")
        #Prepare query for available agents
        url_safe_query = self.get_filter_query(filter_name="status", filter_value="online", quality_value="eq"
                                                     , ctr=0)
        params = "filter.search_type=and" + f"&{url_safe_query}"

        # Get query to nessus to fetch the filtered agents.
        agents_found = self.get_agents(params=params)
        agent_ips = ""
        for agent in agents_found:
            if "ip" in agent:
                agent_ips += agent["ip"] + ","
        agent_ips = agent_ips[:-1]
        return agent_ips

    def filter_agents_using_query(self, filter_name: str, filter_value: str):
        self.LOGGER.info(
            f"Filtering agents for stig scan using filter_name: {filter_name}, filter_value: {filter_value} "
        )
        # Filter the agnets for stig scan
        params = "filter.search_type=and"
        url_safe_query = self.get_filter_query(filter_name, filter_value, "match", 0)
        params = params + f"&{url_safe_query}"
        return self.get_agents_using_query(params)

    def _filter_agents(self, total_chunk_size: int) -> list:
        """
        This function takes the output of _get_agents() and filters the agent list creating a group with the number of
        agents defined in the configuration
        #1 agents that haven't been scanned ever
        #2 the agents that haven't been scanned in the last "scan_interval_hours" time duration
        """
        parent_agent_group_names = self.scan_config.get(
            ScanConfigEnum.PARENT_AGENT_GROUP_NAME.value, ""
        )
        excluded_group_names = self.scan_config.get(
            ScanConfigEnum.EXCLUDED_GROUP_NAMES.value, ""
        )
        if parent_agent_group_names:
            agents_data = self.get_from_parent_agent_groups(parent_agent_group_names)
        else:
            agents_data = self.get_agents()
        if not agents_data:
            self.argus_client.add_metric((MetricsEnum.AGENTS_COUNT, 0))
            return list()
        if excluded_group_names:
            agents_data = self._exclude_agents(excluded_group_names, agents_data)

        self.argus_client.add_metric((MetricsEnum.AGENTS_COUNT, len(agents_data)))
        online_agents_data = []
        online_agents_not_scanned = []
        online_agents_scanned = []

        # Populates the array online_agents_data will online agents
        for agent in agents_data:
            if "online" in agent["status"]:
                online_agents_data.append(agent)
        self.argus_client.add_metric(
            (MetricsEnum.ONLINE_AGENTS, len(online_agents_data))
        )
        # Populates the array online_agents_not_scanned with agents that are onlin but have never been scanned
        for online_agent in online_agents_data:
            if online_agent.get("last_scanned") is None:
                online_agents_not_scanned.append(online_agent)
                self.contains_only_scanned_for_day = False
            else:
                online_agents_scanned.append(online_agent)

        self.argus_client.add_metric(
            (MetricsEnum.AGENTS_NOT_SCANNED, len(online_agents_not_scanned))
        )
        # creates a new variable with last scan dates for online agents sorted from oldest to newest
        sorted_agents_scan_date = sorted(
            online_agents_scanned, key=lambda i: i.get("last_scanned")
        )

        add_group = []
        agent_counter = 0

        # This code loops over the online_agent_not_scanned list and adds them to the array add_group
        self.LOGGER.info(
            f"Adding {len(online_agents_not_scanned)} of never scanned agents to scan group"
        )
        for agent in online_agents_not_scanned:
            if agent_counter < total_chunk_size:
                add_group.append(agent["id"])
                agent_counter += 1

        self.LOGGER.info(
            f"Added {agent_counter} unscanned agents to the scan group for {self.site} "
        )

        if agent_counter >= total_chunk_size:
            self.LOGGER.info(
                f"Entire batch of size {total_chunk_size} filled, not adding additional agents."
            )
            self.LOGGER.info(
                f"Total agents scanned for {self.site} are {agent_counter}"
            )
            return add_group

        scan_type = self.scan_config.get("scan_type", ScanTypeEnum.DAILY.value)
        self.LOGGER.info(
            f"{scan_type} scan_type set in config. Adding additional agents accordingly."
        )
        agent_scan_history = datetime.utcnow() - timedelta(
            hours=self.scan_config.get(
                ScanTypeEnum.SCAN_INTERVAL_HOURS.value,
                ScanTypeEnum.SCAN_INTERVAL_DEFAULT_HOURS.value,
            )
        )
        agents_added = agent_counter
        for agent in sorted_agents_scan_date:
            if (
                scan_type == ScanTypeEnum.DAILY.value
                and agent["last_scanned"] < agent_scan_history.timestamp()
            ) or (scan_type == ScanTypeEnum.CONTINUOUS.value):
                add_group.append(agent["id"])
                agent_counter += 1
                today_timestamp = datetime.utcnow()
                beginning_day_timestamp = datetime(
                    today_timestamp.year,
                    today_timestamp.month,
                    today_timestamp.day,
                    tzinfo=timezone(timedelta(hours=0, minutes=0)),
                ).timestamp()
                if (
                    not self.rescanned_agent_flex_point
                    and agent["last_scanned"] > beginning_day_timestamp
                ):
                    self.rescanned_agent_flex_point = agent_counter

            if agent_counter >= total_chunk_size:
                # break early if no more space in the scans agent groups
                break
        agents_added = agent_counter - agents_added
        self.LOGGER.info(
            f"Added additional {agents_added} agents to the scan chunk based on {scan_type} scan type"
            f" rule for {self.site}"
        )
        self.LOGGER.info(f"Total agents scanned for {self.site} are {agent_counter}")
        if self.rescanned_agent_flex_point:
            self.LOGGER.info(
                f"{self.site} : some Scan contains only agents which have been scanned in last 24 hours "
                f"from {self.rescanned_agent_flex_point}"
            )

        return add_group

    def get_from_parent_agent_groups(self, parent_agent_groups):
        groups = parent_agent_groups.split(",")
        agents_data = []
        group_agent_ids = set()
        for group in groups:
            group = group.strip()
            response = self.get_agents_from_group(group)
            if response:
                for agent in response:
                    if agent["id"] not in group_agent_ids:
                        agents_data.append(agent)
                group_agent_ids |= {agent["id"] for agent in response}
        return agents_data

    def get_agents_from_group(self, agent_group_name) -> List[str]:
        self.LOGGER.info(f"Getting agents from agent group {agent_group_name}")
        agent_group_id = self._get_existing_agent_scan_group_id(agent_group_name)

        if agent_group_id is None:
            self.LOGGER.error(f"No agent group found with the name: {agent_group_name}")
            raise ValueError(f"No agent group found with the name: {agent_group_name}")
        try:
            self.LOGGER.info(f"Getting agents from agent group Id : {agent_group_id}")

            agent_group_details = self.nessus.get(
                f"agent-groups/{agent_group_id}"
            ).json()
            agents_list = agent_group_details.get("agents")
            agents_list = agents_list if agents_list else list()
            return agents_list
        except Exception as err:
            self.LOGGER.error(f"Failed to pull agents data from {self.site}. {err}")
            raise err

    def get_agent_scan_group(self, agent_scan_group_name) -> str:
        """
        Create an agent scan group with the name agent_scan_group_name.
        This scan group will be attached to the scan created by rapidsnail.
        Rapidsnail will continuously filter the agents which have not been scanned and add them to this agent
        scan group and launch the scan.
        """
        try:
            self.LOGGER.info(f"Pulling list of groups from {self.site}")
            group_id = self._get_existing_agent_scan_group_id(agent_scan_group_name)

            if group_id:
                return str(group_id)
            return self.create_new_agent_scan_group(agent_scan_group_name)
        except Exception as err:
            self.LOGGER.error(
                f"Error while trying to create the agent scan group on site {self.site}"
            )
            raise err

    def _exclude_agents(self, excluded_groups, agents_data):
        groups = excluded_groups.split(",")
        excluded_agent_ids = set()
        for group in groups:
            group = group.strip()
            response = self.get_agents_from_group(group)
            if response:
                self.LOGGER.info(
                    f"Excluding agents from group {group} for site {self.site}.."
                )
                excluded_agent_ids |= {agent["id"] for agent in response}

        new_agents_data = []
        if excluded_agent_ids:
            for agent in agents_data:
                if agent["id"] not in excluded_agent_ids:
                    new_agents_data.append(agent)
        else:
            return agents_data

        return new_agents_data

    def create_new_agent_scan_group(self, agent_scan_group_name) -> str:
        self.LOGGER.info(
            f"Attempting to create a scan group with name: {agent_scan_group_name}"
        )
        res = self.nessus.post(
            "agent-groups", json={"name": agent_scan_group_name}
        ).json()
        return str(res.get("id"))

    def _get_existing_agent_scan_group_id(self, group_name):
        """
        Fetches all the agent scan group from Nessus Manager and returns the id of the agent scan group name which
        matches the given arg.

        :param group_name: Name of the agent scan group name
        :type group_name: str
        """
        if not group_name or not isinstance(group_name, str):
            self.LOGGER.info("Provide a valid agent scan group name.")
            return None

        try:
            groups = self.nessus.get("agent-groups").json().get("groups", list())

            if not groups:
                self.LOGGER.info(
                    f"No agent groups available or accessible on {self.site}"
                )
                return None
            for group in groups:
                if group_name == group.get("name", ""):
                    group_id = group.get("id")
                    self.LOGGER.info(
                        f"Found scan group with name {group_name} with id {group_id} on site {self.site}."
                    )
                    return group_id

            self.LOGGER.info(
                f"Did not found any agent scan group with name {group_name} on site {self.site}"
            )
            return None

        except Exception as err:
            self.LOGGER.error(f"Error trying to fetch agent group id for: {group_name}")
            raise err

    def clear_scan_group(self, agent_scan_group_name) -> Optional[str]:
        """
        This function removes all the agents from a scan group so we can re-populate it.
        """
        try:
            group_id = self.get_agent_scan_group(agent_scan_group_name)
            self.nessus.delete(f"agent-groups/{group_id}/agents")
            self.LOGGER.info(
                f"Cleared the group {group_id} on {self.site} of its agents"
            )
            return group_id
        except Exception as err:
            self.LOGGER.error(
                f"Error while clearing the existing agent scan group {agent_scan_group_name} on {self.site}"
            )
            raise err

    def populate_agent_scan_groups(
        self, available_agent_groups_with_scan_names: Dict[str, str]
    ) -> List[str]:
        """
        Follows the following step:
        1. Clears out the agent scan group with name agent_scan_group_name
        2. Filters out the agents that need to be scanned based on _filter_agents function
        3. Updates the agent scan group with the agent list obtained in step 2
        4. Return True if everything went smooth, False otherwise
        """
        group_ids: List[str] = []
        available_agent_groups = list(available_agent_groups_with_scan_names.keys())
        for agent_group in available_agent_groups:
            group_ids.append(self.clear_scan_group(agent_group))

        # defines the number of agents we're going to put in the group
        chunk = self.scan_config.get(
            ScanConfigEnum.GROUP_SIZE.value,
            int(ScanConfigEnum.DEFAULT_GROUP_SIZE.value),
        )
        min_agents_required = self.scan_config.get(
            ScanConfigEnum.SCAN_MIN_AGENTS_REQUIRED.value,
            ScanConfigEnum.SCAN_MIN_AGENTS_REQUIRED_DEFAULT.value,
        )
        self.LOGGER.info(
            f"{self.site} site has capacity set to scan {chunk} agents in single scan"
        )
        total_chunk_size = chunk * len(available_agent_groups)
        filtered_agents_to_scan = self._filter_agents(total_chunk_size)
        populated_agent_groups: List[str] = []
        if filtered_agents_to_scan:
            filtered_agents_per_group = [
                filtered_agents_to_scan[i : i + chunk]
                for i in range(0, len(filtered_agents_to_scan), chunk)
            ]
            index: int = 0
            agent_counter = 1
            for agents_per_group in filtered_agents_per_group:
                group_id = group_ids[index]
                group_name = available_agent_groups[index]
                group_size = len(agents_per_group)
                if group_size < min_agents_required:
                    self.LOGGER.info(
                        f"Group size {group_size} is less than {min_agents_required}."
                        f"Omitting these agents from scanning for now."
                    )
                    continue
                try:
                    self.LOGGER.info(
                        f"Attempting to populate scan group {self.site}: {group_id} : {group_name}"
                        f" with {group_size} agents"
                    )
                    self.populate_agent_group(group_id, agents_per_group)

                    populated_agent_groups.append(group_name)
                    index += 1
                    if (
                        self.rescanned_agent_flex_point
                        and agent_counter >= self.rescanned_agent_flex_point
                    ):
                        new_scan_name = (
                            available_agent_groups_with_scan_names.get(group_name)
                            + "_rescanned"
                        )
                        available_agent_groups_with_scan_names.update(
                            {group_name: new_scan_name}
                        )
                        self.LOGGER.info(
                            f"Group : {group_name} and scan {new_scan_name} contains only rescanned agents"
                        )

                    agent_counter += group_size

                except Exception as err:
                    self.LOGGER.error(
                        f"Error populating {self.site} scan group {group_id} : {group_name}"
                    )
                    self.LOGGER.error(f"{err}")
                    raise err

            self.argus_client.add_metric(
                (MetricsEnum.FILTERED_AGENT, len(filtered_agents_to_scan))
            )
            self.argus_client.push_metrics()
            self.LOGGER.info(
                f"Successfully populated scan group with {len(filtered_agents_to_scan)} agents"
            )
        else:
            self.LOGGER.info("There are no hosts to add to these groups.")
        return populated_agent_groups

    def populate_agent_group(self, group_id, agent_ids: List[str]):
        self.LOGGER.info(
            f"Attempting to populate scan group {self.site}: {group_id}"
            f" with {len(agent_ids)} agents"
        )
        self.nessus.put(f"agent-groups/{group_id}/agents", json={"ids": agent_ids})

    def _get_beehive_user_id(self) -> Optional[str]:
        """
        Returns user id for a user which has "beehive" in the username.

        This user is added to scan with modify permission so when logging
        in the UI via this username the scan created by rapidsnail is accessible.
        """
        try:
            users = self.nessus.get("users").json().get("users", list())

            if not users:
                self.LOGGER.warning(
                    f"{self.site} don't seem to have any users available."
                )
                return None

            for user in users:
                if "beehive" in user.get("username", "").lower():
                    return str(user.get("id"))

            self.LOGGER.error(f"beehive_user not found on {self.site}")
        except Exception as err:
            self.LOGGER.error(
                f"Error trying to fetch the users information from site: {self.site}"
            )
            self.LOGGER.error(err)

    def get_folder_id(self):
        """
        This function returns the 'My Scans' folder's id.
        """
        try:
            self.LOGGER.info(f"Getting folder id of the My Scans folder")
            folders = self.nessus.get("folders").json().get("folders", dict())
            dest_folder = None
            for folder in folders:
                if "My Scans" in folder.get("name", ""):
                    dest_folder = folder["id"]

            if not dest_folder:
                raise ValueError(
                    f"Could not find a folder on {self.nessus_host} with My Scans in name"
                )

            return dest_folder
        except Exception:
            raise

    def _get_policy_template_uuid(self, policy_name="Advanced Agent Scan"):
        """
        Getting the policy template UUID of the name specified in the YAML config
        """
        try:
            templates = self.nessus.get("editor/policy/templates").json()["templates"]
            self.LOGGER.info(
                f"Successfully retrieved the policy templates from {self.site}"
            )

            for template in templates:
                if policy_name in template.get("title", ""):
                    return template["uuid"]
        except Exception as err:
            self.LOGGER.error(f"Failed to get policy templates from {self.site}")
            self.LOGGER.error(f"{err}")
            raise err

    def get_policy_id(self, req_policy=None):
        """
        Get policy id of the policy name specified in the YAML Config file
        """

        required_policy: str = req_policy or self.scan_config.get(
            ScanConfigEnum.SCAN_POLICY_NAME.value, ""
        )
        if not required_policy:
            self.LOGGER.info(f"No policy name provided. Going with default policy")
            return None
        try:
            policies = self.nessus.get("policies").json().get("policies", list())
            if policies is not None:
                self.LOGGER.info(
                    f"Successfully retrieved the policies from {self.site}"
                )
                for policy in policies:
                    name = policy.get("name", "")
                    if name == required_policy:
                        required_id = policy.get("id")
                        self.LOGGER.info(
                            f"Found Policy Id {required_id} for policy name {required_policy}"
                        )
                        return required_id
            self.LOGGER.info(
                f"Policy {required_policy} not found on the manager. Trying to upload.."
            )
            policy_file_path = f"{POLICIES_PATH}/{required_policy}.nessus"
            if os.path.isfile(policy_file_path):
                self.LOGGER.info(
                    f"File {policy_file_path} is present.. Creating the policy."
                )
                policy_id = self.create_policy(policy_file_path=policy_file_path)
                self.LOGGER.info(
                    f"Created Policy Id {policy_id} for policy name {required_policy}"
                )
                return policy_id
            else:
                self.LOGGER.warning(
                    f"Did not find any policy/policy file for policy name {required_policy}.."
                )
                raise ValueError(
                    f"Did not find any policy/policy file for policy name {required_policy}.."
                )
        except Exception as err:
            self.LOGGER.warning(
                f"Encountered error {err} while getting policy Id for"
                f": {required_policy} from {self.site}"
            )
            self.argus_client.add_metric(
                MetricsEnum.NO_POLICY_FOUND,
                additional_tags={"policy_name": required_policy},
            )
            self.argus_client.push_metrics()
            self.LOGGER.warning(f"{err}")
            return None

    def get_scan_id(self, scan_name: str):
        """
        After a scan is created, we need to know the id of the scan, this returns that value.
        """
        try:
            dest_folder = self.get_folder_id()
            self.LOGGER.info(
                f"attempting to get scan details to return the scan id of a created scan"
            )
            scans = (
                self.nessus.get("scans", json={"folder_id": dest_folder})
                .json()
                .get("scans", list())
            )
            for scan in scans:
                if scan_name == scan.get("name", ""):
                    return str(scan.get("id"))
            self.LOGGER.info(f"{scan_name} named scan not found on site {self.site}")
            return None
        except Exception as err:
            self.LOGGER.error(f"Error getting scan details")
            self.LOGGER.error(f"{err}")

    def get_uuid(self, scan_name: str):
        """
        get's the UUID of the scan that was started in order to track the particular instance of the scan
        """

        scan_id = self.get_scan_id(scan_name)

        try:
            self.LOGGER.info(
                f"Attempting to get UUID for scan {scan_id} for {self.site}"
            )
            scan_uuid = self.nessus.get(f"scans/{scan_id}").json()["info"]["uuid"]
            self.LOGGER.info(
                f"Successfully got {scan_uuid} from scan {scan_id} for {self.site}"
            )
            return scan_uuid
        except Exception as err:
            self.LOGGER.error(
                f"Error retrieving UUID for scan {scan_id} for {self.site}"
            )
            self.LOGGER.error(f"{err}")

    def delete_scan_history(self, scan_name: str):
        """
        Delete's history before mentioned hours for scan so the manager doesn't fill up on space
        """
        try:
            dest_scan = self.get_scan_id(scan_name)
            scan_history = self.nessus.get(f"scans/{dest_scan}").json().get("history")
            self.LOGGER.info(f"Successfully pulled scan history for {scan_name}")
            delete_before_hours = self.scan_config.get(
                ScanConfigEnum.SCAN_HISTORY_RETENTION_TIME.value,
                ScanConfigEnum.SCAN_HISTORY_RETENTION_TIME_DEFAULT.value,
            )
            if not scan_history:
                return
            threshold_timestamp = datetime.utcnow() - timedelta(
                hours=delete_before_hours
            )
            threshold_timestamp = threshold_timestamp.timestamp()
            self.LOGGER.info(
                f"Attempting to remove history before {delete_before_hours} hours for scan {scan_name}"
            )
            for history in scan_history:
                delete_id = history["history_id"]
                try:
                    if history["last_modification_date"] < threshold_timestamp:
                        delete_id = history["history_id"]
                        self.nessus.delete(f"scans/{dest_scan}/history/{delete_id}")
                        self.LOGGER.info(
                            f"Deleted history id {delete_id} for scan {scan_name}"
                        )
                except Exception as e:
                    self.LOGGER.error(
                        f"Failed to delete history {delete_id} for {scan_name}, error {e}"
                    )
        except Exception as err:
            self.LOGGER.error(f"Error fetching scan history for {scan_name}: {err}")
            raise err

    def create_scan(self, scan_name: str, agent_group_name: str):
        """
        Creates a scan with name: scan_name with the following properties:
            uuid: UUID of the "Advanced Agent Scan" Template
            settings:
                name: scan_name
                description: (This doesn't matter, but is a required field by tenable)
                launch: ON_DEMAND, this makes sure that the scan don't run on a schedule
                timezone: UTC
                acls: Adds the beehive user with modify permissions.
                enabled: "false" This an ambiguous field which dictates if the scan is suppose to be scheduled.
                scan_time_window: Time duration for which this scan should allow agents to report scan data
                agent_group_id: List of strings denoting the agent groups which will be a part of the scan.

        NOTE: If a scan with name scan_name already exist, this method will just make sure that the
        correct agent group is added to the scan.
        """
        try:
            group_id = [self.get_agent_scan_group(agent_group_name)]
            beehive_user_id = self._get_beehive_user_id()
            dest_folder = self.get_folder_id()
            dest_scan = self.get_scan_id(scan_name)
            dest_policy_template = self._get_policy_template_uuid(
                policy_name=self.scan_config.get(
                    "scan_template", ScanConfigEnum.DEFAULT_SCAN_TEMPLATE.value
                )
            )
            dest_policy_id = self.get_policy_id()
            beehive_acl = list()
            if beehive_user_id:
                beehive_acl.append(
                    {
                        "id": beehive_user_id,  # Adds user with beehive in name to the scan
                        "owner": 0,
                        "permissions": 64,  # Tenable uses 64 to indicate modify permissions.
                        "type": "user",
                    }
                )

            # Loads the audit files configuration from scan config
            audit_list = self.scan_config.get(ScanConfigEnum.AUDIT_FILES.value, list())

            # Configure the policy with the audit files from configuration
            if audit_list is not None and len(audit_list) > 0:
                self.add_audit_files_to_policy(dest_policy_id, audit_list)
            else:
                self.LOGGER.info(
                    f" Audit files configuration not present for the site: {self.site} , "
                    f"hence policy not configured with audit files for site: {self.site}"
                )
                self.argus_client.add_metric(MetricsEnum.NO_AUDIT_CONFIG_FOUND)

            # Payload to use if the creating the destination scan from scratch.
            settings_payload = {
                "name": scan_name,
                "description": "Scan created by rapidsnail.",
                "launch": "ON_DEMAND",
                "timezone": "UTC",
                "acls": beehive_acl,
                "enabled": "false",  # indicates that this scan is not supposed to be on a schedule,
                "folder_id": str(dest_folder),
                "scan_time_window": str(
                    self.scan_config.get(
                        ScanConfigEnum.SCAN_TIME_WINDOW.value,
                        ScanConfigEnum.DEFAULT_SCAN_TIME_WINDOW_IN_MINUTES.value,
                    )
                ),
                "agent_group_id": group_id,
            }

            # payload to use when scan already exists but need to make sure that the correct
            # agent scan group is added.
            existing_scan_payload = {
                "name": scan_name,
                "description": "Scan created by rapidsnail.",
                "agent_group_id": group_id,
                "scan_time_window": str(
                    self.scan_config.get(
                        ScanConfigEnum.SCAN_TIME_WINDOW.value,
                        ScanConfigEnum.DEFAULT_SCAN_TIME_WINDOW_IN_MINUTES.value,
                    )
                ),
            }
            if dest_policy_id:
                settings_payload["policy_id"] = dest_policy_id
                existing_scan_payload["policy_id"] = dest_policy_id

            payload = {
                "uuid": dest_policy_template,
                "settings": existing_scan_payload if dest_scan else settings_payload,
            }
            error_on_configure = False
            res = None
            if dest_scan:
                self.LOGGER.info(
                    f"Site {self.site} already has a scan with id {dest_scan}"
                )
                res = self.nessus.put("scans/{}".format(dest_scan), json=payload)
                self.argus_client.add_metric(MetricsEnum.SCAN_UPDATED)
                self.LOGGER.info(
                    f"Site: {self.site} Made a PUT request with payload {payload} on scan with id {dest_scan}"
                )
                if not res.ok:
                    # error status_code comes when the scan doesn't exist or is corrupt, indicating someone manually removed the
                    # scan recently. Try creating the scan again.
                    self.LOGGER.warning(
                        f"Got code {res.status_code} while trying to update: {dest_scan}; host {self.nessus_host}; site {self.site}"
                    )
                    error_on_configure = True

            if not dest_scan or error_on_configure:
                self.LOGGER.info(
                    f"Site: {self.site} Attempting to create a scan for continuous scanning for {self.site}"
                )
                res = self.nessus.post("scans", json=payload)
                self.argus_client.add_metric(MetricsEnum.SCAN_CREATED)
                self.LOGGER.info(
                    f"Site: {self.site} Created a scan for continuous scanning for {self.site} with properties"
                    f" {payload}"
                )

            if res and not res.ok:
                # both PUT and POST requests return ONLY 200 code if everything went well.
                self.argus_client.add_metric(MetricsEnum.SCAN_CREATION_ERROR)
                raise Exception(
                    f"Error trying to update/create the scan on host {self.nessus_host}, site {self.site}. {res.reason}"
                )
        except Exception as err:
            self.LOGGER.error(
                f"Error while trying to create the Agent Scan on site {self.site}"
            )
            raise err

    def start_scan(self, scan_name: str):
        """
        Kicks off a scan after it's created
        """

        dest_scan = self.get_scan_id(scan_name)
        if dest_scan:
            try:
                self.LOGGER.info(f"Attempting to start scan {dest_scan} on {self.site}")
                self.nessus.post(f"scans/{dest_scan}/launch")
                self.argus_client.add_metric(MetricsEnum.LAUNCH_SCAN)
                self.LOGGER.info(
                    f"Successfully started scan {dest_scan} on {self.site}"
                )
            except Exception as err:
                self.LOGGER.error(f"{err}")
                if "500" not in str(err):
                    self.argus_client.add_metric((MetricsEnum.LAUNCH_SCAN, 0))
                    self.LOGGER.error(
                        f"Failed to start scan {dest_scan} on {self.site}"
                    )
                    raise err
                else:
                    self.LOGGER.info(f"Encountered Api error [500]..")
                    self.argus_client.add_metric(MetricsEnum.LAUNCH_SCAN)
                    self.LOGGER.info(
                        f"Successfully started scan {dest_scan} on {self.site}"
                    )
            self.argus_client.push_metrics()
            self.LOGGER.info(f"Scan is running and this job is complete.")
        else:
            self.argus_client.add_metric((MetricsEnum.LAUNCH_SCAN, 0))
            self.LOGGER.error(f"Failed to start scan {dest_scan} on {self.site}")
            self.LOGGER.error(f"No Scan found with name {scan_name}")
            raise Exception(f"No scan found with name {scan_name}")

    def track_scan_data(
        self, scan_name: str, filename=SCAN_TRACKING_FILE, scan_config=None
    ):
        """
        appends a row to the tracking sheet based on scan that was created
        """
        tracking_path = os.path.abspath(filename)

        dest_scan = self.get_scan_id(scan_name)
        dest_uuid = self.get_uuid(scan_name)
        if not scan_config:
            scan_config = self.scan_config

        try:
            self.LOGGER.info(
                f"Getting scan details for scan {dest_scan} for tracking information on {self.site} in {filename}"
            )
            scan_details = self.nessus.get(f"scans/{dest_scan}").json()["info"]
            scan_start = datetime.fromtimestamp(int(scan_details["scan_start"]))
            scan_end = scan_start + timedelta(
                minutes=int(scan_config["scan_time_window"])
            )
            scan_end = int(scan_end.timestamp())
            row = [
                self.site,
                self.nessus_host,
                dest_scan,
                scan_name,
                dest_uuid,
                scan_details["status"],
                int(scan_details["scan_start"]),
                int(scan_config["scan_time_window"]),
                scan_end,
                int(scan_details.get("hostcount", 0)),
            ]
            self.LOGGER.info(
                f"Adding the following to scan tracking file {filename}: {row}"
            )
            file_lock = file_locks.get(filename)
            file_lock.acquire()
            with open(tracking_path, "a") as csvFile:
                writer = csv.writer(csvFile)
                writer.writerow(row)
            file_lock.release()
        except Exception as err:
            self.LOGGER.error(
                f"Encountered {err} while trying to write to tracking file {filename}"
            )
            file_lock.release()
            raise err

    def export_scan(self, scan_id: str, scan_uuid: str) -> dict:
        """
        This function is designed to look at the tracking document in order to export the scan currently stored there.

        :param scan_id: Id of the scan to export from Nessus Manager.
        :param scan_uuid: UUID of the scan which is generated by the Nessus Manager.
        """
        try:
            self.LOGGER.info(f"Pulling status of scan {scan_id} for {self.site}...")
            scan_response = self.nessus.get(f"scans/{scan_id}").json()
            scan_status = scan_response.get("info", dict()).get("status").lower()
            scan_type = scan_response.get("info", dict()).get("scan_type", "").lower()
            scan_name = scan_response.get("info", dict()).get("name")

            self.LOGGER.info(
                f"Pulled status of scan {scan_id} for {self.site}, if complete  rapidsnail will export it"
            )
            if "completed" in scan_status:
                if "remote" in scan_type:
                    if get_targeted_netscan_suffix() in scan_name:
                        res = self.export_network_scan(
                            scan_id=scan_id, scan_response=scan_response, scan_type_name = NetscanTypesEnum.TARGETED_NETSCAN.value
                        )
                    else :
                        res = self.export_network_scan(
                            scan_id=scan_id, scan_response=scan_response
                        )
                else:
                    if "stig" in scan_name:
                        scan_type_name = scan_name.split("_")[-2]
                        res = self.export_agent_scan(
                            scan_id=scan_id,
                            scan_response=scan_response,
                            scan_type_name=scan_type_name,
                        )
                    else:
                        res = self.export_agent_scan(
                            scan_id=scan_id, scan_response=scan_response
                        )
                self.argus_client.push_metrics()
                return res

            else:
                self.LOGGER.info(
                    f"{self.site} scan with id {scan_id} has not completed and is in {scan_status} status"
                )
                self.argus_client.add_metric((MetricsEnum.EXPORT_SCAN, 0))
                is_running: bool = False
                for state in ValidRunningScanStateEnum.list():
                    if state in scan_status:
                        is_running = True
                        break
                if not is_running:
                    raise Exception(
                        f"{self.site} scan with id {scan_id} is in {scan_status} status"
                    )
        except Exception as err:
            self.LOGGER.error(
                f"Failed to export the scan on site: {self.site} with error: {err}"
            )
            self.argus_client.add_metric(MetricsEnum.EXPORT_ERROR)
            clear_scan_tracking(site=self.site, uuid=scan_uuid)
            clear_scan_tracking(
                site=self.site, uuid=scan_uuid, file_name=ADHOC_SCAN_TRACKING_FILE
            )
            raise err
        finally:
            self.argus_client.push_metrics()

    def export_agent_scan(self, scan_id, scan_response, scan_type_name=None):
        history_ids: List[str] = self._get_last_run_ids(scan_response)
        files_exported = dict()
        for last_run_scan_id in history_ids:
            scan_start, scan_end = self._export_scan_report(last_run_scan_id, scan_id)
            # Means that last_run_scan_id doesn't have any reported agents
            if not scan_start:
                continue

            # Once we verify the status of the scan is completed, we download the file, output to a file
            # and return the filename
            export = self.nessus.post(
                f"scans/{scan_id}/export?history_id={last_run_scan_id}",
                json={"format": "nessus"},
            ).json()
            self.LOGGER.info(
                f"Successfully launched the export of scan {scan_id} from {self.site}"
            )
            token = export.get("token")
            if token is None:
                raise ValueError(
                    f"{self.site} No token generated for export of scan: {scan_id}, history_id"
                    f":{last_run_scan_id}"
                )
            export_status_endpoint = f"tokens/{token}/status"
            export_status = self.nessus.get(export_status_endpoint).json()
            while export_status["status"] != "ready":
                time.sleep(30)
                export_status = self.nessus.get(export_status_endpoint).json()
            # Attempt to download the scan results once completed from Nessus
            self.LOGGER.info(
                f"Attempting to download scan: scanId {scan_id}, history_id: {last_run_scan_id} from {self.site}"
            )
            scan_data = self.nessus.get(f"tokens/{token}/download")
            self.LOGGER.info(f"Successfully Downloaded scan {scan_id} from {self.site}")

            if scan_type_name is not None:
                filename = self._get_export_file_name(
                    scan_id, last_run_scan_id, scan_type=scan_type_name
                )
            else:
                filename = self._get_export_file_name(scan_id, last_run_scan_id)

            # TODO: Temporary fix for now, to push info into aws_information table till we fix the DAG
            if "cdpfalcon" in self.site.lower():
                filename = f"falcon_{filename}"
            # dump the downloaded content to a file
            self.LOGGER.info(f"Writing the output of the download to: {filename}")
            nessus_file_path = os.path.abspath(f"data/{filename}.nessus")
            with open(nessus_file_path, "wb") as zfile:
                zfile.write(scan_data.content)
            self.argus_client.add_metric(MetricsEnum.EXPORT_SCAN)
            filename = filename + ".nessus"

            files_exported[filename] = self._get_export_file_metadata(last_run_scan_id)
            self.LOGGER.info(
                f"Scan start time for file {filename} is {scan_start} and end time is {scan_end}"
            )
            tags = {
                "scan_id": filename,
                "major_bu": self.major_bu,
                "minor_bu": self.minor_bu,
            }
            self.argus_client.add_metric(
                (MetricsEnum.SCAN_START_TIME, scan_start), additional_tags=tags
            )
            self.argus_client.add_metric(
                (MetricsEnum.SCAN_END_TIME, scan_end), additional_tags=tags
            )
        if not files_exported or len(files_exported) == 0:
            self.LOGGER.error(f"No scan results to export")
            raise RuntimeError("Scan completed with zero results..")
        self.LOGGER.info(
            f"{self.site} scan with id {scan_id} has exported {len(files_exported)} files."
        )
        self.LOGGER.info(f"{self.site}:{scan_id}:  {files_exported}")

        return files_exported

    def _get_last_run_ids(self, scan_response) -> List[str]:
        is_clustering_enabled = self.vnscanam_cfg.get(
            SiteConfigEnum.CLUSTER_ENABLED.value,
            SiteConfigEnum.DEFAULT_IS_CLUSTER_ENABLED.value,
        )
        self.LOGGER.info(
            f"{self.site} has clustering enabled set to {is_clustering_enabled}"
        )
        scan_history = scan_response.get("history", list())
        size = len(scan_history)
        node_id_to_history_id_map: Dict[str, str] = dict()
        for i in range(size):
            current_node_id = scan_history[i].get("node_id", "")
            if is_clustering_enabled:
                if not current_node_id:
                    continue
            else:
                current_node_id = "id"
            current_history_id = scan_history[i].get("history_id", "-1")
            if int(node_id_to_history_id_map.get(current_node_id, "-1")) <= int(
                current_history_id
            ):
                node_id_to_history_id_map.update({current_node_id: current_history_id})
        history_ids = list(node_id_to_history_id_map.values())
        self.LOGGER.info(
            f"Fetched latest history Id : {node_id_to_history_id_map} for {self.site}"
        )
        return history_ids

    def _export_scan_report(self, last_run_scan_id, scan_id):
        param = {"history_id": last_run_scan_id}
        scan_history_response = self.nessus.get(f"scans/{scan_id}", json=param).json()
        total_agent_count: int = int(
            scan_history_response.get("info", {}).get("agent_count", 0)
        )
        host_count: int = int(scan_history_response.get("info", {}).get("hostcount", 0))
        scan_start = str(scan_history_response.get("info", {}).get("scan_start", ""))
        scan_end = str(scan_history_response.get("info", {}).get("scan_end", ""))
        self.LOGGER.info(
            f"Total agent count for scanId : {scan_id}, history_id {last_run_scan_id}"
            f" was {total_agent_count} for site {self.site}"
        )
        self.LOGGER.info(
            f"Total agent reported for scanId : {scan_id} history_id {last_run_scan_id}"
            f" was {host_count} for site {self.site}"
        )

        # Rare scenario where scan completes without any results..
        # Need to clean scan from tracking file and throw a failure metrics in such cases
        if total_agent_count == 0 or host_count == 0:
            self.LOGGER.error(f"{self.site} : Scan completed with zero results.. ")
            self.LOGGER.error(
                f"{self.site} : Cleaning history id: {last_run_scan_id} as it"
                f" completed with zero results.. "
            )
            # self.nessus.delete(f"scans/{scan_id}/history/{last_run_scan_id}")
            return None, None

        missed_agent_count = total_agent_count - host_count
        self.LOGGER.info(
            f"Missed agent count for scanId : {scan_id}, history_id {last_run_scan_id}"
            f" was {missed_agent_count} for site {self.site}"
        )
        tags = {
            "repository_name": f"{self.repository_name}"
            if self.repository_name
            else "",
            "history_id": str(last_run_scan_id),
            "scan_id": str(scan_id),
        }
        self.argus_client.add_metric(
            (MetricsEnum.SCAN_TOTAL_AGENTS_COUNT, total_agent_count)
        )
        self.argus_client.add_metric(
            (MetricsEnum.SCAN_MISSED_AGENTS_COUNT, missed_agent_count),
            additional_tags=tags,
        )
        self.argus_client.add_metric(
            (MetricsEnum.SCAN_AGENTS_REPORTED_COUNT, host_count), additional_tags=tags
        )
        return scan_start, scan_end

    def _get_export_file_name(self, scan_id, last_run_scan_id, scan_type=None):
        # This is where we are setting the filename of the download
        time_format = datetime.utcnow().strftime("%Y-%m-%d-%H%M")
        site_name = self.site.replace("_", "-")
        last_run_scan_id = str(last_run_scan_id).replace("_", "-")
        scan_id = str(scan_id).replace("_", "-")
        self.LOGGER.info(f"Getting file name for site: {self.site} scan {scan_id}")
        if self.is_falcon:
            fi_name, _, _ = get_falcon_env_vars()
            if scan_type is not None:
                filename = f"falcon_{fi_name}_{scan_id}_{scan_type}-scan_{last_run_scan_id}_{time_format}"
            else:
                filename = f"falcon_{fi_name}_{scan_id}_agent-scan_{last_run_scan_id}_{time_format}"
        elif self.repository_name and "_" not in self.repository_name:
            filename = f"{self.env}_{site_name}_{last_run_scan_id}_{self.repository_name}_{time_format}"
        else:
            filename = (
                f"{self.env}_{site_name}_{scan_id}_{last_run_scan_id}_{time_format}"
            )
        return filename

    def _get_export_file_metadata(self, last_run_scan_id, additional_metadata={}):
        is_falcon_file = "False"
        data_center = str(self.site)
        if self.is_falcon or "cdpfalcon" in self.site.lower():
            is_falcon_file = "true"
        fi_name = None
        if self.is_falcon:
            fi_name, _, _ = get_falcon_env_vars()
            data_center = self.repository_name
        metadata = {
            ScanReportMetadataParams.CONSOLE.value: str(self.env),
            ScanReportMetadataParams.DATA_CENTER.value: data_center,
            ScanReportMetadataParams.REPO_NAME.value: str(
                self.repository_name if self.repository_name else self.site
            ),
            ScanReportMetadataParams.SCAN_ID.value: str(last_run_scan_id),
            ScanReportMetadataParams.TIME_FORMAT.value: str(
                datetime.utcnow().strftime("%Y-%m-%d-%H%M")
            ),
            ScanReportMetadataParams.IS_FALCON_FILE.value: str(is_falcon_file),
            ScanReportMetadataParams.FI_NAME.value: str(fi_name),
        }
        metadata.update(additional_metadata)
        return metadata

    def export_network_scan(self, scan_id: str, scan_response, scan_type_name = None) -> dict:
        """
        This function is designed to look at the tracking document in order to export the scan currently stored there.

        :param scan_id: Id of the scan to export from Nessus Manager.
        :param scan_response: Scan response from REST call to nessus manager
        """
        try:
            self.LOGGER.info(f"Pulling status of scan {scan_id} for {self.site}...")
            scanner_name = scan_response.get("info", dict()).get("scanner_name").lower()
            fd_name = get_fd_name(scanner_name)
            self.LOGGER.info(
                f"Pulled status of scan {scan_id} for {self.site}, if complete  rapidsnail will export it"
            )

            # Once we verify the status of the scan is completed, we download the file, output to a file
            # and return the filename
            export = self.nessus.post(
                f"scans/{scan_id}/export", json={"format": "nessus"}
            ).json()
            self.LOGGER.info(
                f"Successfully launched the export of scan {scan_id} from {self.site}"
            )
            token = export.get("token")
            if token is None:
                raise ValueError(
                    f"{self.site} No token generated for export of scan: {scan_id}"
                )
            export_status_endpoint = f"tokens/{token}/status"
            export_status = self.nessus.get(export_status_endpoint).json()
            while export_status["status"] != "ready":
                time.sleep(30)
                export_status = self.nessus.get(export_status_endpoint).json()
            # Attempt to download the scan results once completed from Nessus
            self.LOGGER.info(
                f"Attempting to download scan: scanId {scan_id} from {self.site}"
            )
            scan_data = self.nessus.get(f"tokens/{token}/download")
            self.LOGGER.info(f"Successfully Downloaded scan {scan_id} from {self.site}")

            filename = self._get_export_net_scan_filename(scan_id, fd_name, scan_type_name)
            filename = filename + ".nessus"
            # dump the downloaded content to a file
            self.LOGGER.info(f"Writing the output of the download to: {filename}")
            nessus_file_path = os.path.abspath(f"data/{filename}")
            with open(nessus_file_path, "wb") as zfile:
                zfile.write(scan_data.content)
            self.argus_client.add_metric(MetricsEnum.EXPORT_SCAN)

            metadata = self._get_export_file_metadata(
                scan_id, additional_metadata={"fd_name": fd_name}
            )
            self.LOGGER.info(
                f"{self.site} scan with id {scan_id} has exported to {filename}"
            )
            return {filename: metadata}
        except Exception as e:
            self.LOGGER.error(f"Exporting network scan failed with error : {e}")
            raise e

    def _get_export_net_scan_filename(self, scan_id, fd_name=None, scan_type_name = None):
        # This is where we are setting the filename of the download
        time = datetime.utcnow().strftime("%Y-%m-%d-%H%M")
        site_name = self.site.replace("_", "-")
        scan_id = str(scan_id).replace("_", "-")
        self.LOGGER.info(f"Getting file name for site: {self.site} scan {scan_id}")
        if self.is_falcon:
            if scan_type_name is not None and scan_type_name == NetscanTypesEnum.TARGETED_NETSCAN.value:
                fi_name, _, _ = get_falcon_env_vars()
                filename = f"falcon_{fi_name}_{fd_name}_{scan_id}_targeted-agents-net-scan_{time}"
            else :
                fi_name, _, _ = get_falcon_env_vars()
                filename = f"falcon_{fi_name}_{fd_name}_{scan_id}_net-scan_{time}"
        else:
            filename = f"{self.env}_{site_name}_{scan_id}_net-scan_{time}"
        return filename

    def get_running_scans(self) -> Set[str]:
        running_scans: Set[str] = set()
        scans = self.nessus.get("scans").json().get("scans", list())
        if not scans:
            self.LOGGER.info(f"No scans found on site {self.site}")
            return running_scans
        for scan in scans:
            status = scan.get("status", "").lower()
            is_running: bool = False
            for state in ValidRunningScanStateEnum.list():
                if state in status:
                    is_running = True
                    break
            if is_running:
                running_scans.add(scan["name"])
        return running_scans

    def upload_data(
        self,
        file: str,
        s3_proxy: str,
        s3_bucket: str,
        s3_path: str,
        s3_region: str = None,
        metadata=None,
    ):
        """
        This function will upload the file to S3
        """
        try:
            s3_client = S3Client(self.is_falcon, vault_manager=self.vault_manager)
            self.LOGGER.info(f"Proceeding to upload data to s3 bucket..")
            s3_client.upload_data(
                file, s3_proxy, s3_bucket, s3_path, s3_region, metadata
            )
            self.argus_client.add_metric(
                (MetricsEnum.S3_UPLOAD, 1), additional_tags={"bucket": s3_bucket}
            )
            self.argus_client.add_metric(
                (MetricsEnum.S3_UPLOAD_TIME, int(datetime.now().timestamp())),
                additional_tags={
                    "scan_id": file,
                    "bucket": s3_bucket,
                    "major_bu": self.major_bu,
                    "minor_bu": self.minor_bu,
                },
            )
        except Exception as e:
            self.LOGGER.error(
                f"Upload to s3 failed with error {self.site}, {self.nessus_host} with Exception {e} "
            )
            self.argus_client.add_metric(
                (MetricsEnum.S3_UPLOAD, 0), additional_tags={"bucket": s3_bucket}
            )
            raise e

    def create_policy(self, policy_file_path):
        try:
            files = {"Filedata": open(policy_file_path, "rb")}
            upload_res = self.nessus.post("file/upload", files=files)
            if upload_res and not upload_res.ok:
                self.argus_client.add_metric(MetricsEnum.POLICY_CREATION_ERROR)
                raise Exception(
                    f"Error trying to upload the policy file on host {self.nessus_host}, site {self.site}"
                    f". {upload_res.reason}"
                )
            self.LOGGER.info(f"File uploaded {upload_res.json()}")
            res = self.nessus.post(
                "policies/import", json={"file": upload_res.json().get("fileuploaded")}
            )
            if res and not res.ok:
                self.argus_client.add_metric(MetricsEnum.POLICY_CREATION_ERROR)
                raise Exception(
                    f"Error trying to update/create the policy on host {self.nessus_host}, site {self.site}. {res.reason}"
                )
            self.LOGGER.info(f"Policy Created: {res.json()}")
            return res.json().get("id")
        except Exception as err:
            self.LOGGER.error(
                f"Error {err} while trying to create the policy {policy_file_path} on site {self.site}."
            )
            raise err

    def add_audit_files_to_policy(self, policy_id, audit_files: list):
        policy_name: str = ""
        try:
            self.LOGGER.info(
                "Fetching the policy details to check if audit files exist."
            )
            policy_resp = self.get_policy_details(policy_id)
            policy_name = policy_resp.get("settings", dict()).get("name")
            policy_audits = policy_resp.get("audits", dict())
            existing_audits_names = set()

            if policy_audits is not None:
                custom_dict = policy_audits.get("custom", dict())
                if custom_dict is not None:
                    existing_audits = custom_dict.get("add", list())
                    for val in existing_audits:
                        existing_audits_names.add(val.get("file"))

            audit_file_names = set()
            audit_metadata = []
            custom_dict = {}
            audits_dict = {}

            for item in audit_files:
                name = item.get("file_name") + ".audit"
                if name not in existing_audits_names:
                    audit_file_names.add(name)
                    file_dict = {}
                    variable_dict = {}
                    file_dict.update({"category": item.get("category"), "file": name})
                    variable_dict.update({"file": name})
                    file_dict.update({"variables": variable_dict})
                    audit_metadata.append(file_dict)
            custom_dict.update({"add": audit_metadata})
            audits_dict.update({"custom": custom_dict, "feed": None})

            # If the audit files already exist on policy, do nothing.
            if len(audit_file_names) == 0:
                self.LOGGER.info(
                    f"Given audit files already added to the policy {policy_id} on host {self.nessus_host}, site {self.site}."
                )
                return

            # Upload the audit files
            if not self.upload_audit_files(audit_file_names):
                raise Exception(
                    f"Error while trying to upload the audit files on host {self.nessus_host}, site {self.site}. Unable to configure policy."
                )

            # Update the policy details with audits payload
            policy_resp.update({"audits": audits_dict})

            # Configure the policy
            self.LOGGER.info(f"Nessus API PUT called to configure the policy. ")
            res = self.nessus.put(f"policies/{policy_id}", json=policy_resp)
            if res.status_code != 200:
                raise Exception(
                    f"Error trying to configure the policy for adding audit files on host {self.nessus_host}, site {self.site}. {res.reason}"
                )

            self.LOGGER.info(
                f"Policy: {policy_id} configured by adding audit files on on host {self.nessus_host}, site {self.site}. "
            )
        except Exception as err:
            self.argus_client.add_metric(
                MetricsEnum.POLICY_CONFIGURE_ERROR,
                additional_tags={"policy_name": policy_name},
            )
            self.LOGGER.error(
                f"Error {err} while trying to upload the audit files on host {self.nessus_host}, site {self.site}."
            )
            raise err

    def get_policy_details(self, policy_id) -> Dict[str, object]:
        self.LOGGER.info(f"Calling Nessus GET API to fetch policy details. ")
        try:
            policy_resp = self.nessus.get(f"policies/{policy_id}")
            if policy_resp.status_code != 200:
                self.argus_client.add_metric(
                    MetricsEnum.NO_POLICY_FOUND,
                    additional_tags={"policy_id": policy_id},
                )
                raise Exception(
                    f"Error trying to fetch policy id details : {policy_id} on host {self.nessus_host}, site {self.site}. {policy_resp.reason}"
                )
            return policy_resp.json()
        except ValueError as nojson:
            self.LOGGER.error(
                f"No JSON resturned for policy_id {policy_id}. Exception: {nojson}"
            )
            raise nojson
        except Exception as e:
            self.LOGGER.error(
                f"Error {e} while trying to get policy details on {self.site}."
            )
            raise e

    def upload_audit_files(self, audit_files: Set[str]):
        try:
            for audit_file in audit_files:
                audit_file_path = f"{AUDIT_FILES_PATH}/{audit_file}"
                if not os.path.isfile(audit_file_path):
                    self.argus_client.add_metric(
                        MetricsEnum.AUDIT_FILE_NOT_FOUND,
                        additional_tags={"audit-file": audit_file},
                    )
                    self.LOGGER.warning(
                        f"Unable to find any audit file for name {audit_file}.."
                    )
                    return False

                file = {"Filedata": open(audit_file_path, "rb")}
                upload_res = self.nessus.post("file/upload", files=file)
                if upload_res.status_code != 200:
                    self.argus_client.add_metric(
                        MetricsEnum.AUDIT_FILES_UPLOAD_ERROR,
                        additional_tags={"audit-file": audit_file},
                    )
                    raise Exception(
                        f"Error trying to upload the audit file {audit_file} on host {self.nessus_host}, site {self.site}"
                        f". {upload_res.reason}"
                    )
                self.LOGGER.info(
                    f"Audit File {audit_file} uploaded {upload_res.json()}"
                )
            self.LOGGER.info(f"Audit Files upload complete")
            return True
        except Exception as err:
            self.LOGGER.error(
                f"Error {err} while trying to upload the audit files on site {self.site}."
            )
            raise err

    def is_eligible_for_netscan(self, scan_name, netscan_config = None):
        try:
            self.LOGGER.info(f"Checking Eligibilty of scan {scan_name}")
            scan_id = self.get_scan_id(scan_name=scan_name)
            if not scan_id:
                self.LOGGER.info(f"Scan {scan_name} doesn't exist as of now.. ")
                return True

            if netscan_config is None:
                netscan_config = self.site_cfg.get("netscan_config", dict())

            scan_response = (
                self.nessus.get(f"scans/{scan_id}").json().get("info", dict())
            )

            scan_status = scan_response.get("status").lower()
            self.LOGGER.info(f"Scan status is {scan_status}")

            if (
                "abort" in scan_status
                or "cancel" in scan_status
                or "empty" in scan_status
            ):
                self.LOGGER.info(
                    f"Scan {scan_name} is {scan_status}, "
                    f"hence it is eligible for scan.. "
                )
                return True
            if "completed" not in scan_status:
                self.LOGGER.info(
                    f"Scan {scan_name} is not in completed state, "
                    f"therefore not eligible for scan.. "
                )
                return False
            scan_end = scan_response.get("scan_end", 0)
            required_end_time = datetime.utcnow() - timedelta(
                hours=netscan_config.get(
                    ScanTypeEnum.SCAN_INTERVAL_HOURS.value,
                    ScanTypeEnum.SCAN_INTERVAL_DEFAULT_HOURS.value,
                )
            )
            if required_end_time.timestamp() > scan_end:
                self.LOGGER.info(f"Scan {scan_name} is eligible for new scan run..")
                return True
            else:
                self.LOGGER.info(
                    f"Scan {scan_name} is not eligible for a new run as of now .."
                )
                return False
        except Exception as e:
            self.LOGGER.error(
                f"Encountered error {e} while filtering scanners for network scan"
            )
            return False

    def get_scanners(self):
        try:
            scanners = self.nessus.get("scanners").json().get("scanners", list())
            required_scanners = []
            for scanner in scanners:
                if "managed" in scanner.get("type") and "on" in scanner.get("status"):
                    required_scanners.append(scanner)
            return required_scanners
        except Exception as e:
            self.LOGGER.info(
                f"Error fetching the scanners from the manager {self.nessus_host},"
                f"Error {e}"
            )
            raise e

    def create_network_scan(self, scan_name, scanner_id, fd_name):
        try:
            netscan_config = self.site_cfg.get("netscan_config", dict())
            dest_folder = self.get_folder_id()
            dest_scan = self.get_scan_id(scan_name)
            dest_policy_template = self._get_policy_template_uuid(
                policy_name=netscan_config.get(
                    "scan_template", ScanConfigEnum.DEFAULT_NETSCAN_TEMPLATE.value
                )
            )
            dest_policy_id = self.get_policy_id(
                req_policy=netscan_config.get(ScanConfigEnum.SCAN_POLICY_NAME.value, "")
            )

            # Loads the audit files configuration from netscan config
            audit_list = netscan_config.get(ScanConfigEnum.AUDIT_FILES.value, list())

            # Configure the policy with the audit files from configuration
            if audit_list is not None and len(audit_list) > 0:
                self.add_audit_files_to_policy(dest_policy_id, audit_list)
            else:
                self.LOGGER.info(
                    f" Audit files configuration not present in netscan config for the site: {self.site} , "
                    f"hence policy not configured with audit files for site: {self.site}"
                )
                self.argus_client.add_metric(MetricsEnum.NO_AUDIT_CONFIG_FOUND)
            if (
                self.is_falcon
                and netscan_config.get(ScanConfigEnum.DERIVED_BOM_FILE.value)
                is not None
            ):
                target_ip_range = get_fd_target_ip_range(fd_name)
            elif self.is_falcon and get_targeted_netscan_suffix() in scan_name:
                target_ip_range = self.get_available_agents_ip_using_query()
            else:
                target_ip_range = netscan_config.get("targets")

            # Payload to use if the creating the destination scan from scratch.
            settings_payload = {
                "name": scan_name,
                "description": "NetScan created by rapidsnail.",
                "launch": "ON_DEMAND",
                "timezone": "UTC",
                "enabled": "false",  # indicates that this scan is not supposed to be on a schedule,
                "folder_id": str(dest_folder),
                "scanner_id": scanner_id,
                "text_targets": target_ip_range,
            }

            if dest_policy_id:
                settings_payload["policy_id"] = dest_policy_id

            payload = {"uuid": dest_policy_template, "settings": settings_payload}
            error_configure = False
            res = None
            if dest_scan:
                self.LOGGER.info(
                    f"Site {self.site} already has a scan with id {dest_scan}"
                )
                res = self.nessus.put("scans/{}".format(dest_scan), json=payload)
                self.argus_client.add_metric(MetricsEnum.NETSCAN_UPDATED)
                self.LOGGER.info(
                    f"Site: {self.site} Made a PUT request with payload {payload} on scan with id {dest_scan}"
                )
                if not res.ok:
                    # 404 error status_code comes when the scan doesn't exist, indicating someone manually removed the
                    # scan recently. Try creating the scan again.
                    self.LOGGER.warning(
                        f"Got an 404 while trying to update: {dest_scan}; host {self.nessus_host}; site {self.site}"
                    )
                    error_configure = True

            if not dest_scan or error_configure:
                self.LOGGER.info(
                    f"Site: {self.site} Attempting to create a scan for network scanning for {self.site}"
                )
                res = self.nessus.post("scans", json=payload)
                self.argus_client.add_metric(MetricsEnum.NETSCAN_CREATED)
                self.LOGGER.info(
                    f"Site: {self.site} Created a scan for network scanning for {self.site} with properties"
                    f" {payload}"
                )

            if res and not res.ok:
                # both PUT and POST requests return ONLY 200 code if everything went well.
                self.argus_client.add_metric(MetricsEnum.NETSCAN_CREATION_ERROR)
                raise Exception(
                    f"Error trying to update/create the netscan on host {self.nessus_host}, site {self.site}. {res.reason}"
                )
        except Exception as err:
            self.LOGGER.error(
                f"Error while trying to create the Network Scan on site {self.site}"
            )
            raise err
