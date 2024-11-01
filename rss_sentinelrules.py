# hitem
#!/usr/bin/env python3
import concurrent.futures
import requests
import yaml
from lxml import etree
import datetime
from datetime import timezone
import os
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import email.utils
import uuid
import calendar

# Set up retry strategy
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    # Retry on common server errors
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.Session()
session.mount("https://", adapter)

# Define the list of GitHub file URLs
github_file_urls = [
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Azure%20Firewall/Analytic%20Rules/SeveralDenyActionsRegistered.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/MultipleDataSources/ADFS-DKM-MasterKey-Export.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/MultipleDataSources/AuditPolicyManipulation_using_auditpol.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/AuthenticationMethodsChangedforPrivilegedAccount.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Azure%20Firewall/Analytic%20Rules/Azure%20Firewall%20-%20Abnormal%20Deny%20Rate%20for%20Source%20IP.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Azure%20Firewall/Analytic%20Rules/Azure%20Firewall%20-%20Multiple%20Sources%20Affected%20by%20the%20Same%20TI%20Destination.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Azure%20Firewall/Analytic%20Rules/Azure%20Firewall%20-%20Port%20Scan.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Azure%20Firewall/Analytic%20Rules/Azure%20Firewall%20-%20Port%20Sweep.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/SigninBruteForce-AzurePortal.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Attacker%20Tools%20Threat%20Protection%20Essentials/Analytic%20Rules/CredentialDumpingToolsFileArtifacts.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/DistribPassCrackAttempt.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/ASimDNS/imDNS_Miners.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/ASimDNS/imDNS_TorProxies.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Windows%20Security%20Events/Analytic%20Rules/ExchangeOABVirtualDirectoryAttributeContainingPotentialWebshell.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Windows%20Security%20Events/Analytic%20Rules/GainCodeExecutionADFSViaSMB.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/MultipleDataSources/ForestBlizzardJuly2019IOCs.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Endpoint%20Threat%20Protection%20Essentials/Analytic%20Rules/LateralMovementViaDCOM.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Endpoint%20Threat%20Protection%20Essentials/Analytic%20Rules/malware_in_recyclebin.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Azure%20Key%20Vault/Analytic%20Rules/KeyvaultMassSecretRetrieval.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/MultipleDataSources/Mercury_Log4j_August2022.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/MFARejectedbyUser.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/AADHealthSvcAgentRegKeyAccess.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Cloud%20Identity%20Threat%20Protection%20Essentials/Analytic%20Rules/NewExtUserGrantedAdmin.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/UserCreatedAddedToBuiltinAdmins_1d.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/MidnightBlizzard_SuspiciousScriptRegistryWrite.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/MidnightBlizzard_SuspiciousRundll32Exec.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Azure%20Activity/Analytic%20Rules/NRT_Creation_of_Expensive_Computes_in_Azure.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/OfficeActivity/NRT_Malicious_Inbox_Rule.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/OfficeActivity/NRT_Office_MailForwarding.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Windows%20Security%20Events/Analytic%20Rules/NRT_SecurityEventLogCleared.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Azure%20Key%20Vault/Analytic%20Rules/NRT_KeyVaultSensitiveOperations.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/SigninPasswordSpray.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/SeamlessSSOPasswordSpray.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20365/Analytic%20Rules/ForestBlizzardCredHarvesting.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Network%20Session%20Essentials/Analytic%20Rules/PossibleBeaconingActivity.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/PotentialKerberoast.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Attacker%20Tools%20Threat%20Protection%20Essentials/Analytic%20Rules/powershell_empire.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/PrivilegedAccountsSigninFailureSpikes.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20365/Analytic%20Rules/RareOfficeOperations.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/RareApplicationConsent.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Azure%20Activity/Analytic%20Rules/RareOperations.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SecurityEvent/RDP_Nesting.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Endpoint%20Threat%20Protection%20Essentials/Analytic%20Rules/RegistryPersistenceViaAppCertDLLModification.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Windows%20Security%20Events/Analytic%20Rules/ScheduleTaskHide.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ServicePrincipalAssignedPrivilegedRole.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20365/Analytic%20Rules/SharePoint_Downloads_byNewUserAgent.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20365/Analytic%20Rules/SharePoint_Downloads_byNewUserAgent.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/DomainEntity_DnsEvents.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/DomainEntity_SecurityAlert.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/DomainEntity_Syslog.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/EmailEntity_AzureActivity.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/EmailEntity_OfficeActivity.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/EmailEntity_SecurityAlert.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/EmailEntity_SecurityEvent.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/EmailEntity_SigninLogs.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/FileHashEntity_CommonSecurityLog.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/FileHashEntity_SecurityEvent.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_AzureKeyVault.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_AzureSQL.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_AzureActivity.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_CustomSecurityLog.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_DnsEvents.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_OfficeActivity.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_SigninLogs.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_VMConnection.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_W3CIISLog.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/URLEntity_AuditLogs.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Threat%20Intelligence/Analytic%20Rules/URLEntity_SecurityAlerts.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Endpoint%20Threat%20Protection%20Essentials/Analytic%20Rules/WindowsBinariesExecutedfromNon-DefaultDirectory.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/MFASpammingfollowedbySuccessfullogin.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/AdminPromoAfterRoleMgmtAppPermissionGrant.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/CredentialAddedAfterAdminConsent.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Windows%20Security%20Events/Analytic%20Rules/NonDCActiveDirectoryReplication.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/PossibleSignInfromAzureBackdoor.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Windows%20Security%20Events/Analytic%20Rules/PotentialFodhelperUACBypass.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Windows%20Security%20Events/Analytic%20Rules/MultipleFailedFollowedBySuccess.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/SuspiciousOAuthApp_OfflineAccess.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Azure%20Activity/Analytic%20Rules/NRT-AADHybridHealthADFSNewServer.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/SigninLogs/AuthenticationAttemptfromNewCountry.yaml"
    # Add more URLs as needed
]

# Output files
output_file = "slimmed_down_feed.xml"
processed_versions_file = "processed_versions.txt"
log_file = "removed_or_moved_files.txt"

# Read previously processed versions
try:
    with open(processed_versions_file, "r") as f:
        processed_versions = {}
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2:
                rule_id = parts[0]
                version = parts[1]
                last_updated = parts[2] if len(parts) == 3 else "Unknown"
                processed_versions[rule_id] = [version, last_updated]
except FileNotFoundError:
    processed_versions = {}

# Function to convert GitHub URL to raw URL
def convert_to_raw_url(github_url):
    if "github.com" in github_url and "/blob/" in github_url:
        raw_url = github_url.replace(
            "github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        return raw_url
    return github_url

# Function to extract only the required fields from the YAML content


def extract_essential_fields(yaml_content, url):
    try:
        yaml_data = yaml.safe_load(yaml_content)
        rule_id = yaml_data.get("id")
        if not rule_id:
            return None
        fields = {
            "id": rule_id,
            "name": yaml_data.get("name"),
            "version": yaml_data.get("version", "Unknown"),
            "url": url,
            "updated": datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
            "pubDate": email.utils.format_datetime(datetime.datetime.now(timezone.utc)),
        }
        return fields
    except (yaml.YAMLError, ValueError):
        return None 

# Function to remove the failed URLs from the 'github_file_urls' in the source file
def remove_url_from_list(url):
    github_file = "rss_sentinelrules.py"
    try:
        with open(github_file, "r") as file:
            lines = file.readlines()

        with open(github_file, "w") as file:
            inside_url_block = False
            for line in lines:
                if "github_file_urls = [" in line:
                    inside_url_block = True

                if inside_url_block:
                    if url in line:
                        continue
                    if line.strip().endswith("],") and "https" in line:
                        file.write(line.replace("],", "]\n"))
                        inside_url_block = False
                        continue
                    if "]" in line:
                        inside_url_block = False
                        file.write(line)
                    else:
                        file.write(line)
                else:
                    file.write(line)

        # Log the removal
        with open(log_file, "a") as log:
            log.write(
                f"{datetime.datetime.now(timezone.utc)} - URL Removed: {url}\n")
    except Exception as e:
        print(f"Error while removing URL {url}: {e}")

# Fetch URL function
def fetch_url(url):
    raw_url = convert_to_raw_url(url)
    try:
        response = session.get(raw_url)
        response.raise_for_status()  
        return url, response
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return url, None

# Parallel fetching of URLs
with concurrent.futures.ThreadPoolExecutor() as executor:
    future_to_url = {executor.submit(
        fetch_url, url): url for url in github_file_urls}

    new_entries = []
    updated_entries = []
    removed_entries = []
    invalid_entries = []

    for future in concurrent.futures.as_completed(future_to_url):
        url, response = future.result()
        if response:
            yaml_content = response.text
            fields = extract_essential_fields(yaml_content, url)

            if fields is None:
                invalid_entries.append(url)
                continue

            rule_id = fields["id"]
            rule_version = fields["version"]
            # Check if the rule is new or updated
            if rule_id not in processed_versions:
                # New entry
                new_entries.append(fields)
                processed_versions[rule_id] = [rule_version, fields["updated"]]
            elif processed_versions.get(rule_id)[0] != rule_version:
                # Updated entry
                updated_entries.append(fields)
                processed_versions[rule_id] = [rule_version, fields["updated"]]
            else:
                # No change
                pass 
        else:
            removed_entries.append(url)
            remove_url_from_list(url)

# Get the previous month
now = datetime.datetime.now(timezone.utc)
previous_month = now.month - 1 if now.month > 1 else 12
previous_month_year = now.year if now.month > 1 else now.year - 1
previous_month_name = calendar.month_name[previous_month]

# Create a new XML tree for the RSS feed
root = etree.Element("rss", version="2.0")
channel = etree.SubElement(root, "channel")
etree.SubElement(channel, "title").text = "Slimmed Down GitHub YAML Updates"
etree.SubElement(
    channel, "link").text = "https://hitem.github.io/rss-sentinel/slimmed_down_feed.xml"
etree.SubElement(
    channel, "description").text = "A feed of updated YAML files from GitHub"
etree.SubElement(channel, "lastBuildDate").text = datetime.datetime.now(
    timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

# Function to add items to RSS channel
def add_rss_item(title, description_text, channel):
    item = etree.SubElement(channel, "item")
    etree.SubElement(item, "title").text = title
    etree.SubElement(
        item, "link").text = "https://hitem.github.io/rss-sentinel/slimmed_down_feed.xml"
    etree.SubElement(item, "pubDate").text = email.utils.format_datetime(
        datetime.datetime.now(timezone.utc))
    etree.SubElement(
        item, "guid", isPermaLink="false").text = str(uuid.uuid4())
    etree.SubElement(item, "description").text = description_text


# Add New, Updated, and Removed rules as separate entries
if new_entries:
    new_description = "New rules:<br/>" + "".join(
        f"<b>Name:</b> {entry['name']} ({entry['version']})<br/><b>ID:</b> <a href='{entry['url']}'>{entry['id']}</a><br/><br/>"
        for entry in new_entries
    )
    add_rss_item(
        f"{previous_month_name} {previous_month_year}: New Rules", new_description, channel)

if updated_entries:
    updated_description = "Updated rules:<br/>" + "".join(
        f"<b>Name:</b> {entry['name']} ({entry['version']})<br/><b>ID:</b> <a href='{entry['url']}'>{entry['id']}</a><br/><br/>"
        for entry in updated_entries
    )
    add_rss_item(f"{previous_month_name} {previous_month_year}: Updated Rules",
                 updated_description, channel)

if removed_entries or invalid_entries:
    removed_description = ""
    if removed_entries:
        removed_description += "Removed rules:<br/>" + "".join(
            f"<b>Link:</b> <a href='{url}'>{url}</a><br/><br/>"
            for url in removed_entries
        )
    if invalid_entries:
        removed_description += "Invalid rules (missing 'id'):<br/>" + "".join(
            f"<b>Link:</b> <a href='{url}'>{url}</a><br/><br/>"
            for url in invalid_entries
        )
    add_rss_item(f"{previous_month_name} {previous_month_year}: Removed or Invalid Rules",
                 removed_description, channel)

# Write the slimmed down feed to the output file
with open(output_file, "wb") as f:
    f.write(etree.tostring(root, pretty_print=True))

# Update the processed_versions.txt file to keep the latest version information
with open(processed_versions_file, "w") as f:
    for rule_id, data in processed_versions.items():
        version, updated = data
        f.write(f"{rule_id} {version} {updated}\n")

# Log invalid entries with missing 'id'
with open(log_file, "a") as log:
    if invalid_entries:
        log.write(
            f"{datetime.datetime.now(timezone.utc)} - Files with missing 'id':\n")
        for url in invalid_entries:
            log.write(f"{url}\n")

# Set the RSS_FEED_ENTRIES environment variable
with open(os.environ["GITHUB_ENV"], "a") as f:
    f.write(f"RSS_FEED_ENTRIES={len(new_entries) + len(updated_entries)}\n")
