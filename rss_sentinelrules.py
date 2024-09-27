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

# Set up retry strategy
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],  # Retry on common server errors
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.Session()
session.mount("https://", adapter)

# Define the list of GitHub file URLs
github_file_urls = [
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Detections/MultipleDataSources/ADFS-DKM-MasterKey-Export.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Detections/MultipleDataSources/AuditPolicyManipulation_using_auditpol.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/AuthenticationMethodsChangedforPrivilegedAccount.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Azure%20Firewall/Analytic%20Rules/Azure%20Firewall%20-%20Multiple%20Sources%20Affected%20by%20the%20Same%20TI%20Destination.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Azure%20Firewall/Analytic%20Rules/Azure%20Firewall%20-%20Port%20Scan.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Azure%20Firewall/Analytic%20Rules/Azure%20Firewall%20-%20Port%20Sweep.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/SigninBruteForce-AzurePortal.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Attacker%20Tools%20Threat%20Protection%20Essentials/Analytic%20Rules/CredentialDumpingToolsFileArtifacts.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/DistribPassCrackAttempt.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Detections/ASimDNS/imDNS_TorProxies.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Windows%20Security%20Events/Analytic%20Rules/ExchangeOABVirtualDirectoryAttributeContainingPotentialWebshell.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Windows%20Security%20Events/Analytic%20Rules/GainCodeExecutionADFSViaSMB.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Endpoint%20Threat%20Protection%20Essentials/Analytic%20Rules/LateralMovementViaDCOM.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Endpoint%20Threat%20Protection%20Essentials/Analytic%20Rules/malware_in_recyclebin.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Azure%20Key%20Vault/Analytic%20Rules/KeyvaultMassSecretRetrieval.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/e373814e90162e0499e4bdeaa129e0ccde5668ee/Detections/MultipleDataSources/Mercury_Log4j_August2022.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/MFARejectedbyUser.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/MFARejectedbyUser.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Detections/SecurityEvent/AADHealthSvcAgentRegKeyAccess.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Cloud%20Identity%20Threat%20Protection%20Essentials/Analytic%20Rules/NewExtUserGrantedAdmin.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Detections/SecurityEvent/UserCreatedAddedToBuiltinAdmins_1d.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/e373814e90162e0499e4bdeaa129e0ccde5668ee/Detections/SecurityEvent/MidnightBlizzard_SuspiciousScriptRegistryWrite.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/e373814e90162e0499e4bdeaa129e0ccde5668ee/Detections/SecurityEvent/MidnightBlizzard_SuspiciousRundll32Exec.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Azure%20Activity/Analytic%20Rules/NRT_Creation_of_Expensive_Computes_in_Azure.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Windows%20Security%20Events/Analytic%20Rules/NRT_SecurityEventLogCleared.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Azure%20Key%20Vault/Analytic%20Rules/NRT_KeyVaultSensitiveOperations.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/SigninPasswordSpray.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/SeamlessSSOPasswordSpray.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/e373814e90162e0499e4bdeaa129e0ccde5668ee/Solutions/Microsoft%20365/Analytic%20Rules/ForestBlizzardCredHarvesting.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/e373814e90162e0499e4bdeaa129e0ccde5668ee/Solutions/Network%20Session%20Essentials/Analytic%20Rules/PossibleBeaconingActivity.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/e373814e90162e0499e4bdeaa129e0ccde5668ee/Detections/SecurityEvent/PotentialKerberoast.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Attacker%20Tools%20Threat%20Protection%20Essentials/Analytic%20Rules/powershell_empire.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Network%20Session%20Essentials/Analytic%20Rules/PossibleBeaconingActivity.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Microsoft%20365/Analytic%20Rules/RareOfficeOperations.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/RareApplicationConsent.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Azure%20Activity/Analytic%20Rules/RareOperations.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Detections/SecurityEvent/RDP_Nesting.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Endpoint%20Threat%20Protection%20Essentials/Analytic%20Rules/RegistryPersistenceViaAppCertDLLModification.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Windows%20Security%20Events/Analytic%20Rules/ScheduleTaskHide.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Detections/AuditLogs/ServicePrincipalAssignedPrivilegedRole.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Microsoft%20365/Analytic%20Rules/SharePoint_Downloads_byNewUserAgent.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Microsoft%20365/Analytic%20Rules/SharePoint_Downloads_byNewUserAgent.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/DomainEntity_DnsEvents.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/DomainEntity_SecurityAlert.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/DomainEntity_Syslog.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/EmailEntity_AzureActivity.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/EmailEntity_OfficeActivity.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/EmailEntity_SecurityAlert.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/EmailEntity_SecurityEvent.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/EmailEntity_SigninLogs.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/FileHashEntity_CommonSecurityLog.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/FileHashEntity_SecurityEvent.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_AzureKeyVault.yaml#L4",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_AzureSQL.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_AzureActivity.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_CustomSecurityLog.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_DnsEvents.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_OfficeActivity.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_SigninLogs.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_VMConnection.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/IPEntity_W3CIISLog.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/URLEntity_AuditLogs.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Threat%20Intelligence/Analytic%20Rules/URLEntity_SecurityAlerts.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Endpoint%20Threat%20Protection%20Essentials/Analytic%20Rules/WindowsBinariesExecutedfromNon-DefaultDirectory.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Solutions/Azure%20Firewall/Analytic%20Rules/SeveralDenyActionsRegistered.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Detections/ASimDNS/imDNS_Miners.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/e373814e90162e0499e4bdeaa129e0ccde5668ee/Detections/MultipleDataSources/ForestBlizzardJuly2019IOCs.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Detections/OfficeActivity/NRT_Malicious_Inbox_Rule.yaml",
    "https://github.com/Azure/Azure-Sentinel/blob/6bdfd518b2f70098e67f9000f4e26fa459460d00/Detections/OfficeActivity/NRT_Office_MailForwarding.yaml"
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
            if len(parts) == 3:  # Full entry with rule_id, version, and last_updated
                rule_id, version, last_updated = parts
            elif len(parts) == 2:  # Missing last_updated, set it to "Unknown"
                rule_id, version = parts
                last_updated = "Unknown"
            processed_versions[rule_id] = [version, last_updated]
except FileNotFoundError:
    processed_versions = {}

# Function to convert GitHub URL to raw URL
def convert_to_raw_url(github_url):
    if "github.com" in github_url and "/blob/" in github_url:
        raw_url = github_url.replace(
            "github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        return raw_url
    return github_url  # If the URL is already in raw format or doesn't need conversion

# Function to extract only the required fields from the YAML content using PyYAML
def extract_essential_fields(yaml_content, url):
    fields = {}
    try:
        yaml_data = yaml.safe_load(yaml_content)
        fields["id"] = yaml_data.get("id")
        fields["name"] = yaml_data.get("name")
        fields["version"] = yaml_data.get("version", "Unknown")
        fields["url"] = url
        fields["updated"] = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        fields["pubDate"] = email.utils.format_datetime(datetime.datetime.now(timezone.utc))

    except (yaml.YAMLError, ValueError):
        fields["id"] = None  # Invalid YAML or parsing error
        return fields

    return fields

# Fetch URL function
def fetch_url(url):
    raw_url = convert_to_raw_url(url)
    try:
        response = session.get(raw_url)
        response.raise_for_status()  # Will raise an exception for 4XX/5XX errors
        return url, response
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return url, None

# Parallel fetching of URLs
with concurrent.futures.ThreadPoolExecutor() as executor:
    future_to_url = {executor.submit(fetch_url, url): url for url in github_file_urls}

    all_entries = []
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

            if fields["id"] not in processed_versions or processed_versions.get(fields["id"])[0] != fields["version"]:
                all_entries.append(fields)
                processed_versions[fields["id"]] = [fields["version"], fields["updated"]]
        else:
            removed_entries.append(url)

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

# Set the maximum number of rules per message
MAX_RULES_PER_MESSAGE = 20

# Function to split the list into chunks of a specific size
def chunk_list(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]

# If there are any updated rules, process them in chunks
if all_entries:
    chunks = list(chunk_list(all_entries, MAX_RULES_PER_MESSAGE))
    
    for i, chunk in enumerate(chunks):
        # Create a new XML item for each chunk of 20 rules
        item = etree.SubElement(channel, "item")
        etree.SubElement(
            item, "title").text = f"Week {datetime.datetime.now(timezone.utc).isocalendar()[1]}: Updated Rules (Part {i+1})"
        etree.SubElement(
            item, "link").text = "https://hitem.github.io/rss-sentinel/slimmed_down_feed.xml"
        etree.SubElement(item, "pubDate").text = email.utils.format_datetime(
            datetime.datetime.now(timezone.utc))
        etree.SubElement(
            item, "guid", isPermaLink="false").text = str(uuid.uuid4())
        
        # Build description for this chunk
        description_text = "Updated rules this week:<br/>"
        for entry in chunk:
            description_text += f"<b>Name:</b> {entry['name']} ({entry['version']})<br/>"
            description_text += f"<b>ID:</b> <a href='{entry['url']}'>{entry['id']}</a><br/><br/>"
        
        # Add the description to the item
        etree.SubElement(item, "description").text = description_text

# Separate section for removed or invalid entries
if removed_entries or invalid_entries:
    removed_item = etree.SubElement(channel, "item")
    etree.SubElement(
        removed_item, "title").text = f"Week {datetime.datetime.now(timezone.utc).isocalendar()[1]}: Removed or Invalid Rules"
    etree.SubElement(
        removed_item, "link").text = "https://hitem.github.io/rss-sentinel/slimmed_down_feed.xml"
    etree.SubElement(removed_item, "pubDate").text = email.utils.format_datetime(
        datetime.datetime.now(timezone.utc))
    etree.SubElement(
        removed_item, "guid", isPermaLink="false").text = str(uuid.uuid4())

    # Create a digest-style description for removed/invalid rules
    removed_description_text = "Removed or invalid rules:<br/>"
    for url in removed_entries:
        removed_description_text += f"<b>Link:</b> <a href='{url}'>{url}</a><br/><br/>"

    for url in invalid_entries:
        removed_description_text += f"<b>Link:</b> <a href='{url}'>{url}</a> (Missing 'id')<br/><br/>"

    etree.SubElement(removed_item, "description").text = removed_description_text

# Write the slimmed down feed to the output file
with open(output_file, "wb") as f:
    f.write(etree.tostring(root, pretty_print=True))

# Only keep the most recent version of each rule in processed_versions
with open(processed_versions_file, "w") as f:
    for rule_id, data in processed_versions.items():
        version, updated = data
        f.write(f"{rule_id} {version} {updated}\n")

# Log invalid entries with missing 'id'
with open(log_file, "a") as log:
    if invalid_entries:
        log.write(f"{datetime.datetime.now(timezone.utc)} - Files with missing 'id':\n")
        for url in invalid_entries:
            log.write(f"{url}\n")

# Set the RSS_FEED_ENTRIES environment variable
with open(os.environ["GITHUB_ENV"], "a") as f:
    f.write(f"RSS_FEED_ENTRIES={len(all_entries)}\n")
