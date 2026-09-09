from typing import Optional

# Maps exe name (lowercase) -> (vendor, plain-English description)
KNOWN_AGENTS: dict[str, tuple[str, str]] = {
    "csfalconservice.exe":      ("CrowdStrike",        "CrowdStrike Falcon EDR agent service"),
    "csfalconcontainer.exe":    ("CrowdStrike",        "CrowdStrike Falcon container sensor"),
    "sentinelagent.exe":        ("SentinelOne",        "SentinelOne endpoint protection agent"),
    "sentinelservicehost.exe":  ("SentinelOne",        "SentinelOne service host"),
    "cb.exe":                   ("Carbon Black",       "VMware Carbon Black endpoint agent"),
    "cbdefense.exe":            ("Carbon Black",       "VMware Carbon Black Defense agent"),
    "cbdefensesvc.exe":         ("Carbon Black",       "VMware Carbon Black Defense service"),
    "cortex_agent.exe":         ("Palo Alto Networks", "Cortex XDR agent"),
    "pangpa.exe":               ("Palo Alto Networks", "Cortex XDR GlobalProtect agent"),
    "pangps.exe":               ("Palo Alto Networks", "Cortex XDR GlobalProtect service"),
    "msmpeng.exe":              ("Microsoft",          "Microsoft Defender Antivirus engine"),
    "mssense.exe":              ("Microsoft",          "Microsoft Defender for Endpoint sensor"),
    "securityhealthservice.exe":("Microsoft",          "Windows Security Health Service"),
    "taniumclient.exe":         ("Tanium",             "Tanium endpoint management client"),
    "taniumcx.exe":             ("Tanium",             "Tanium Client Extensions"),
    "xagt.exe":                 ("Trellix (FireEye)",  "Trellix/FireEye Endpoint Security agent"),
    "amagent.exe":              ("Absolute",           "Absolute endpoint security agent"),
    "amservice.exe":            ("Absolute",           "Absolute endpoint security service"),
    "dsagent.exe":              ("Druva",              "Druva inSync backup and security agent"),
    "ntrtscan.exe":             ("Trend Micro",        "Trend Micro real-time scan service"),
    "tmlisten.exe":             ("Trend Micro",        "Trend Micro listener service"),
    "savservice.exe":           ("Sophos",             "Sophos Anti-Virus service"),
    "sophosui.exe":             ("Sophos",             "Sophos user interface"),
    # Microsoft Defender for Endpoint (MDE) sub-processes
    "sensece.exe":              ("Microsoft",          "Microsoft Defender for Endpoint CE agent"),
    "sensetvm.exe":             ("Microsoft",          "Microsoft Defender for Endpoint TVM agent"),
    "sensetracer.exe":          ("Microsoft",          "Microsoft Defender for Endpoint tracer"),
    "sensedlpprocessor.exe":    ("Microsoft",          "Microsoft Defender for Endpoint DLP processor"),
    "sensendr.exe":             ("Microsoft",          "Microsoft Defender for Endpoint NDR agent"),
    "defendersessionhelper.exe":("Microsoft",          "Microsoft Defender session helper"),
    "mpdefendercoreservice.exe":("Microsoft",          "Microsoft Defender core service"),
    "mpdlpservice.exe":         ("Microsoft",          "Microsoft Defender DLP service"),
    "dlpuseragent.exe":         ("Microsoft",          "Microsoft Defender DLP user agent"),
    # CrowdStrike additional
    "csfalconuihost.exe":       ("CrowdStrike",        "CrowdStrike Falcon UI host"),
}

VENDOR_KEYWORDS = [
    "crowdstrike", "sentinelone", "carbonblack", "carbon black",
    "cortexdr", "cortex xdr", "paloalto", "palo alto", "panw",
    "windows defender", "microsoft defender", "tanium",
    "fireeye", "trellix", "absolute software", "druva",
    "trendmicro", "trend micro", "sophos", "cylance", "cybereason",
    "darktrace", "vectra", "eset", "bitdefender", "malwarebytes",
    "webroot", "forcepoint",
]

_SYSTEM_EXE_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "lsass.exe", "services.exe", "svchost.exe",
    "dwm.exe", "explorer.exe", "taskhost.exe", "taskhostw.exe",
    "spoolsv.exe", "searchindexer.exe", "wuauclt.exe", "conhost.exe",
    "fontdrvhost.exe", "runtimebroker.exe", "sihost.exe",
    "system idle process", "memory compression",
}

_SYSTEM_PATH_PREFIXES = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\",
    "c:\\windows\\servicing\\",
)


def classify(
    name: str,
    exe_path: str,
    publisher: str,
) -> tuple[str, Optional[str], Optional[str]]:
    """Return (proc_type, vendor, description).

    proc_type is one of: 'Security Agent', 'System', 'User App'
    vendor and description are None for non-agent processes.
    """
    name_lower = name.lower().strip()

    # Exact match in known agent list
    if name_lower in KNOWN_AGENTS:
        vendor, desc = KNOWN_AGENTS[name_lower]
        return "Security Agent", vendor, desc

    # Trend Micro wildcard prefix
    if name_lower.startswith("trendmicro"):
        return "Security Agent", "Trend Micro", "Trend Micro security component"

    # Vendor keywords in path or publisher
    search_text = f"{exe_path or ''} {publisher or ''}".lower()
    for keyword in VENDOR_KEYWORDS:
        if keyword in search_text:
            vendor = publisher if publisher and publisher != "Unknown" else "Unknown Vendor"
            return "Security Agent", vendor, "Security agent (detected by vendor name)"

    # System process check
    if name_lower in _SYSTEM_EXE_NAMES:
        return "System", None, None

    if exe_path:
        path_lower = exe_path.lower()
        if any(path_lower.startswith(p) for p in _SYSTEM_PATH_PREFIXES):
            return "System", None, None

    return "User App", None, None
