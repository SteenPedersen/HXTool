import re
import os
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Full list of HX Enterprise Search "displayable" fields that a query may target.
# These are the exact field display names accepted by the /hx/api/v3/searches query array.
SEARCHABLE_FIELDS = [
    'Application Name',
    'Browser Name',
    'Browser Version',
    'Cookie Flags',
    'Cookie Name',
    'Cookie Value',
    'DNS Hostname',
    'Driver Device Name',
    'Driver Module Address',
    'Driver Module In-Tree',
    'Driver Module License',
    'Driver Module Name',
    'Driver Module Parameters',
    'Driver Module Return Trampoline',
    'Driver Module Signature',
    'Driver Module Signer',
    'Driver Module Signing Hash Algorithm',
    'Driver Module Signing Key',
    'Driver Module Status',
    'Driver Module Vermagic',
    'Driver Module Version',
    'Executable Exported Dll Name',
    'Executable Exported Function Name',
    'Executable Imported Function Name',
    'Executable Imported Module Name',
    'Executable Injected',
    'Executable PE Type',
    'Executable Resource Name',
    'File Attributes',
    'File Certificate Issuer',
    'File Certificate Subject',
    'File Download Mime Type',
    'File Download Referrer',
    'File Download Type',
    'File Full Path',
    'File MD5 Hash',
    'File Name',
    'File SHA1 Hash',
    'File SHA256 Hash',
    'File Signature Exists',
    'File Signature Verified',
    'File Stream Name',
    'File Text Written',
    'Group ID',
    'Group Name',
    'HTTP Header',
    'Host Set',
    'Hostname',
    'INode',
    'IP Address',
    'Local IP Address',
    'Local Port',
    'Login Failed',
    'Login Record Type',
    'Network Route Flags',
    'Parent Process Name',
    'Parent Process Path',
    'Port',
    'Port Protocol',
    'Port State',
    'Process Arguments',
    'Process Name',
    'Quarantine Event Sender Address',
    'Quarantine Event Sender Name',
    'Registry Key Full Path',
    'Registry Key Value Name',
    'Registry Key Value Text',
    'Remote IP Address',
    'Remote Login',
    'Remote Port',
    'Service DLL',
    'Service Mode',
    'Service Name',
    'Service Status',
    'Service Type',
    'Session Length',
    'Shell Command',
    'Shell Type',
    'Size in bytes',
    'Socket Protocol',
    'Socket State',
    'Socket Type',
    'Sudo Command',
    'Sudo Command Success',
    'Syslog Event ID',
    'Syslog Event Message',
    'Syslog Facility',
    'Syslog File',
    'Syslog Sender',
    'Syslog Severity Level',
    'Task Flag',
    'Task Name',
    'Task Reference',
    'Task Status',
    'Terminal Type',
    'Timestamp - Accessed',
    'Timestamp - Changed',
    'Timestamp - Created',
    'Timestamp - Event',
    'Timestamp - Last Login',
    'Timestamp - Last Run',
    'Timestamp - Modified',
    'Timestamp - Started',
    'URL',
    'Username',
    'Web Page Origin URL',
    'Web Page Title',
    'Windows Event ID',
    'Windows Event Log Type',
    'Windows Event Message',
]

# All operators supported for a hunt field condition (union across field types). These
# strings are passed straight through as the "operator" value in the HX /searches query
# array. If a controller rejects one of these spellings, this is the single place to fix it.
HUNT_OPERATORS = [
    'equals',
    'not equals',
    'contains',
    'not contains',
    'starts with',
    'ends with',
    'less than',
    'greater than',
    'between',
]

# Which operators make sense per field data type. String fields get substring operators;
# numeric/date fields get comparison operators; booleans only equality.
OPERATORS_BY_TYPE = {
    'string':  ['equals', 'not equals', 'contains', 'not contains', 'starts with', 'ends with'],
    'integer': ['equals', 'not equals', 'less than', 'greater than', 'between'],
    'date':    ['equals', 'not equals', 'less than', 'greater than', 'between'],
    'bool':    ['equals', 'not equals'],
    'ip':      ['equals', 'not equals', 'contains', 'not contains'],
}

# Data type of each searchable field (anything not listed defaults to 'string').
# Drives which operators the UI offers and what save validation accepts.
FIELD_TYPES = {
    # integers
    'Local Port': 'integer',
    'Port': 'integer',
    'Remote Port': 'integer',
    'Size in bytes': 'integer',
    'Session Length': 'integer',
    'Syslog Event ID': 'integer',
    'Syslog Severity Level': 'integer',
    'Windows Event ID': 'integer',
    'INode': 'integer',
    'Group ID': 'integer',
    # booleans
    'Executable Injected': 'bool',
    'File Signature Exists': 'bool',
    'File Signature Verified': 'bool',
    'Login Failed': 'bool',
    'Sudo Command Success': 'bool',
    'Remote Login': 'bool',
    'Driver Module In-Tree': 'bool',
    # dates
    'Timestamp - Accessed': 'date',
    'Timestamp - Changed': 'date',
    'Timestamp - Created': 'date',
    'Timestamp - Event': 'date',
    'Timestamp - Last Login': 'date',
    'Timestamp - Last Run': 'date',
    'Timestamp - Modified': 'date',
    'Timestamp - Started': 'date',
    # IPs
    'IP Address': 'ip',
    'Local IP Address': 'ip',
    'Remote IP Address': 'ip',
}


def field_type(field_name: str) -> str:
    return FIELD_TYPES.get(field_name, 'string')


def operators_for_field(field_name: str) -> list:
    return OPERATORS_BY_TYPE.get(field_type(field_name), OPERATORS_BY_TYPE['string'])

# Local JSON file holding the IOC-type -> [{field, operator}] mapping (operator-editable).
FIELDS_FILE_NAME = 'ioc_hunt_fields.json'


def _norm_url(v):
    v = re.sub(r'^hxxps?', lambda m: m.group().replace('xx', 'tt').replace('XX', 'TT'), v, flags=re.I)
    v = re.sub(r'\[:\/{0,2}\]', lambda m: '://' if '//' in m.group() else ':', v)
    return re.sub(r'\[\.?\]|\(\.\)', '.', v)


HUNT_NORMALIZERS = {
    'none':    lambda v: v,
    'process': lambda v: re.sub(r'<[^>]+>', '*', v),
    'ip':      lambda v: re.sub(r'\s', '', re.sub(r'\[\.?\]|\(\.\)|\\.', '.', v)),
    'domain':  lambda v: re.sub(r'\[\.?\]|\(\.\)', '.', v).lower(),
    'url':     _norm_url,
    'dirpath': lambda v: re.sub(r'[/\\](\*{1,2})?$', '', v),
}

# query_fields: each entry becomes {"field": ..., "operator": ..., "value": <IOC>} in the
# POST /hx/api/v3/searches  "query" array.
# Multiple entries for one IOC type (e.g. remote + local IP) each get their own condition row.
HUNT_TYPES = [
    {'id': 'url', 'name': 'URL', 'normalizer': 'url',
     'regexes': [r'((?:https?://|hxxps?:/{1,2}|hxxps?\[:\/{0,2}\]|www\.)[^\s<>"\'`,]+)'],
     'query_fields': [
         {'field': 'URL', 'operator': 'contains'},
     ]},
    {'id': 'dns', 'name': 'DNS / Domain', 'normalizer': 'domain',
     'regexes': [
         r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*(?!(?:exe|dll|msi|bat|ps1|vbs|cmd|scr|pif|jar|hta|wsf|lnk|iso|bin)(?![a-zA-Z0-9\-]))[a-zA-Z]{2,})\b",
         r"\b([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\[\.\]|\(\.\))[a-zA-Z0-9\-\.\[\]\(\)]*[a-zA-Z]{2,})\b",
     ],
     'query_fields': [
         {'field': 'DNS Hostname', 'operator': 'equals'},
     ]},
    {'id': 'sha256', 'name': 'SHA256 Hash', 'normalizer': 'none',
     'regexes': [r'\b([a-fA-F0-9]{64})\b'],
     'query_fields': [
         {'field': 'File SHA256 Hash', 'operator': 'equals'},
     ]},
    {'id': 'sha1', 'name': 'SHA1 Hash', 'normalizer': 'none',
     'regexes': [r'\b([a-fA-F0-9]{40})\b'],
     'query_fields': [
         {'field': 'File SHA1 Hash', 'operator': 'equals'},
     ]},
    {'id': 'md5', 'name': 'MD5 Hash', 'normalizer': 'none',
     'regexes': [r'\b([a-fA-F0-9]{32})\b'],
     'query_fields': [
         {'field': 'File MD5 Hash', 'operator': 'equals'},
     ]},
    {'id': 'ip', 'name': 'IP Address', 'normalizer': 'ip',
     'regexes': [r'\b(\d{1,3}(?:\[\.\]|\(\.\)|\.)\d{1,3}(?:\[\.\]|\(\.\)|\.)\d{1,3}(?:\[\.\]|\(\.\)|\.)\d{1,3})\b'],
     'query_fields': [
         {'field': 'IP Address', 'operator': 'equals'},
     ]},
    {'id': 'registry', 'name': 'Registry Key', 'normalizer': 'none',
     'regexes': [r'((?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_CLASSES_ROOT|HKCR|HKU|HKEY_USERS|HKCC|HKEY_CURRENT_CONFIG)[\\/][^\s,;\'"<>|\n]+)'],
     'query_fields': [
         {'field': 'Registry Key Full Path', 'operator': 'contains'},
     ]},
    {'id': 'process', 'name': 'Process / File', 'normalizer': 'process',
     'regexes': [
         r'((?:[A-Za-z]:\\|\\)(?:[^\\:"\|\r\n]+\\)*[^\\:"\|\r\n\s]+\.[A-Za-z0-9]{1,10})',
         r'\b([A-Za-z0-9_\-]+\.(?:exe|dll|msi|bat|ps1|sh|py|vbs|cmd|scr|pif|jar|hta|js|wsf|lnk|sys|drv))\b',
     ],
     'query_fields': [
         {'field': 'File Name', 'operator': 'contains'},
         {'field': 'Process Name', 'operator': 'contains'},
     ]},
    {'id': 'cmdline', 'name': 'Command Line', 'normalizer': 'dirpath',
     'regexes': [
         r'((?:[A-Za-z]:\\|(?:\*{1,2})?\\)(?:[^\n\r"\\]*\\)+(?:\*{1,2})?)',
         r'(/[a-zA-Z0-9_.~\-]+(?:/[a-zA-Z0-9_.~\-]+)+/?(?:\*{1,2})?)',
     ],
     'query_fields': [
         {'field': 'Process Arguments', 'operator': 'contains'},
     ]},
]

HUNT_TYPE_BY_ID = {ht['id']: ht for ht in HUNT_TYPES}


# ── Configurable field mapping (persisted to a local JSON file) ────────────────

def _fields_file_path():
    from hxtool_util import combine_app_path
    return combine_app_path(FIELDS_FILE_NAME)


def load_field_mappings() -> dict:
    """Load the IOC-type -> [{field, operator}] mapping from the local JSON file.
    Returns {} if the file is absent or unreadable (callers fall back to built-in defaults).
    """
    try:
        p = _fields_file_path()
        if os.path.isfile(p):
            with open(p, 'r') as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
    except Exception as e:
        logger.warning('Unable to read %s: %s', FIELDS_FILE_NAME, e)
    return {}


def save_field_mappings(mapping: dict) -> dict:
    """Validate and persist the IOC-type -> [{field, operator}] mapping to the local JSON file.
    Only known IOC type ids, known searchable fields and known operators are kept.
    Returns the cleaned mapping that was written.
    """
    cleaned = {}
    valid_fields = set(SEARCHABLE_FIELDS)
    for type_id, rows in (mapping or {}).items():
        if type_id not in HUNT_TYPE_BY_ID or not isinstance(rows, list):
            continue
        clean_rows = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            field = row.get('field')
            operator = row.get('operator')
            # operator must be valid for this field's data type
            if field in valid_fields and operator in operators_for_field(field):
                clean_rows.append({'field': field, 'operator': operator})
        cleaned[type_id] = clean_rows
    with open(_fields_file_path(), 'w') as fh:
        json.dump(cleaned, fh, indent=2)
    return cleaned


def get_query_fields(type_id: str) -> list:
    """Return the effective [{field, operator}] list for an IOC type:
    the file mapping if present and non-empty, otherwise the built-in default.
    """
    mapping = load_field_mappings()
    rows = mapping.get(type_id)
    if rows:  # present and non-empty
        return rows
    ht = HUNT_TYPE_BY_ID.get(type_id)
    return ht.get('query_fields', []) if ht else []


def detect_ioc_type(value: str, forced_id: Optional[str] = None) -> Optional[dict]:
    if forced_id:
        return HUNT_TYPE_BY_ID.get(forced_id)
    for ht in HUNT_TYPES:
        for pattern in ht['regexes']:
            if re.search(pattern, value):
                return ht
    return None


def ioc_group_to_query_array(ioc_type_id: str, values: list) -> Optional[list]:
    """Build HX query array for POST /hx/api/v3/searches.
    Returns None if the type has no query_fields or no values.
    Each value x each query_field produces one {'field','operator','value'} entry.
    """
    if ioc_type_id not in HUNT_TYPE_BY_ID or not values:
        return None
    query_fields = get_query_fields(ioc_type_id)
    if not query_fields:
        return None
    query = []
    for val in values:
        for qf in query_fields:
            query.append({'field': qf['field'], 'operator': qf['operator'], 'value': str(val)})
    return query or None
