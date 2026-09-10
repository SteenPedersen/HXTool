import re
from typing import Optional


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
         {'field': 'SHA256 Hash', 'operator': 'equals'},
     ]},
    {'id': 'md5', 'name': 'MD5 Hash', 'normalizer': 'none',
     'regexes': [r'\b([a-fA-F0-9]{32})\b'],
     'query_fields': [
         {'field': 'MD5 Hash', 'operator': 'equals'},
     ]},
    {'id': 'ip', 'name': 'IP Address', 'normalizer': 'ip',
     'regexes': [r'\b(\d{1,3}(?:\[\.\]|\(\.\)|\.)\d{1,3}(?:\[\.\]|\(\.\)|\.)\d{1,3}(?:\[\.\]|\(\.\)|\.)\d{1,3})\b'],
     'query_fields': [
         {'field': 'Remote IP', 'operator': 'equals'},
     ]},
    {'id': 'registry', 'name': 'Registry Key', 'normalizer': 'none',
     'regexes': [r'((?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_CLASSES_ROOT|HKCR|HKU|HKEY_USERS|HKCC|HKEY_CURRENT_CONFIG)[\\/][^\s,;\'"<>|\n]+)'],
     'query_fields': [
         {'field': 'Registry Key Path', 'operator': 'contains'},
     ]},
    {'id': 'process', 'name': 'Process / File', 'normalizer': 'process',
     'regexes': [
         r'((?:[A-Za-z]:\\|\\)(?:[^\\:"\|\r\n]+\\)*[^\\:"\|\r\n\s]+\.[A-Za-z0-9]{1,10})',
         r'\b([A-Za-z0-9_\-]+\.(?:exe|dll|msi|bat|ps1|sh|py|vbs|cmd|scr|pif|jar|hta|js|wsf|lnk|sys|drv))\b',
     ],
     'query_fields': [
         {'field': 'Application Name', 'operator': 'equals'},
     ]},
    {'id': 'cmdline', 'name': 'Command Line', 'normalizer': 'dirpath',
     'regexes': [
         r'((?:[A-Za-z]:\\|(?:\*{1,2})?\\)(?:[^\n\r"\\]*\\)+(?:\*{1,2})?)',
         r'(/[a-zA-Z0-9_.~\-]+(?:/[a-zA-Z0-9_.~\-]+)+/?(?:\*{1,2})?)',
     ],
     'query_fields': [
         {'field': 'Command Line Arguments', 'operator': 'contains'},
     ]},
]

HUNT_TYPE_BY_ID = {ht['id']: ht for ht in HUNT_TYPES}


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
    ht = HUNT_TYPE_BY_ID.get(ioc_type_id)
    if not ht or not ht.get('query_fields') or not values:
        return None
    query = []
    for val in values:
        for qf in ht['query_fields']:
            query.append({'field': qf['field'], 'operator': qf['operator'], 'value': str(val)})
    return query or None
