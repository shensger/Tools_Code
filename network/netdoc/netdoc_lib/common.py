"""Shared data model helpers."""
import ipaddress
import re


def new_device(platform):
    return {
        "hostname": "", "platform": platform, "model": "", "version": "", "domain": "",
        "role": "", "router_id": "", "asn": "", "last_commit": "",
        "interfaces": {}, "vlans": {}, "static_routes": [],
        "bgp": {"groups": {}, "neighbors": {}},
        "routing_instances": {}, "ri_interfaces": {},
        "vc": {"preprovisioned": False, "members": {}},
        "lag_device_count": None, "services": {},
        "fw": {"zones": {}, "vips": [], "policies": [], "ipsec_p1": [], "ipsec_p2": [], "vdoms": []},
        "live": {"lldp": [], "bgp": {}, "ifstate": {}},
        "inactive": [], "notes": set(), "sources": [], "aliases": set(),
    }


def new_interface(name):
    return {"name": name, "description": "", "disabled": False, "lag": None, "lacp": "",
            "min_links": "", "mtu": "", "speed": "", "native_vlan": "", "vlan_tagging": False,
            "esi": False, "units": {},
            # FortiOS-only fields
            "alias": "", "type": "", "role": "", "allowaccess": [], "parent": "", "members": [],
            "vdom": "", "mode": "", "fw_vlanid": None, "zone": ""}


def new_unit(unit):
    return {"unit": unit, "description": "", "disabled": False, "vlan_id": "", "families": [],
            "inet": [], "inet6": [], "vips": [], "mode": "", "native_vlan": "",
            "vlans": [], "vlans_all": False, "vlans_undefined": [], "instance": "master"}


def norm_if(name):
    """xe-0/0/1.0 -> xe-0/0/1 ; keeps other units (ge-0/0/1.100 stays)."""
    if name.endswith(".0"):
        return name[:-2]
    return name


def short_host(name):
    name = (name or "").strip().strip('"').lower()
    if not name or re.fullmatch(r"[\d.]+", name):
        return name
    return name.split(".")[0]


def expand_vlan_tokens(tokens, name2id):
    ids, undefined, allv = [], [], False
    for tok in tokens:
        tok = tok.strip()
        if tok == "all":
            allv = True
        elif re.fullmatch(r"\d+", tok):
            ids.append(int(tok))
        elif re.fullmatch(r"\d+-\d+", tok):
            a, b = map(int, tok.split("-"))
            ids.extend(range(a, b + 1))
        elif tok in name2id and isinstance(name2id[tok], int):
            ids.append(name2id[tok])
        else:
            undefined.append(tok)
    return sorted(set(ids)), undefined, allv


def vlan_ranges(ids):
    """[1,2,3,7,9,10] -> '1-3,7,9-10'"""
    ids = sorted(set(i for i in ids if isinstance(i, int)))
    out, i = [], 0
    while i < len(ids):
        j = i
        while j + 1 < len(ids) and ids[j + 1] == ids[j] + 1:
            j += 1
        out.append(str(ids[i]) if i == j else f"{ids[i]}-{ids[j]}")
        i = j + 1
    return ",".join(out)


def iface_net(cidr):
    try:
        return ipaddress.ip_interface(cidr)
    except ValueError:
        return None


def mask_to_cidr(ip, mask):
    try:
        return str(ipaddress.ip_interface(f"{ip}/{mask}"))
    except ValueError:
        return None
