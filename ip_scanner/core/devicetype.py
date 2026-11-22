"""
Device categories: what kind of thing each host is, for icons and grouping.

The engine's ``Device.device_type`` is a coarse fingerprint from ports and
TTL ("Windows PC", "Linux Server", "IP Camera"...). The category refines it
with everything else a scan learns: what the device announced over
SSDP/mDNS, its manufacturer, its host name, whether its MAC is randomised,
and whether it is this computer or the default gateway.

Rules are ordered by how trustworthy the evidence is: a device describing
itself ("I am a MediaRenderer", "_ipp._tcp") beats a guess from the
manufacturer, which beats a guess from open ports.
"""

from __future__ import annotations

import re
from typing import Iterable

from .models import Device

# Category keys (also the icon file names) and their display names.
COMPUTER = "computer"
LAPTOP = "laptop"
SERVER = "server"
ROUTER = "router"
ACCESS_POINT = "access_point"
PHONE = "phone"
TABLET = "tablet"
PRINTER = "printer"
CAMERA = "camera"
TV = "tv"
MEDIA = "media"
SPEAKER = "speaker"
CONSOLE = "console"
STORAGE = "storage"
SMART_HOME = "smart_home"
NETWORK = "network"
THIS_COMPUTER = "this_computer"
UNKNOWN = "unknown"

CATEGORY_NAMES: dict[str, str] = {
    COMPUTER: "Computer",
    LAPTOP: "Laptop",
    SERVER: "Server",
    ROUTER: "Router",
    ACCESS_POINT: "Access point",
    PHONE: "Phone",
    TABLET: "Tablet",
    PRINTER: "Printer",
    CAMERA: "Camera",
    TV: "TV",
    MEDIA: "Media player",
    SPEAKER: "Speaker",
    CONSOLE: "Game console",
    STORAGE: "Network storage",
    SMART_HOME: "Smart home",
    NETWORK: "Network device",
    THIS_COMPUTER: "This computer",
    UNKNOWN: "Unknown",
}

#: Categories that route or watch the network (used by the exposure checks).
INFRASTRUCTURE = frozenset({ROUTER, ACCESS_POINT, NETWORK})
EMBEDDED = frozenset({CAMERA, SMART_HOME, PRINTER, STORAGE, TV, MEDIA, SPEAKER})


def category_name(key: str) -> str:
    return CATEGORY_NAMES.get(key, CATEGORY_NAMES[UNKNOWN])


def is_randomized_mac(mac: str | None) -> bool:
    """Locally administered MAC: phones and laptops use these for privacy."""
    if not mac:
        return False
    try:
        first = int(mac.replace("-", ":").split(":")[0], 16)
    except ValueError:
        return False
    return bool(first & 0x02) and not first & 0x01


# Evidence tables, checked in order. Patterns are matched case-insensitively
# against the text named in each section.

#: UPnP deviceType URNs and mDNS service types: the device's own words.
_SELF_DESCRIBED: tuple[tuple[str, str], ...] = (
    (r"internetgatewaydevice|wanconnectiondevice|wandevice", ROUTER),
    (r"wlanaccesspointdevice", ACCESS_POINT),
    (r"device:printer|_ipp\._tcp|_ipps\._tcp|_printer\._tcp|_pdl-datastream|_uscan|_scanner",
     PRINTER),
    (r"digitalsecuritycamera|networkvideotransmitter|onvif", CAMERA),
    (r"_androidtvremote|_amzn-wplay", TV),
    (r"_googlecast\._tcp", MEDIA),
    (r"_sonos\._tcp|_spotify-connect|_raop\._tcp", SPEAKER),
    (r"_hap\._tcp|_matter\._tcp", SMART_HOME),
    (r"mediarenderer|mediaserver:.*|dial", MEDIA),
    (r"_apple-mobdev2|_companion-link", PHONE),
)

#: Model / friendly-name keywords (from UPnP, mDNS TXT or the web page).
_MODEL_WORDS: tuple[tuple[str, str], ...] = (
    (r"\b(iphone|pixel|galaxy s|galaxy a|galaxy z|redmi|oneplus|moto g|android phone)", PHONE),
    (r"\b(ipad|galaxy tab|tablet|kindle|fire hd)", TABLET),
    (r"\b(macbook|thinkpad|latitude|xps|zenbook|vivobook|ideapad|surface laptop|notebook|laptop)",
     LAPTOP),
    (r"\b(imac|mac mini|mac studio|optiplex|thinkcentre|desktop)", COMPUTER),
    (r"\b(bravia|smart ?tv|webos|tizen|roku tv|android tv|google tv|qled|oled|\btv\b|television)",
     TV),
    (r"\b(chromecast|apple ?tv|roku|fire ?tv|shield|nvidia shield|media player)", MEDIA),
    # "echo" must be a whole word: Huawei's EchoLife routers are not Amazon Echos.
    (r"\b(echo|alexa|homepod|nest (mini|audio|hub)|google home|sonos|soundbar|speaker)\b",
     SPEAKER),
    (r"\b(playstation|ps[345]\b|xbox|nintendo|switch)", CONSOLE),
    (r"\b(laserjet|deskjet|officejet|envy|ecotank|pixma|imageclass|workforce|mfc-|hl-|dcp-|"
     r"bizhub|printer|kyocera|lexmark)", PRINTER),
    (r"\b(ipc|ipcam|camera|cam\b|nvr|dvr|doorbell|ring|arlo|wyze|reolink|tapo c|eufy)", CAMERA),
    (r"\b(diskstation|rackstation|qnap|ts-\d|my cloud|nas\b|readynas)", STORAGE),
    (r"\b(echolife|archer|deco|eero|orbi|nighthawk|router|gateway|livebox|fritz)", ROUTER),
    (r"\b(access point|unifi|ap\d|eap\d)", ACCESS_POINT),
    (r"\b(hue|bridge|thermostat|nest|plug|bulb|tuya|shelly|sonoff|smart home|tado|ecobee)",
     SMART_HOME),
)

#: Host-name patterns people and vendors actually use.
_HOSTNAME_WORDS: tuple[tuple[str, str], ...] = (
    (r"iphone|android|galaxy|redmi|pixel|oneplus|huawei-p|xiaomi|moto|phone", PHONE),
    (r"ipad|tab|tablet|kindle", TABLET),
    (r"macbook|laptop|notebook|lt-|nb-", LAPTOP),
    (r"desktop|pc-|-pc\b|workstation|imac|\bws\d", COMPUTER),
    (r"tv|bravia|roku|firetv|chromecast|appletv", TV),
    (r"\becho\b|alexa|homepod|sonos|speaker", SPEAKER),
    (r"ps[345]|playstation|xbox|nintendo|switch", CONSOLE),
    (r"printer|\bhp[a-f0-9]{6}|epson|brn|canon|brother", PRINTER),
    (r"cam|ipc|nvr|dvr|doorbell", CAMERA),
    (r"nas|diskstation|synology|qnap", STORAGE),
    (r"router|gateway|modem|\bap\b|-ap-", ROUTER),
    (r"srv|server|\bdc\d|esx|proxmox|ubuntu|debian|raspberrypi", SERVER),
)

#: Manufacturers (MAC vendor or UPnP manufacturer) that mostly make one kind
#: of device. Weak evidence: only used when nothing better is known.
_VENDOR_WORDS: tuple[tuple[str, str], ...] = (
    (r"hikvision|dahua|reolink|axis comm|hanwha|uniview|amcrest|wyze|arlo|ezviz", CAMERA),
    (r"synology|qnap|western digital|seagate|buffalo|netgear storage", STORAGE),
    (r"hewlett|hp inc|epson|canon|brother|lexmark|kyocera|xerox|ricoh|konica", PRINTER),
    (r"sonos|bose|harman|denon|yamaha", SPEAKER),
    (r"roku|google|chromecast", MEDIA),
    (r"lg electronics|tcl|hisense|vizio|sony visual|sharp|philips tv|toshiba visual", TV),
    (r"nintendo|sony interactive|microsoft xbox", CONSOLE),
    (r"espressif|tuya|shelly|sonoff|itead|signify|philips lighting|ecobee|nest labs|tp-link "
     r"kasa|lifx|xiaomi iot|ring", SMART_HOME),
    (r"ubiquiti|ruckus|aruba|cambium|engenius", ACCESS_POINT),
    (r"cisco|juniper|mikrotik|netgear|tp-link|d-link|zyxel|huawei|zte|sagemcom|arris|"
     r"technicolor|fritz|avm|tenda|linksys|asus", ROUTER),
    (r"apple", PHONE),
    (r"samsung|xiaomi|oneplus|oppo|vivo|motorola|realme|honor", PHONE),
    (r"raspberry", SERVER),
    (r"intel|azurewave|liteon|realtek|giga-byte|asustek|micro-star|dell|lenovo|"
     r"cloud network|hon hai|foxconn|quanta", COMPUTER),
)

#: Engine fingerprints that already settle the category.
_ENGINE_TYPES: dict[str, str] = {
    "Router": ROUTER,
    "Printer": PRINTER,
    "IP Camera": CAMERA,
    "Network Device": NETWORK,
    "Windows PC": COMPUTER,
    "Linux Server": SERVER,
    "Server": SERVER,
    "Raspberry Pi": SERVER,
    "IoT Device": SMART_HOME,
    "Apple Device": COMPUTER,
}

_PORT_HINTS: tuple[tuple[frozenset[int], str], ...] = (
    (frozenset({631, 9100, 515}), PRINTER),
    (frozenset({554, 8554, 37777, 34567}), CAMERA),
    (frozenset({5000, 5001}) , STORAGE),
    (frozenset({8008, 8009}), MEDIA),
    (frozenset({1883, 8883}), SMART_HOME),
    (frozenset({3389, 135, 139, 445}), COMPUTER),
    (frozenset({22, 3306, 5432, 6379, 9090}), SERVER),
    (frozenset({53, 67, 1900, 7547}), ROUTER),
)


def _first_match(text: str, table: Iterable[tuple[str, str]]) -> str:
    if not text:
        return ""
    for pattern, category in table:
        if re.search(pattern, text, re.IGNORECASE):
            return category
    return ""


def categorize(
    device: Device,
    *,
    self_description: str = "",
    model_text: str = "",
    gateway: str = "",
    local_ips: frozenset[str] | set[str] = frozenset(),
) -> str:
    """
    Pick the category key for a device.

    ``self_description`` is the UPnP device types and mDNS services the device
    published, joined; ``model_text`` its announced model and friendly name.
    """
    ip = device.ip_address
    if ip in local_ips:
        return THIS_COMPUTER
    if gateway and ip == gateway:
        return ROUTER

    category = _first_match(self_description, _SELF_DESCRIBED)
    if category:
        return category
    category = _first_match(" ".join(filter(None, (model_text, device.model))), _MODEL_WORDS)
    if category:
        return category
    category = _first_match(device.hostname, _HOSTNAME_WORDS)
    if category:
        return category

    open_ports = {p.number for p in device.open_ports if p.is_open}
    engine = _ENGINE_TYPES.get(device.device_type, "")
    # Ports that name a single job (printing, RTSP) beat the vendor guess.
    for ports, hinted in _PORT_HINTS[:5]:
        if open_ports & ports:
            return hinted
    if engine in (PRINTER, CAMERA, ROUTER, NETWORK):
        return engine

    vendor = _first_match(device.vendor, _VENDOR_WORDS)
    if is_randomized_mac(device.mac_address) and not open_ports:
        # Private (randomised) addresses are a phone, tablet or laptop habit;
        # with nothing listening, a phone is by far the likeliest.
        return PHONE
    if vendor == PHONE and open_ports & {135, 139, 445, 3389, 22}:
        vendor = COMPUTER                     # an Apple/Samsung box serving files
    if vendor:
        return vendor
    if engine:
        return engine
    for ports, hinted in _PORT_HINTS[5:]:
        if open_ports & ports:
            return hinted
    if device.os_name == "Windows":
        return COMPUTER
    return UNKNOWN
