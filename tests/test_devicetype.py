"""Device categories and what devices announce over UPnP and mDNS.

No network traffic: the protocol parsers get hand-built packets and
documents shaped like the real ones captured on a LAN.
"""

import struct
import unittest

from weftscan.core import devicetype as dt
from weftscan.core.discovery import (
    DeviceInfo,
    parse_mdns_response,
    parse_upnp_description,
)
from weftscan.core.hostnames import _encode_name
from weftscan.core.models import Device, Port
from weftscan.core.network import apply_announcement


def _device(ip="10.0.0.5", ports=(), **fields):
    return Device(ip_address=ip, open_ports=[Port(p, "open") for p in ports], **fields)


class Categories(unittest.TestCase):

    def test_this_computer_and_gateway_win(self):
        self.assertEqual(dt.categorize(_device("10.0.0.2"), local_ips={"10.0.0.2"}),
                         dt.THIS_COMPUTER)
        self.assertEqual(dt.categorize(_device("10.0.0.1"), gateway="10.0.0.1"), dt.ROUTER)

    def test_self_description_beats_everything_else(self):
        device = _device(vendor="Hewlett Packard", ports=(445,))
        self.assertEqual(dt.categorize(device, self_description="_googlecast._tcp"), dt.MEDIA)
        self.assertEqual(dt.categorize(device, self_description="_ipp._tcp"), dt.PRINTER)

    def test_model_words(self):
        for model, expected in (("BRAVIA 4K", dt.TV), ("iPhone 15", dt.PHONE),
                                ("DiskStation DS920+", dt.STORAGE),
                                ("HP LaserJet Pro M404", dt.PRINTER),
                                ("Huawei EchoLife HG8245", dt.ROUTER)):
            self.assertEqual(dt.categorize(_device(), model_text=model), expected, model)

    def test_host_names(self):
        for name, expected in (("Galaxy-S23", dt.PHONE), ("DESKTOP-4KQ2", dt.COMPUTER),
                               ("LivingRoom-TV", dt.TV), ("synology-nas", dt.STORAGE)):
            self.assertEqual(dt.categorize(_device(hostname=name)), expected, name)

    def test_ports_that_name_a_job(self):
        self.assertEqual(dt.categorize(_device(ports=(9100,))), dt.PRINTER)
        self.assertEqual(dt.categorize(_device(ports=(554,))), dt.CAMERA)

    def test_randomized_mac_with_nothing_open_is_a_phone(self):
        device = _device(mac_address="92:53:17:29:1D:6C")
        self.assertTrue(dt.is_randomized_mac(device.mac_address))
        self.assertEqual(dt.categorize(device), dt.PHONE)
        self.assertFalse(dt.is_randomized_mac("14:F6:D8:83:56:58"))

    def test_vendor_fallbacks(self):
        self.assertEqual(dt.categorize(_device(vendor="Hikvision Digital")), dt.CAMERA)
        self.assertEqual(dt.categorize(_device(vendor="Samsung Electronics")), dt.PHONE)
        self.assertEqual(dt.categorize(_device(vendor="Intel Corporate")), dt.COMPUTER)

    def test_unknown_when_nothing_is_known(self):
        self.assertEqual(dt.categorize(_device()), dt.UNKNOWN)

    def test_every_category_has_a_name_and_an_icon(self):
        from pathlib import Path
        icons = Path(dt.__file__).resolve().parents[1] / "assets" / "icons"
        for key in dt.CATEGORY_NAMES:
            self.assertTrue((icons / f"{key}_20.png").is_file(), key)


class Upnp(unittest.TestCase):

    DESCRIPTION = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
  <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
  <friendlyName>Living Room TV</friendlyName>
  <manufacturer>LG Electronics</manufacturer>
  <modelName>OLED55C1</modelName><modelNumber>55C1</modelNumber>
  <deviceList><device><deviceType>urn:dial-multiscreen-org:device:dial:1</deviceType>
  </device></deviceList>
</device></root>"""

    def test_description_is_parsed(self):
        info = parse_upnp_description(self.DESCRIPTION, "10.0.0.9")
        self.assertEqual(info.best_name, "Living Room TV")
        self.assertEqual(info.manufacturer, "LG Electronics")
        self.assertEqual(info.best_model, "OLED55C1")
        self.assertIn("urn:schemas-upnp-org:device:MediaRenderer:1", info.upnp_types)

    def test_generic_class_names_are_not_names(self):
        info = DeviceInfo(ip="10.0.0.1", friendly_name="Huawei IGD")
        self.assertEqual(info.best_name, "")

    def test_bad_xml_is_ignored(self):
        self.assertEqual(parse_upnp_description(b"<root><device>", "1.2.3.4").friendly_name, "")


class Mdns(unittest.TestCase):

    @staticmethod
    def _record(name, rtype, rdata):
        return _encode_name(name) + struct.pack("!HHIH", rtype, 1, 120, len(rdata)) + rdata

    def test_service_instance_and_txt(self):
        instance = "Kitchen speaker._googlecast._tcp.local"
        txt = b"".join(bytes([len(item)]) + item for item in (b"fn=Kitchen speaker",
                                                                 b"md=Google Nest Mini"))
        srv = struct.pack("!HHH", 0, 0, 8009) + _encode_name("nest-mini.local")
        packet = (struct.pack("!HHHHHH", 0, 0x8400, 0, 3, 0, 0)
                  + self._record("_googlecast._tcp.local", 12, _encode_name(instance))
                  + self._record(instance, 16, txt)
                  + self._record(instance, 33, srv))
        info = parse_mdns_response(packet, "10.0.0.7")
        self.assertEqual(info.services, {"_googlecast._tcp"})
        self.assertEqual(info.best_name, "Kitchen speaker")
        self.assertEqual(info.best_model, "Google Nest Mini")
        self.assertEqual(info.mdns_host, "nest-mini")

    def test_garbage_does_not_raise(self):
        self.assertEqual(parse_mdns_response(b"\x00\x01garbage", "10.0.0.7").services, set())


class Announcement(unittest.TestCase):

    def test_announced_data_fills_the_device(self):
        device = _device(mac_address="00:11:22:33:44:55")
        info = DeviceInfo(ip=device.ip_address, friendly_name="Office printer",
                          manufacturer="Brother", model="MFC-L2750DW",
                          services={"_ipp._tcp"})
        apply_announcement(device, info)
        self.assertEqual(device.hostname, "Office printer")
        self.assertEqual(device.vendor, "Brother")
        self.assertEqual(device.model, "MFC-L2750DW")
        self.assertIn("IPP printing", device.details["Announced services"])

    def test_existing_host_name_is_kept(self):
        device = _device(hostname="BRN001122")
        apply_announcement(device, DeviceInfo(ip=device.ip_address, friendly_name="Front desk"))
        self.assertEqual(device.hostname, "BRN001122")
        self.assertEqual(device.details["Announced name"], "Front desk")


if __name__ == "__main__":
    unittest.main()
