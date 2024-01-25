import logging
from typing import Literal

import dns.rdata
import octodns.record
import octodns.source.base
import octodns.zone
import pynetbox.core.api
import pynetbox.core.response


class NetBoxDNSSource(octodns.source.base.BaseSource):
    """
    OctoDNS provider for NetboxDNS
    """

    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS: set[str] = {  # noqa
        "A",
        "AAAA",
        "AFSDB",
        "APL",
        "CAA",
        "CDNSKEY",
        "CERT",
        "CNAME",
        "DCHID",
        "DNAME",
        "DNSKEY",
        "DS",
        "HIP",
        "IPSECKEY",
        "LOC",
        "MX",
        "NAPTR",
        "NS",
        "NSEC",
        "PTR",
        "RP",
        "RRSIG",
        "SOA",
        "SPF",
        "SRV",
        "SSHFP",
        "TLSA",
        "TXT",
    }

    def __init__(
        self,
        id: int,  # noqa
        url: str,
        token: str,
        view: str | None | Literal[False] = False,
        ttl=3600,
        replace_duplicates=False,
        make_absolute=False,
    ):
        """
        Initialize the NetboxDNSSource
        """
        self.log = logging.getLogger(f"NetboxDNSSource[{id}]")
        self.log.debug(f"__init__: {id=}, {url=}, {view=}, {replace_duplicates=}, {make_absolute=}")
        super().__init__(id)

        self.api = pynetbox.core.api.Api(url, token)
        self.nb_view = self._get_view(view)
        self.ttl = ttl
        self.replace_duplicates = replace_duplicates
        self.make_absolute = make_absolute

    def _make_absolute(self, value: str) -> str:
        """
        Return dns name with trailing dot to make it absolute

        @param value: dns record value

        @return: absolute dns record value
        """
        if not self.make_absolute or value.endswith("."):
            return value

        absolute_value = value + "."
        self.log.debug(f"relative={value}, absolute={absolute_value}")

        return absolute_value

    def _get_view(self, view: str | None | Literal[False]) -> dict[str, int | str]:
        """
        Get the correct netbox view when requested

        @param view: `False` for no view, `None` for zones without a view, else the view name

        @return: the netbox view id in the netbox query format
        """
        if view is False:
            return {}
        if view is None:
            return {"view": "null"}

        nb_view: pynetbox.core.response.Record = self.api.plugins.netbox_dns.views.get(name=view)
        if nb_view is None:
            msg = f"dns view: '{view}' has not been found"
            self.log.error(msg)
            raise ValueError(msg)

        self.log.debug(f"found view={nb_view.name}, id={nb_view.id}")

        return {"view_id": nb_view.id}

    def _get_nb_zone(self, name: str, view: dict[str, str | int]) -> pynetbox.core.response.Record:
        """
        Given a zone name and a view name, look it up in NetBox.

        @param name: name of the dns zone
        @param view: the netbox view id in the api query format

        @raise pynetbox.RequestError: if declared view is not existent

        @return: the netbox dns zone object
        """
        query_params = {"name": name[:-1], **view}
        nb_zone = self.api.plugins.netbox_dns.zones.get(**query_params)

        self.log.debug(f"found zone={nb_zone.name}, id={nb_zone.id}")

        return nb_zone

    def populate(
        self, zone: octodns.zone.Zone, target: bool = False, lenient: bool = False
    ) -> None:
        """
        Get all the records of a zone from NetBox and add them to the OctoDNS zone

        @param zone: octodns zone
        @param target: when `True`, load the current state of the provider.
        @param lenient: when `True`, skip record validation and do a "best effort" load of data.
        """
        self.log.info(f"populate: name={zone.name}, target={target}, lenient={lenient}")

        records = {}

        nb_zone = self._get_nb_zone(zone.name, view=self.nb_view)
        if not nb_zone:
            self.log.error(f"Zone '{zone.name[:-1]}' not found in view: '{self.nb_view}'")
            raise LookupError

        nb_records = self.api.plugins.netbox_dns.records.filter(zone_id=nb_zone.id)
        for nb_record in nb_records:
            self.log.debug(f"{nb_record.name!r} {nb_record.type!r} {nb_record.value!r}")

            rcd_name: str = nb_record.name if nb_record.name != "@" else ""
            rcd_value: str = nb_record.value if nb_record.value != "@" else nb_record.zone.name

            if nb_record.ttl:
                nb_ttl = nb_record.ttl
            elif nb_record.type == "NS":
                nb_ttl = nb_zone.soa_refresh
            else:
                nb_ttl = nb_zone.default_ttl

            data = {
                "name": rcd_name,
                "type": nb_record.type,
                "ttl": nb_ttl,
                "values": [],
            }
            rdata = dns.rdata.from_text("IN", nb_record.type, rcd_value)
            match rdata.rdtype.name:
                case "A" | "AAAA":
                    value = rdata.address

                case "CNAME":
                    value = self._make_absolute(rdata.target.to_text())

                case "DNAME" | "NS" | "PTR":
                    value = rdata.target.to_text()

                case "CAA":
                    value = {
                        "flags": rdata.flags,
                        "tag": rdata.tag,
                        "value": rdata.value,
                    }

                case "LOC":
                    value = {
                        "lat_direction": "N" if rdata.latitude[4] >= 0 else "S",
                        "lat_degrees": rdata.latitude[0],
                        "lat_minutes": rdata.latitude[1],
                        "lat_seconds": rdata.latitude[2] + rdata.latitude[3] / 1000,
                        "long_direction": "W" if rdata.latitude[4] >= 0 else "E",
                        "long_degrees": rdata.longitude[0],
                        "long_minutes": rdata.longitude[1],
                        "long_seconds": rdata.longitude[2] + rdata.longitude[3] / 1000,
                        "altitude": rdata.altitude / 100,
                        "size": rdata.size / 100,
                        "precision_horz": rdata.horizontal_precision / 100,
                        "precision_vert": rdata.veritical_precision / 100,
                    }

                case "MX":
                    value = {
                        "preference": rdata.preference,
                        "exchange": self._make_absolute(rdata.exchange.to_text()),
                    }

                case "NAPTR":
                    value = {
                        "order": rdata.order,
                        "preference": rdata.preference,
                        "flags": rdata.flags,
                        "service": rdata.service,
                        "regexp": rdata.regexp,
                        "replacement": rdata.replacement.to_text(),
                    }

                case "SSHFP":
                    value = {
                        "algorithm": rdata.algorithm,
                        "fingerprint_type": rdata.fp_type,
                        "fingerprint": rdata.fingerprint,
                    }

                case "SOA":
                    self.log.debug("SOA")
                    continue

                case "SPF" | "TXT":
                    value = rcd_value.replace(";", r"\;")

                case "SRV":
                    value = {
                        "priority": rdata.priority,
                        "weight": rdata.weight,
                        "port": rdata.port,
                        "target": self._make_absolute(rdata.target.to_text()),
                    }

                case _:
                    raise ValueError

            if (rcd_name, nb_record.type) not in records:
                records[(rcd_name, nb_record.type)] = data
            records[(rcd_name, nb_record.type)]["values"].append(value)

        for data in records.values():
            if len(data["values"]) == 1:
                data["value"] = data.pop("values")[0]
            record = octodns.record.Record.new(
                zone=zone,
                name=data["name"],
                data=data,
                source=self,
                lenient=lenient,
            )
            zone.add_record(record, lenient=lenient, replace=self.replace_duplicates)

        self.log.info(f"populate: found {len(zone.records)} records for zone {zone.name}")
