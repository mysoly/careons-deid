"""
Pools of realistic synthetic Dutch PII values for anonymization mode.
Each entity type has a list of believable fake replacements.
The FakeDataProvider hands them out consistently: the same original value
always maps to the same fake within a single document.
"""

from itertools import cycle
from typing import Dict, Iterator, List

FAKE_POOLS: Dict[str, List[str]] = {
    "PERSON": [
        "Jan Bakker", "Maria Janssen", "Pieter de Boer",
        "Anna Smit", "Thomas van Dijk", "Lisa Hendriks",
        "Erik Visser", "Sophie Meijer", "Lars Peters",
        "Emma de Groot",
    ],
    "LOCATION": [
        "Utrecht", "Rotterdam", "Den Haag",
        "Eindhoven", "Groningen", "Tilburg",
        "Almere", "Breda", "Nijmegen", "Apeldoorn",
    ],
    "DATE": [
        "14 januari 1983", "27 april 1990", "03 september 1975",
        "19 juni 2001", "08 december 1968", "22 februari 1995",
        "11 oktober 1987", "30 maart 2003", "05 juli 1971",
        "16 augustus 1999",
    ],
    "TIME": [
        "09:15", "11:30", "13:45", "15:00", "16:30",
        "08:00", "10:00", "14:15", "17:00", "18:30",
    ],
    "PHONE_NUMBER": [
        "+31 6 87654321", "+31 6 23456789", "+31 20 7654321",
        "+31 10 8765432", "+31 6 34567890", "+31 30 6543210",
        "+31 6 45678901", "+31 70 5432109", "+31 6 56789012",
        "+31 40 4321098",
    ],
    "EMAIL_ADDRESS": [
        "j.bakker@voorbeeld.nl", "m.janssen@bedrijf.nl",
        "p.smit@mail.nl", "k.dejong@info.nl",
        "a.vandenbosch@webmail.nl", "r.peters@kantoor.nl",
        "l.hendriks@post.nl", "s.verhoeven@digitaal.nl",
        "t.meijer@inbox.nl", "c.visser@netwerk.nl",
    ],
    "ZIPCODE": [
        "2500 GH", "3012 KL", "1071 XB", "5611 BW", "9712 MN",
        "6811 DP", "2280 HV", "3525 EC", "1181 ZH", "4811 PK",
    ],
    # All IBANs verified with ISO 13616 mod-97 checksum.
    "IBAN_CODE": [
        "NL20 INGB 0001 2345 67",
        "NL97 RABO 0156 7890 12",
        "NL22 ABNA 0419 2657 86",
        "NL71 INGB 0009 8765 43",
        "NL63 TRIO 0212 3456 78",
        "NL38 RABO 0300 0000 01",
        "NL54 ABNA 0600 1234 56",
        "NL44 INGB 0050 0000 12",
        "NL41 RABO 0456 7890 01",
        "NL70 ABNA 0502 0417 15",
    ],
    "CREDIT_CARD": [
        "4539 1488 0343 6467", "5425 2334 3010 9903",
        "3714 496353 98431", "6011 1111 1111 1117",
        "4916 1234 5678 9012", "5105 1051 0510 5100",
        "3787 344936 71000", "6011 0009 9013 9424",
        "4532 0151 1283 0366", "5425 2334 3010 9911",
    ],
    # All values pass the Dutch elfproef (11-proef) checksum.
    "BSN": [
        "111222333",
        "100000009",
        "200000007",
        "300000005",
        "400000003",
        "500000001",
        "600000011",
        "987654329",
        "112345670",
        "111000002",
    ],
    "PASSPORT": [
        "XK9876543", "LM2345678", "QR3456789",
        "ST4567890", "UV5678901", "WX6789012",
        "YZ7890123", "AC8901234", "BD9012345",
        "CE0123456",
    ],
    "IP_ADDRESS": [
        "10.20.30.40", "172.16.0.1", "10.0.0.5",
        "192.0.2.1", "198.51.100.2", "203.0.113.3",
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        "2001:0db8:85a3:0000:0000:8a2e:0370:1111",
        "fe80:0000:0000:0000:0202:b3ff:fe1e:8329",
        "fc00:0000:0000:0001:0000:0000:0000:0001",
    ],
    "LICENCE_PLATE": [
        "XK-98-LM", "TZ-23-VB", "GH-45-RN",
        "PD-67-WS", "FJ-89-QA", "BN-12-CE",
        "MR-34-HT", "VK-56-YL", "WD-78-ZP",
        "LT-90-SG",
    ],
    "MAC_ADDRESS": [
        "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66",
        "DE:AD:BE:EF:00:01", "CA:FE:BA:BE:00:01",
        "00:11:22:33:44:55", "FF:EE:DD:CC:BB:AA",
        "12:34:56:78:9A:BC", "AB:CD:EF:01:23:45",
        "9C:8E:99:12:34:56", "3C:7C:3F:AA:BB:CC",
    ],
    "URL": [
        "https://www.voorbeeld.nl/pagina",
        "https://portaal.dienst.nl/account",
        "https://www.bedrijf.nl/info",
        "https://mijn.overheid.nl/status",
        "https://www.webshop.nl/bestelling",
        "https://app.platform.nl/profiel",
        "https://service.organisatie.nl/ticket",
        "https://www.nieuws.nl/artikel",
        "https://klant.bank.nl/overzicht",
        "https://omgeving.systeem.nl/dashboard",
    ],
    "IMEI": [
        "356938035643809", "490154203237518",
        "012345678901239", "358720085007187",
        "867400020458894", "013346001080100",
        "355808004048842", "451006440536429",
        "010928034557457", "352034056932508",
    ],
    "GPS_COORDINATES": [
        "51.9225, 4.4791", "52.3667, 4.8945",
        "51.4416, 5.4697", "53.2194, 6.5665",
        "51.5719, 4.7683", "52.0907, 5.1214",
        "51.8126, 5.8372", "52.7596, 6.9139",
        "51.2434, 6.0561", "50.8514, 5.6909",
    ],
    "HEALTH_IDENTIFIER": [
        "ZP100200300", "VGZ200300400", "CZ30040050",
        "MZ400500600", "1234-5678-9012", "5678-9012-3456",
        "ZS500600700", "OV600700800", "DS70080090",
        "NV800900100",
    ],
}


class FakeDataProvider:
    """
    Hands out fake values for each entity type.
    Within one document, the same original text always gets the same fake
    (consistent substitution). Cycles through the pool if there are more
    unique values than pool entries.
    """

    def __init__(self):
        self._cycles: Dict[str, Iterator[str]] = {
            entity: cycle(pool) for entity, pool in FAKE_POOLS.items()
        }
        self._seen: Dict[str, Dict[str, str]] = {}

    def get(self, entity_type: str, original: str) -> str:
        entity_map = self._seen.setdefault(entity_type, {})
        if original not in entity_map:
            pool = self._cycles.get(entity_type)
            if pool:
                candidate = original
                for _ in range(len(FAKE_POOLS.get(entity_type, ["_"]))):
                    candidate = next(pool)
                    if candidate != original:
                        break
                if candidate == original:
                    candidate = f"[{entity_type}]"
                entity_map[original] = candidate
            else:
                entity_map[original] = f"[{entity_type}]"
        return entity_map[original]
