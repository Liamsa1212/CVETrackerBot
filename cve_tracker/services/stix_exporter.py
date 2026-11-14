"""OASIS STIX 2.1 Cyber Threat Intelligence (CTI) JSON Bundle Generator."""

from datetime import datetime, timezone
import json
from typing import Any, Dict
import uuid
from cve_tracker.models.cve import CVEItem


class STIX21Exporter:
    """Converts normalized CVEItem entities into standard STIX 2.1 JSON bundles."""

    @staticmethod
    def generate_bundle(cve: CVEItem) -> Dict[str, Any]:
        """Generate a compliant STIX 2.1 bundle dictionary."""
        bundle_id = f"bundle--{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        objects = []

        # 1. Vulnerability SDO
        vuln_id = f"vulnerability--{uuid.uuid5(uuid.NAMESPACE_DNS, cve.id)}"
        vuln_sdo: Dict[str, Any] = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vuln_id,
            "created": now_iso,
            "modified": now_iso,
            "name": cve.id,
            "description": cve.description,
            "external_references": [
                {"source_name": "cve", "external_id": cve.id},
                {"source_name": "nvd", "url": f"https://nvd.nist.gov/vuln/detail/{cve.id}"},
            ],
        }

        if cve.cvss and cve.cvss.score is not None:
            vuln_sdo["x_cvss_score"] = cve.cvss.score
            vuln_sdo["x_cvss_severity"] = cve.severity.value
            if cve.cvss.vector_string:
                vuln_sdo["x_cvss_vector"] = cve.cvss.vector_string

        if cve.epss_score is not None:
            vuln_sdo["x_epss_score"] = cve.epss_score

        if cve.cwes:
            for cwe in cve.cwes:
                vuln_sdo["external_references"].append({
                    "source_name": "cwe",
                    "external_id": cwe,
                })

        objects.append(vuln_sdo)

        # 2. Indicator SDO (if weaponized PoC exists)
        if cve.poc_urls:
            indicator_id = f"indicator--{uuid.uuid4()}"
            indicator_sdo = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"PoC Exploit Indicator for {cve.id}",
                "pattern_type": "stix",
                "pattern": f"[url:value = '{cve.poc_urls[0]}']",
                "valid_from": now_iso,
                "indicator_types": ["malicious-activity"],
            }
            objects.append(indicator_sdo)

            # Relationship: Indicator -> indicates -> Vulnerability
            rel_sdo = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid4()}",
                "created": now_iso,
                "modified": now_iso,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": vuln_id,
            }
            objects.append(rel_sdo)

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

    @classmethod
    def export_json_bytes(cls, cve: CVEItem) -> bytes:
        """Serialize bundle into formatted UTF-8 encoded bytes for Telegram document delivery."""
        bundle = cls.generate_bundle(cve)
        return json.dumps(bundle, indent=2).encode("utf-8")
