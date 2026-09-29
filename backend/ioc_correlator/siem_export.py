"""Exportación de un escaneo a formatos SIEM / Threat Intelligence estándar.

Roadmap I2 ("Export a SIEM"). Permite volcar el resultado de un escaneo a
formatos interoperables que consumen las plataformas de seguridad reales:

- **STIX 2.1**: bundle con un `indicator` SDO (patrón según el tipo de IOC),
  más un `attack-pattern` + `relationship` por cada técnica MITRE detectada.
- **MISP Event JSON**: evento con sus atributos, listo para importar en MISP.

Todo con librería estándar (json/uuid/datetime); no añade dependencias ni
puede romper el escaneo (es una serialización pura de datos ya calculados).

Los identificadores STIX son deterministas (uuid5 sobre el IOC) para que
re-exportar el mismo indicador produzca el mismo `id` — así una plataforma
receptora lo trata como actualización, no como duplicado.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

# Namespace propio para derivar UUIDs deterministas (uuid5).
_NS = uuid.UUID("6b6963f0-b1ec-4ec0-9a11-0000b1ecec00")

# ---------------------------------------------------------------------------
# Mapas de tipo de IOC → representación en cada formato
# ---------------------------------------------------------------------------

# Patrón STIX 2.1 por tipo de IOC (el valor se inyecta escapado).
def _stix_pattern(ioc_type: str, value: str) -> str:
    v = _escape_stix(value)
    mapping = {
        "ipv4":   f"[ipv4-addr:value = '{v}']",
        "ipv6":   f"[ipv6-addr:value = '{v}']",
        "domain": f"[domain-name:value = '{v}']",
        "url":    f"[url:value = '{v}']",
        "md5":    f"[file:hashes.'MD5' = '{v}']",
        "sha1":   f"[file:hashes.'SHA-1' = '{v}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v}']",
    }
    # Fallback genérico: artifact con el valor como payload textual.
    return mapping.get(ioc_type, f"[artifact:payload_bin = '{v}']")


# Tipo de atributo MISP por tipo de IOC.
_MISP_ATTR_TYPE = {
    "ipv4":   "ip-dst",
    "ipv6":   "ip-dst",
    "domain": "domain",
    "url":    "url",
    "md5":    "md5",
    "sha1":   "sha1",
    "sha256": "sha256",
}

# Etiqueta STIX de indicador según veredicto.
_STIX_LABEL = {
    "critical":   "malicious-activity",
    "malicious":  "malicious-activity",
    "suspicious": "anomalous-activity",
    "clean":      "benign",
}

# threat_level_id de MISP: 1=High, 2=Medium, 3=Low, 4=Undefined.
_MISP_THREAT = {
    "critical":   1,
    "malicious":  1,
    "suspicious": 2,
    "clean":      3,
}


def _escape_stix(value: str) -> str:
    """Escapa comillas y backslashes para un literal de patrón STIX."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _stix_ts(dt: datetime | None) -> str:
    """Formatea a timestamp STIX (UTC, milisegundos, sufijo Z)."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _det_id(kind: str, seed: str) -> str:
    """ID STIX determinista: <kind>--<uuid5(seed)>."""
    return f"{kind}--{uuid.uuid5(_NS, f'{kind}:{seed}')}"


# ---------------------------------------------------------------------------
# STIX 2.1
# ---------------------------------------------------------------------------

def to_stix(scan: Any) -> dict:
    """Construye un bundle STIX 2.1 a partir de una ScanResponse.

    `scan` debe exponer: ioc_value, ioc_type, score, verdict, ai_summary,
    created_at, connector_results (dict) y mitre_techniques (lista con .id,
    .name, .tactic, .reason).
    """
    now = _stix_ts(getattr(scan, "created_at", None))
    ioc_value = scan.ioc_value
    ioc_type = scan.ioc_type
    verdict = scan.verdict or "unknown"

    # Fuentes que dieron un veredicto positivo (para la descripción).
    hits = _positive_sources(scan)
    label = _STIX_LABEL.get(verdict, "anomalous-activity")

    indicator_id = _det_id("indicator", ioc_value)
    description = (
        f"Blue-Echo: {ioc_value} clasificado como {verdict.upper()} "
        f"(score {scan.score}/100). Fuentes positivas: "
        f"{', '.join(hits) if hits else 'ninguna'}."
    )

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": now,
        "modified": now,
        "name": f"{ioc_type}:{ioc_value}",
        "description": description,
        "indicator_types": [label],
        "pattern": _stix_pattern(ioc_type, ioc_value),
        "pattern_type": "stix",
        "valid_from": now,
        "labels": [label],
        "confidence": _confidence(scan.score),
        # Propiedades propias (prefijo x_ según convención STIX).
        "x_blue_echo_score": scan.score,
        "x_blue_echo_verdict": verdict,
        "x_blue_echo_sources": hits,
    }

    objects: list[dict] = [indicator]

    # Una attack-pattern + relationship por técnica MITRE detectada.
    for tech in getattr(scan, "mitre_techniques", []) or []:
        tech_id = getattr(tech, "id", None)
        if not tech_id:
            continue
        ap_id = _det_id("attack-pattern", tech_id)
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created": now,
            "modified": now,
            "name": getattr(tech, "name", tech_id),
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": tech_id,
                "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
            }],
        })
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": _det_id("relationship", f"{ioc_value}:{tech_id}"),
            "created": now,
            "modified": now,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": ap_id,
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def _confidence(score: int) -> int:
    """Mapea el score 0-100 a confidence STIX (0-100)."""
    return max(0, min(100, int(score)))


# ---------------------------------------------------------------------------
# MISP Event JSON
# ---------------------------------------------------------------------------

def to_misp(scan: Any) -> dict:
    """Construye un evento MISP (formato de importación) desde una ScanResponse."""
    verdict = scan.verdict or "unknown"
    now = getattr(scan, "created_at", None) or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    attr_type = _MISP_ATTR_TYPE.get(scan.ioc_type)
    # to_ids=True solo si el veredicto sugiere que es accionable como IOC.
    to_ids = verdict in ("critical", "malicious", "suspicious")

    attributes: list[dict] = []
    if attr_type:
        attributes.append({
            "type": attr_type,
            "category": "Network activity" if scan.ioc_type in ("ipv4", "ipv6", "domain", "url") else "Payload delivery",
            "value": scan.ioc_value,
            "to_ids": to_ids,
            "comment": f"Blue-Echo score {scan.score}/100 · {verdict}",
        })

    # Técnicas MITRE como galaxy/tags textuales (interoperable y simple).
    tags = [{"name": f'misp-galaxy:mitre-attack-pattern="{getattr(t, "id", "")}"'}
            for t in (getattr(scan, "mitre_techniques", []) or []) if getattr(t, "id", None)]
    tags.append({"name": f'blue-echo:verdict="{verdict}"'})

    return {
        "Event": {
            "info": f"Blue-Echo IOC {scan.ioc_value} ({verdict})",
            "threat_level_id": _MISP_THREAT.get(verdict, 4),
            "analysis": 2,               # 0=Initial,1=Ongoing,2=Completed
            "date": now.strftime("%Y-%m-%d"),
            "published": False,
            "Attribute": attributes,
            "Tag": tags,
        }
    }


def _positive_sources(scan: Any) -> list[str]:
    """Nombres de conectores cuyo veredicto es malicious/suspicious."""
    out: list[str] = []
    results = getattr(scan, "connector_results", {}) or {}
    for name, r in results.items():
        verdict = getattr(r, "verdict", None)
        if verdict is None and isinstance(r, dict):
            verdict = r.get("verdict")
        if verdict in ("malicious", "suspicious"):
            out.append(name)
    return out
