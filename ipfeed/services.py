from datetime import datetime, timedelta
import csv
from pathlib import Path
from typing import List

import requests
from django.conf import settings

from .models import FeedConfig, UpdateRun


BASE_DIR = Path(settings.BASE_DIR)

FIREHOL_URL = "https://iplists.firehol.org/files/firehol_level2.netset"
DSHIELD_URL = "https://feeds.dshield.org/block.txt"

OUTPUT_FILE = BASE_DIR / "malicious_ips.txt"
ARCHIVE_DIR = BASE_DIR / "archives"
ATOS_FEEDS_DIR = BASE_DIR / "atos_feeds"

DEFAULT_INTERVAL_MINUTES = 60

_last_update: datetime | None = None
_cached_text: str = ""


def _get_config() -> FeedConfig:
    """
    Retourne la configuration actuelle (crée un enregistrement par défaut si besoin).
    """
    cfg, _ = FeedConfig.objects.get_or_create(
        pk=1, defaults={"update_interval_minutes": DEFAULT_INTERVAL_MINUTES}
    )
    return cfg


def get_cache_ttl() -> timedelta:
    cfg = _get_config()
    minutes = cfg.update_interval_minutes or DEFAULT_INTERVAL_MINUTES
    return timedelta(minutes=minutes)


def _parse_firehol(url: str) -> List[str]:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()

    ips: List[str] = []
    for raw in resp.text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split("#", 1)[0].strip()
        if line:
            ips.append(line)
    return ips


def _parse_dshield(url: str) -> List[str]:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()

    ips: List[str] = []
    for raw in resp.text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        # Format dshield: start_ip end_ip mask reports asn country email
        # On garde le réseau sous la forme "start_ip/mask", ex: 66.132.153.0/24
        if len(parts) >= 3:
            start_ip = parts[0].strip()
            mask = parts[2].strip()
            if start_ip and mask:
                ips.append(f"{start_ip}/{mask}")
    return ips


def _parse_atos_csv(csv_path: Path) -> List[str]:
    """
    Parse un CSV "ATOS" au format fourni :
    - entête : Name, Location, Members Count, Addresses, Tags
    - colonne 'Addresses' contient une liste d'IP séparées par ';'
    """
    if not csv_path.exists():
        return []

    ips: List[str] = []
    with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "Addresses" not in reader.fieldnames:
            raise ValueError(
                f"CSV ATOS invalide (colonne 'Addresses' absente) : {csv_path}"
            )

        for row in reader:
            addresses = row.get("Addresses") or ""
            for item in addresses.split(";"):
                ip = item.strip()
                if ip:
                    ips.append(ip)

    return ips


def _archive_existing_file() -> str | None:
    """
    Si le fichier destination existe, on le déplace dans un fichier d’archive.
    Retourne le chemin d’archive (str) ou None.
    """
    if not OUTPUT_FILE.exists():
        return None

    ARCHIVE_DIR.mkdir(exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    archive_path = ARCHIVE_DIR / f"malicious_ips_{ts}.txt"
    OUTPUT_FILE.rename(archive_path)
    return str(archive_path)


def _build_combined_list() -> str:
    firehol_ips = _parse_firehol(FIREHOL_URL)
    dshield_ips = _parse_dshield(DSHIELD_URL)

    firehol_count = len(firehol_ips)
    dshield_count = len(dshield_ips)

    atos_ips: List[str] = []
    if ATOS_FEEDS_DIR.exists():
        for csv_file in sorted(ATOS_FEEDS_DIR.glob("*.csv")):
            atos_ips.extend(_parse_atos_csv(csv_file))

    atos_count = len(atos_ips)

    all_ips = sorted(set(firehol_ips) | set(dshield_ips) | set(atos_ips))
    text = "\n".join(all_ips)
    if not text.endswith("\n"):
        text += "\n"

    archive_path = _archive_existing_file()
    OUTPUT_FILE.write_text(text, encoding="utf-8")

    UpdateRun.objects.create(
        entries_count=len(all_ips),
        firehol_count=firehol_count,
        dshield_count=dshield_count,
        atos_count=atos_count,
        main_file=str(OUTPUT_FILE),
        archive_file=archive_path or "",
    )

    return text


def ensure_updated(force: bool = False) -> str:
    """
    Appelée par la vue.
    - Si dernière mise à jour < CACHE_TTL et pas force=True → on renvoie le cache.
    - Sinon → on reconstruit la liste, archive, sauvegarde l’historique.
    """
    global _last_update, _cached_text

    now = datetime.utcnow()
    ttl = get_cache_ttl()
    if (
        not force
        and _last_update is not None
        and now - _last_update < ttl
        and _cached_text
    ):
        return _cached_text

    try:
        text = _build_combined_list()
        _cached_text = text
        _last_update = now
        return text
    except Exception as exc:  # noqa: BLE001
        UpdateRun.objects.create(
            entries_count=0,
            firehol_count=0,
            dshield_count=0,
            atos_count=0,
            main_file=str(OUTPUT_FILE),
            archive_file="",
            error=str(exc),
        )
        if OUTPUT_FILE.exists():
            return OUTPUT_FILE.read_text(encoding="utf-8", errors="ignore")
        raise


def get_last_update() -> datetime | None:
    return _last_update

