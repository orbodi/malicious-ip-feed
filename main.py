from datetime import datetime, timedelta
from pathlib import Path
from typing import List

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse


BASE_DIR = Path(__file__).resolve().parent
FIREHOL_FILE = BASE_DIR / "firehol_level2.netset"
DSHIELD_URL = "https://feeds.dshield.org/block.txt"
OUTPUT_FILE = BASE_DIR / "malicious_ips.txt"
ARCHIVE_DIR = BASE_DIR / "archives"

# Durée de mise en cache avant de retélécharger les listes
# Ici: 60 minutes pour forcer au max une mise à jour par heure.
CACHE_TTL_MINUTES = 60

app = FastAPI(title="ATOS IP FEED")

_last_update: datetime | None = None
_cached_text: str = ""


def _parse_firehol(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"Fichier FireHOL introuvable: {path}")

    ips: List[str] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # enlever éventuels commentaires en fin de ligne
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
    firehol_ips = _parse_firehol(FIREHOL_FILE)
    dshield_ips = _parse_dshield(DSHIELD_URL)

    all_ips = sorted(set(firehol_ips) | set(dshield_ips))

    text = "\n".join(all_ips)
    if not text.endswith("\n"):
        text += "\n"

    # archiver l’ancien fichier AVANT d’écrire le nouveau
    _archive_existing_file()
    OUTPUT_FILE.write_text(text, encoding="utf-8")
    return text


def _ensure_updated(force: bool = False) -> str:
    global _last_update, _cached_text

    now = datetime.utcnow()
    if (
        not force
        and _last_update is not None
        and now - _last_update < timedelta(minutes=CACHE_TTL_MINUTES)
        and _cached_text
    ):
        return _cached_text

    try:
        text = _build_combined_list()
    except Exception as exc:  # noqa: BLE001
        # En cas d’erreur, si on a déjà un fichier local, on le sert quand même
        if OUTPUT_FILE.exists():
            _cached_text = OUTPUT_FILE.read_text(encoding="utf-8", errors="ignore")
            return _cached_text
        raise exc

    _cached_text = text
    _last_update = now
    return text


@app.on_event("startup")
def startup_update() -> None:
    # On essaie de préparer la liste au démarrage,
    # mais on n’interrompt pas l’API si ça échoue.
    try:
        _ensure_updated(force=True)
    except Exception:
        pass


@app.get("/health", response_class=PlainTextResponse)
def health() -> str:
    return "OK"


@app.get("/malicious-ips", response_class=PlainTextResponse)
def get_malicious_ips() -> PlainTextResponse:
    """
    Endpoint principal à pointer depuis vos équipements de sécurité.

    Retourne un texte brut, une IP / réseau par ligne.
    """
    try:
        text = _ensure_updated()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except requests.RequestException as exc:
        # Si pas de connexion ET pas de fichier local, on renvoie 503
        if not OUTPUT_FILE.exists():
            raise HTTPException(
                status_code=503,
                detail="Impossible de mettre à jour les listes (pas de cache local).",
            ) from exc
        text = OUTPUT_FILE.read_text(encoding="utf-8", errors="ignore")

    return PlainTextResponse(text, media_type="text/plain")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    """
    Petit tableau de bord HTML pour suivre :
    - le fichier FireHOL local
    - la source DShield
    - le fichier final et ses archives
    """

    def file_info(path: Path) -> dict:
        if not path.exists():
            return {"exists": False}
        stat = path.stat()
        try:
            line_count = sum(1 for _ in path.open("r", encoding="utf-8", errors="ignore"))
        except OSError:
            line_count = None
        return {
            "exists": True,
            "path": str(path),
            "size": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime),
            "lines": line_count,
        }

    firehol_info = file_info(FIREHOL_FILE)
    output_info = file_info(OUTPUT_FILE)

    archives: list[dict] = []
    if ARCHIVE_DIR.exists():
        for f in sorted(ARCHIVE_DIR.glob("malicious_ips_*.txt"), key=lambda p: p.stat().st_mtime, reverse=True):
            info = file_info(f)
            if info["exists"]:
                archives.append(info)

    last_update_str = _last_update.isoformat(sep=" ", timespec="seconds") if _last_update else "Jamais"

    html_parts: list[str] = []
    html_parts.append("<html><head><title>ATOS IP FEED - Dashboard</title>")
    html_parts.append(
        "<style>"
        "body{font-family:Arial,Helvetica,sans-serif;margin:20px;}"
        "table{border-collapse:collapse;margin-bottom:20px;}"
        "th,td{border:1px solid #ccc;padding:4px 8px;font-size:13px;}"
        "th{background:#f5f5f5;}"
        "h1,h2{font-family:Arial,Helvetica,sans-serif;}"
        "</style></head><body>"
    )

    html_parts.append("<h1>ATOS IP FEED - Dashboard</h1>")
    html_parts.append(f"<p><strong>Dernière mise à jour en mémoire :</strong> {last_update_str}</p>")

    # FireHOL
    html_parts.append("<h2>Source FireHOL</h2>")
    html_parts.append("<table><tr><th>Chemin</th><th>Existe</th><th>Taille (octets)</th><th>Lignes</th><th>Dernière modif.</th></tr>")
    if firehol_info["exists"]:
        html_parts.append(
            "<tr>"
            f"<td>{firehol_info['path']}</td>"
            "<td>oui</td>"
            f"<td>{firehol_info['size']}</td>"
            f"<td>{firehol_info['lines']}</td>"
            f"<td>{firehol_info['mtime']}</td>"
            "</tr>"
        )
    else:
        html_parts.append(
            "<tr><td colspan='5'>Fichier FireHOL introuvable</td></tr>"
        )
    html_parts.append("</table>")

    # DShield
    html_parts.append("<h2>Source DShield</h2>")
    html_parts.append("<table><tr><th>URL</th></tr>")
    html_parts.append(f"<tr><td>{DSHIELD_URL}</td></tr>")
    html_parts.append("</table>")

    # Fichier final
    html_parts.append("<h2>Fichier final (malicious_ips.txt)</h2>")
    html_parts.append("<table><tr><th>Chemin</th><th>Existe</th><th>Taille (octets)</th><th>Lignes</th><th>Dernière modif.</th></tr>")
    if output_info["exists"]:
        html_parts.append(
            "<tr>"
            f"<td>{output_info['path']}</td>"
            "<td>oui</td>"
            f"<td>{output_info['size']}</td>"
            f"<td>{output_info['lines']}</td>"
            f"<td>{output_info['mtime']}</td>"
            "</tr>"
        )
    else:
        html_parts.append(
            "<tr><td colspan='5'>Fichier final non encore généré</td></tr>"
        )
    html_parts.append("</table>")

    # Archives
    html_parts.append("<h2>Archives du fichier final</h2>")
    html_parts.append("<table><tr><th>Chemin</th><th>Taille (octets)</th><th>Lignes</th><th>Dernière modif.</th></tr>")
    if archives:
        for a in archives:
            html_parts.append(
                "<tr>"
                f"<td>{a['path']}</td>"
                f"<td>{a['size']}</td>"
                f"<td>{a['lines']}</td>"
                f"<td>{a['mtime']}</td>"
                "</tr>"
            )
    else:
        html_parts.append(
            "<tr><td colspan='4'>Aucune archive pour le moment</td></tr>"
        )
    html_parts.append("</table>")

    html_parts.append("</body></html>")
    return HTMLResponse("".join(html_parts))


@app.post("/refresh", response_class=PlainTextResponse)
def force_refresh() -> PlainTextResponse:
    """
    Forcer un rafraîchissement des listes (peut être appelé manuellement).
    """
    text = _ensure_updated(force=True)
    return PlainTextResponse(text, media_type="text/plain")

