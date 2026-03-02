from datetime import datetime
from pathlib import Path

from django.http import HttpResponse, HttpResponseServerError
from django.shortcuts import render

from .models import FeedConfig, UpdateRun
from .services import (
    ARCHIVE_DIR,
    DSHIELD_URL,
    FIREHOL_URL,
    OUTPUT_FILE,
    ensure_updated,
    get_last_update,
)


def health(request):
    return HttpResponse("OK", content_type="text/plain")


def landing(request):
    recent_runs = UpdateRun.objects.all()[:1]
    last_update = recent_runs[0].run_at if recent_runs else None
    return render(request, "ipfeed/landing.html", {"last_update": last_update})


def malicious_ips(request):
    try:
        force = request.GET.get("force") == "1"
        text = ensure_updated(force=force)
    except Exception as e:  # noqa: BLE001
        return HttpResponseServerError(str(e))
    return HttpResponse(text, content_type="text/plain")


def _file_info(path: Path) -> dict:
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


def _get_config() -> FeedConfig:
    cfg, _ = FeedConfig.objects.get_or_create(
        pk=1, defaults={"update_interval_minutes": 60}
    )
    return cfg


def dashboard(request):
    cfg = _get_config()
    config_error = ""

    if request.method == "POST":
        raw = request.POST.get("update_interval_minutes")
        try:
            minutes = int(raw)
            if minutes < 1 or minutes > 1440:
                raise ValueError
            cfg.update_interval_minutes = minutes
            cfg.save()
        except (TypeError, ValueError):
            config_error = "Valeur invalide, merci de choisir entre 1 et 1440 minutes."

    # Déclenche une mise à jour "automatique" si le TTL est dépassé,
    # sans forcer si le cache est encore valide.
    try:
        ensure_updated()
    except Exception:
        # On ne casse pas le dashboard si la mise à jour échoue
        pass

    firehol_info = {"url": FIREHOL_URL}
    dshield_info = {"url": DSHIELD_URL}
    output_info = _file_info(OUTPUT_FILE)

    archives: list[dict] = []
    if ARCHIVE_DIR.exists():
        for f in sorted(
            ARCHIVE_DIR.glob("malicious_ips_*.txt"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ):
            info = _file_info(f)
            if info["exists"]:
                archives.append(info)

    recent_runs = UpdateRun.objects.all()[:20]
    last_update = recent_runs[0].run_at if recent_runs else None

    context = {
        "last_update": last_update,
        "firehol_info": firehol_info,
        "dshield_info": dshield_info,
        "output_info": output_info,
        "archives": archives,
        "recent_runs": recent_runs,
        "config": cfg,
        "config_error": config_error,
    }
    return render(request, "ipfeed/dashboard.html", context)

