from django.db import models


class UpdateRun(models.Model):
    run_at = models.DateTimeField(auto_now_add=True)
    entries_count = models.IntegerField()
    firehol_count = models.IntegerField(default=0)
    dshield_count = models.IntegerField(default=0)
    main_file = models.CharField(max_length=255)
    archive_file = models.CharField(max_length=255, blank=True)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-run_at"]

    def __str__(self) -> str:
        status = "OK" if not self.error else "ERROR"
        return f"{self.run_at} - {status} - {self.entries_count} entrées"


class FeedConfig(models.Model):
    """
    Configuration globale du cycle de mise à jour.

    On utilise un seul enregistrement (id=1) pour stocker
    l’intervalle en minutes.
    """

    update_interval_minutes = models.PositiveIntegerField(default=60)

    def __str__(self) -> str:  # pragma: no cover - repr utilitaire
        return f"{self.update_interval_minutes} minutes"
