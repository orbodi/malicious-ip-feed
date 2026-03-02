from django.core.management.base import BaseCommand, CommandError

from ipfeed.services import ensure_updated


class Command(BaseCommand):
    help = "Met à jour la liste des IP malicieuses (FireHOL + DShield)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help=(
                "Ignore le cache et force la reconstruction même si le TTL "
                "n'est pas dépassé."
            ),
        )

    def handle(self, *args, **options):
        force: bool = options["force"]
        try:
            text = ensure_updated(force=force)
        except Exception as exc:  # noqa: BLE001
            raise CommandError(str(exc))

        lines = len(text.splitlines())
        self.stdout.write(
            self.style.SUCCESS(
                f"Liste mise à jour ({lines} lignes, force={force})"
            )
        )

