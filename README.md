# MALICIOUS IP FEED

Ce petit projet agrège des listes d'IP malicieuses et les expose via une API HTTP simple, exploitable par n’importe quel pare-feu, reverse proxy ou système de sécurité réseau.

Sources utilisées :

- `firehol_level2.netset` (fichier déjà présent localement)
- `https://feeds.dshield.org/block.txt` (URL indiquée dans `doc.txt`)

L’API retourne un fichier texte avec **une IP ou un réseau CIDR par ligne**.

## Installation

Dans le dossier du projet (`malicious-ip-file-hander`) :

```bash
pip install -r requirements.txt
```

Assure‑toi que le fichier `firehol_level2.netset` est bien présent dans le même répertoire que `main.py`.

## Lancer l’API

Toujours dans le dossier du projet :

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Tu peux adapter l’hôte/port selon ton environnement.

## Endpoints principaux

- **Santé**

  - **Méthode**: `GET`
  - **URL**: `/health`
  - **Réponse**: texte `"OK"`

- **Liste IP agrégées**

  - **Méthode**: `GET`
  - **URL**: `/malicious-ips`
  - **Réponse**: `text/plain`, une IP ou un réseau par ligne (idéal pour alimenter des listes de blocage / règles de sécurité).

- **Rafraîchissement forcé**

  - **Méthode**: `POST`
  - **URL**: `/refresh`
  - **Effet**: force le re‑téléchargement des listes FireHOL + DShield et met à jour `malicious_ips.txt`.

## Intégration (idée générale)

1. Déployer ce service sur un serveur accessible par votre équipement de sécurité (pare-feu, WAF, reverse proxy, etc.).
2. Configurer ce composant pour récupérer régulièrement l’URL :
   - `http://<votre-serveur>:8000/malicious-ips`
3. Utiliser la liste récupérée (une entrée par ligne) dans vos mécanismes de filtrage (listes IP, règles, policies, etc.).

## Mise à jour automatique côté serveur

L’intervalle de mise à jour (en minutes) est paramétrable dans le dashboard.  
Pour déclencher la mise à jour côté serveur, vous pouvez programmer l’exécution régulière de :

```bash
python manage.py update_malicious_ips
```

Par exemple :

- sous Windows : une tâche planifiée (Task Scheduler) qui lance cette commande toutes les X minutes ;
- sous Linux : une entrée `cron` (`*/X * * * * python /chemin/vers/manage.py update_malicious_ips`).

La commande respecte le TTL configuré dans le dashboard. Pour forcer la reconstruction à chaque exécution, ajoutez `--force`.

## Ajout d’une source ATOS (CSV)

Pour fusionner un fichier CSV “ATOS” avec FireHOL + DShield :

1. Copiez vos CSV dans le dossier `atos_feeds/` (à la racine du projet).
2. Le format attendu est :
   - colonne `Addresses` contenant des IP séparées par `;`

À chaque mise à jour, le service lit tous les `*.csv` présents dans `atos_feeds/` et les fusionne dans `malicious_ips.txt`.

