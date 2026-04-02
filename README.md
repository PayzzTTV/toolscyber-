# RootGuard — Scanner d'Intégrité & Détection de Rootkits

Outil CLI Python qui surveille l'intégrité des fichiers critiques d'un système Linux. Il génère une baseline cryptographique (SHA-256) de l'état sain, puis la compare lors de chaque scan pour détecter toute modification, ajout ou suppression suspecte — typiques d'une infection par rootkit ou d'une compromission système.

## Installation

```bash
git clone https://github.com/<votre-username>/rootguard.git
cd rootguard
pip install -r requirements.txt
```

## Usage

```bash
# Générer la baseline (sur système sain, en root)
sudo python3 main.py baseline

# Scanner le système et comparer à la baseline
sudo python3 main.py scan

# Rapport en JSON (pour intégration CI/CD ou SIEM)
sudo python3 main.py scan --output json

# Voir les chemins surveillés
python3 main.py config --list-paths
```

## Exemple de sortie

```
=== RootGuard Scan Report ===
  Files scanned : 1247
  Anomalies     : 2
  Duration      : 3.41s

[CRITICAL] MODIFIED (1)
  * /etc/passwd
    old: d9d9306eaf0ace2ce...
    new: 0dc05bb02996ee65c...

[HIGH] NEW (1)
  * /usr/bin/evil_binary
    new: 4b2e7f9a1c3d5e6f...
```

## Codes de sortie

| Code | Signification |
|---|---|
| `0` | Aucune anomalie détectée |
| `1` | Anomalies détectées (modified/new/missing) |
| `2` | Erreur de configuration (baseline absente) |

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `ROOTGUARD_LOG_LEVEL` | `INFO` | Niveau de log (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

## Structure du projet

```
core/           Moteur (hasher, baseline, scanner, reporter)
config/         Constantes et chemins surveillés
db/             baseline.json (généré, chmod 400 — ne pas committer)
logs/           Historique des scans
tests/          Tests unitaires (19 tests, coverage 81%)
```

## Tests

```bash
python3 -m pytest tests/ -v --cov=core --cov=config
```

## Chemins surveillés (Linux)

- `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`
- `/etc`
- `/lib`, `/lib64`
- `/boot`

## Sécurité

- Aucun contenu de fichier n'est loggé (uniquement chemin + hash)
- La baseline est mise en lecture seule (`chmod 400`) après génération
- Les pseudo-filesystems (`/proc`, `/sys`, `/dev`) sont exclus
- Les fichiers dynamiques (`.log`, `.tmp`, `.pid`, `.lock`, `.swp`) sont ignorés
