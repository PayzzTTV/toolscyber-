# CLAUDE.md — RootGuard : Scanner d'Intégrité & Détection de Rootkits

## Vue d'ensemble du projet

**RootGuard** est un outil CLI de cybersécurité en Python qui surveille l'intégrité des fichiers critiques d'un système Linux/Windows. Il génère une baseline (snapshot cryptographique de l'état sain) et la compare lors de chaque scan pour détecter toute modification, ajout ou suppression suspecte — typiques d'une infection par rootkit ou d'une compromission système.

**Cas d'usage principal :** Détection post-incident, audit de conformité, surveillance continue en environnement sensible.

---

## Stack technique

- **Langage :** Python 3.10+
- **Dépendances externes :** aucune pour le core (stdlib uniquement)
- **Optionnelles (features avancées) :** `rich` (UI terminal), `cryptography` (chiffrement baseline), `schedule` (automatisation), `requests` (VirusTotal API)
- **OS cibles :** Linux (priorité), Windows (support secondaire)
- **Stockage :** JSON local (baseline), logs texte/JSON

---

## Architecture du projet

```
rootguard/
├── CLAUDE.md
├── README.md
├── requirements.txt
├── main.py                    # Point d'entrée CLI (argparse)
│
├── core/
│   ├── __init__.py
│   ├── exceptions.py          # HashError, BaselineNotFoundError
│   ├── hasher.py              # Calcul SHA-256 des fichiers
│   ├── baseline.py            # Génération et sauvegarde de la baseline
│   ├── scanner.py             # Moteur de comparaison
│   └── reporter.py            # Formatage et affichage des résultats
│
├── config/
│   ├── __init__.py
│   └── settings.py            # Chemins critiques, extensions ignorées, constantes
│
├── db/
│   └── baseline.json          # Base de données "saine" (générée, ne pas committer)
│
├── logs/
│   └── scan_history.log       # Historique des scans (généré)
│
└── tests/
    ├── test_hasher.py
    ├── test_scanner.py
    ├── test_baseline.py
    ├── test_reporter.py
    └── fixtures/
        └── sample.txt
```

---

## Roadmap & To-Do List

### ✅ V1 — CLI fonctionnel (TERMINÉ)

- [x] `core/exceptions.py` — exceptions typées (`HashError`, `BaselineNotFoundError`)
- [x] `config/settings.py` — chemins Linux critiques et constantes
- [x] `core/hasher.py` — fonction de hash SHA-256 par chunks
- [x] `core/baseline.py` — génération, sauvegarde (`chmod 400`) et chargement JSON
- [x] `core/scanner.py` — moteur de comparaison (modified / new / missing)
- [x] `core/reporter.py` — affichage terminal (`rich` si installé, fallback ASCII) + JSON
- [x] `main.py` — CLI argparse (`baseline`, `scan`, `scan --output json`, `config --list-paths`)
- [x] `tests/` — 19 tests unitaires, coverage 81%
- [x] `README.md` — installation, usage, exemples
- [x] Repo GitHub initialisé et pushé

---

### 🔄 V1.5 — CI/CD & DevSecOps (PROCHAIN SPRINT)

- [ ] `.github/workflows/ci.yml` — pipeline CI :
  - [ ] Job `lint` : `flake8` + `black --check` + `isort --check`
  - [ ] Job `test` : `pytest` avec coverage minimum 80%
  - [ ] Job `security-sast` : `bandit -r core/`
  - [ ] Job `docker-build` : vérifier que l'image compile
  - [ ] Job `docker-scan` : Trivy scan CVE (fail si CRITICAL)
- [ ] `.github/workflows/cd.yml` — pipeline CD :
  - [ ] Build + push image Docker sur GHCR (`latest` + tag SHA)
  - [ ] GitHub Release automatique sur tag `v*`
- [ ] `Dockerfile` — base `python:3.11-slim`, utilisateur non-root
- [ ] `docker-compose.yml` — services `scanner` + `scanner-json`
- [ ] `.dockerignore`
- [ ] Documenter les 4 métriques DORA dans le `README.md`

---

### 🔜 V2 — Robustesse & Automatisation

- [ ] **Scheduling** : mode daemon avec scan périodique via `schedule`
- [ ] **Alerting email** : notification SMTP si anomalie détectée
- [ ] **Alerting Slack** : webhook Slack sur anomalie
- [ ] **Chiffrement de la baseline** : AES-256 via `cryptography`
- [ ] **Signature de la baseline** : hash de la baseline elle-même, stocké séparément

---

### 🔜 V3 — Intelligence & Contexte

- [ ] **VirusTotal API** : vérification des hashes suspects contre la base VT
- [ ] **SUID/SGID checker** : détecter les fichiers avec permissions anormales
- [ ] **Comparaison de permissions** : détecter les changements owner/group/chmod
- [ ] **Détection de symlinks suspects** : liens symboliques vers chemins inhabituels

---

### 🔜 V4 — Temps réel & Dashboard

- [ ] **Daemon inotify** : surveillance temps réel via `watchdog` (Linux)
- [ ] **API REST Flask** : exposition des résultats pour intégration SIEM
- [ ] **Dashboard Next.js** : UI de visualisation
- [ ] **Export SIEM** : format CEF ou JSON structuré compatible Splunk/ELK

---

### 🔜 V5 — Multi-système & Conformité

- [ ] **Support Windows complet** : System32, registre, fichiers de démarrage
- [ ] **Profils de conformité** : CIS Benchmark, PCI-DSS, ANSSI
- [ ] **Rapport PDF** : export d'audit professionnel
- [ ] **Mode réseau** : scan d'hôtes distants via SSH

---

## Règles de développement

### Sécurité (PRIORITÉ ABSOLUE)

- Ne jamais logger les contenus de fichiers, uniquement les chemins et hashes
- La baseline doit être en lecture seule après génération (`chmod 400`)
- Toujours gérer `PermissionError` et `FileNotFoundError` sans crash
- Ne jamais écrire dans les répertoires surveillés
- Valider tous les chemins en entrée (pas de path traversal)

### Qualité du code

- Type hints obligatoires sur toutes les fonctions
- Docstrings sur chaque module et fonction publique
- Gestion d'erreurs explicite, pas de `except Exception: pass`
- Logging via le module `logging` standard, pas de `print()` en production
- Niveau de log configurable via `ROOTGUARD_LOG_LEVEL`

### Performance

- Lecture des fichiers par chunks de 8192 bytes
- Exclure les extensions dynamiques : `.log`, `.tmp`, `.pid`, `.lock`, `.swp`
- Exclure les pseudo-filesystems : `/proc`, `/sys`, `/dev`
