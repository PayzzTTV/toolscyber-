# RootGuard V1 — Design Document

**Date :** 2026-04-02  
**Scope :** CLI de détection de rootkits par comparaison de hashes SHA-256  
**Répertoire :** `/Users/alexisdelburg/Desktop/Claude/rootguard/`

---

## 1. Architecture & flux de données

### Structure des fichiers

```
rootguard/
├── main.py                    # Point d'entrée CLI (argparse)
├── requirements.txt
├── core/
│   ├── __init__.py
│   ├── exceptions.py          # HashError, BaselineNotFoundError
│   ├── hasher.py              # hash_file(path) → SHA-256
│   ├── baseline.py            # build_baseline(), save_baseline(), load_baseline()
│   ├── scanner.py             # scan(baseline) → {modified, new, missing}
│   └── reporter.py            # report(results, mode, duration, total)
├── config/
│   ├── __init__.py
│   └── settings.py            # Constantes : chemins, extensions, config
├── db/
│   └── baseline.json          # Généré, chmod 400 après création
├── logs/
│   └── scan_history.log       # Généré
└── tests/
    ├── test_hasher.py
    ├── test_scanner.py
    └── fixtures/              # Fichiers statiques pour les tests
```

### Flux baseline

```
settings.CRITICAL_PATHS
    → parcours récursif (os.walk)
    → filtre EXTENSIONS_IGNORE + PSEUDO_FS_EXCLUDE
    → hash_file() par chunk de 8192 bytes
    → dict {path: {hash, size, mtime}}
    → JSON indenté + generated_at (ISO 8601) + system (platform.uname())
    → db/baseline.json (chmod 400)
```

### Flux scan

```
db/baseline.json (load_baseline)
    → scanner.scan(baseline_data)
        → recharge fichiers actuels
        → compare hash par hash
        → {modified: [...], new: [...], missing: [...]}
    → reporter.report(results, mode, duration, total)
    → stdout + logs/scan_history.log
    → exit code 0 (propre) ou 1 (anomalies)
```

---

## 2. Modules détaillés

### `config/settings.py`

| Constante | Valeur |
|---|---|
| `CRITICAL_PATHS` | `["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/etc", "/lib", "/lib64", "/boot"]` |
| `EXTENSIONS_IGNORE` | `{".log", ".tmp", ".pid", ".lock", ".swp"}` |
| `PSEUDO_FS_EXCLUDE` | `{"/proc", "/sys", "/dev"}` |
| `BASELINE_PATH` | `"db/baseline.json"` |
| `LOG_PATH` | `"logs/scan_history.log"` |
| `CHUNK_SIZE` | `8192` |

### `core/exceptions.py`

- `HashError(path: str, original: Exception)` — levée si fichier illisible
- `BaselineNotFoundError(path: str)` — levée si baseline absente au moment du scan

### `core/hasher.py`

```python
def hash_file(path: str) -> str:
    # Lecture binaire par chunks de CHUNK_SIZE
    # Retourne digest SHA-256 hexadécimal
    # Lève HashError si PermissionError ou FileNotFoundError
```

### `core/baseline.py`

```python
def build_baseline() -> dict:
    # Parcours récursif CRITICAL_PATHS
    # Filtre extensions + pseudo-fs
    # Retourne {path: {"hash": str, "size": int, "mtime": float}}

def save_baseline(data: dict, path: str) -> None:
    # JSON indenté, ajoute generated_at + system
    # chmod 400 après écriture

def load_baseline(path: str) -> dict:
    # Désérialise baseline.json
    # Lève BaselineNotFoundError si absent
```

### `core/scanner.py`

```python
def scan(baseline: dict) -> dict:
    # Recharge fichiers actuels depuis CRITICAL_PATHS
    # Compare hash par hash avec la baseline
    # Retourne {"modified": [...], "new": [...], "missing": [...]}
    # Chaque item : {"path": str, "old_hash": str|None, "new_hash": str|None}
```

### `core/reporter.py`

```python
def report(results: dict, mode: str, duration: float, total: int) -> None:
    # mode="terminal" : tente rich, fallback ASCII
    #   - Résumé : nb fichiers scannés, nb anomalies, durée
    #   - CRITICAL (rouge) : modified
    #   - HIGH (jaune) : new
    #   - MEDIUM (cyan) : missing
    # mode="json" : dump JSON sur stdout
```

### `main.py`

Commandes CLI via `argparse` :

| Commande | Action |
|---|---|
| `python main.py baseline` | Génère la baseline |
| `python main.py scan` | Compare avec la baseline |
| `python main.py scan --verbose` | Rapport détaillé |
| `python main.py scan --output json` | Export JSON |
| `python main.py config --list-paths` | Affiche les chemins surveillés |

---

## 3. Gestion des erreurs & sécurité

### Exceptions et comportements

| Situation | Comportement |
|---|---|
| Fichier inaccessible pendant scan | WARNING loggé, fichier exclu (pas de crash) |
| Baseline absente au `scan` | Message clair + exit code 2 |
| `PermissionError` sur `chmod 400` | WARNING loggé, non bloquant |
| Chemin invalide en entrée | Rejeté après validation `os.path.realpath()` |

### Sécurité

- Validation des chemins : `os.path.realpath()` + vérification que le chemin reste dans les racines autorisées (anti path traversal)
- Jamais de contenu de fichier loggé — uniquement chemin et hash
- `db/baseline.json` → `chmod 400` immédiatement après génération
- Ne jamais écrire dans les répertoires surveillés

### Logging

- Module `logging` standard
- Niveau configurable via `ROOTGUARD_LOG_LEVEL` (défaut : `INFO`)
- Format : `%(asctime)s [%(levelname)s] %(name)s: %(message)s`
- Double handler : fichier (`logs/scan_history.log`) + console

---

## 4. Tests

### `tests/test_hasher.py`
- Hash d'un fichier connu avec contenu fixe → vérifie le SHA-256 attendu
- Fichier inexistant → vérifie que `HashError` est levée
- Fichier vide → vérifie que le hash est le SHA-256 de `b""`

### `tests/test_scanner.py`
- Baseline fictive vs état identique → `{modified: [], new: [], missing: []}`
- Fichier modifié → apparaît dans `modified`
- Fichier supprimé → apparaît dans `missing`
- Fichier ajouté → apparaît dans `new`

### `tests/fixtures/`
- `sample.txt` — contenu fixe pour tests de hash reproductibles

---

## 5. Codes de sortie

| Code | Signification |
|---|---|
| `0` | Aucune anomalie détectée |
| `1` | Anomalies détectées (modified/new/missing) |
| `2` | Erreur de configuration (baseline absente, chemin invalide) |

---

## Critère de succès V1

`sudo python3 main.py baseline` génère une baseline valide, et `sudo python3 main.py scan` retourne un rapport correct avec code de sortie 0 ou 1.
