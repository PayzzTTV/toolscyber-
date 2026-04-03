# RootGuard V2 — Design Document

**Date :** 2026-04-03  
**Scope :** Robustesse & Automatisation — scheduling, alerting, chiffrement baseline  
**Prérequis :** V1 fonctionnelle (CLI, hasher, baseline, scanner, reporter)

---

## 1. Architecture globale

Quatre nouveaux modules ajoutés sans modifier le code V1 :

```
core/
├── hasher.py         (V1 — inchangé)
├── baseline.py       (V1 — étendu : --encrypt flag)
├── scanner.py        (V1 — inchangé)
├── reporter.py       (V1 — inchangé)
├── exceptions.py     (V1 — étendu : SignatureError)
├── crypto.py         (NEW) chiffrement AES-256-GCM + signature
├── alerting.py       (NEW) email SMTP + Slack webhook
└── scheduler.py      (NEW) daemon de scan périodique

config/
└── settings.py       (étendu : SMTP, Slack, intervalle daemon)

main.py               (étendu : commandes daemon + baseline --encrypt)
```

### Flux V2

```
[daemon --interval N]
        │
        └─► scheduler.run_daemon(N)
                │  (boucle toutes les N secondes)
                ├─► scanner.scan(baseline)
                ├─► reporter.report(results)
                └─► alerting.notify(results)  ──► email SMTP
                                               └─► Slack webhook

[baseline --encrypt]
        └─► build_baseline()
            ├─► save_baseline()  (JSON clair)
            ├─► crypto.sign_baseline()  →  db/baseline.sig  (chmod 400)
            └─► crypto.encrypt_baseline()  →  db/baseline.enc  (chmod 400)

[scan] (avec baseline chiffrée)
        └─► crypto.verify_signature()  (si .sig présent)
            └─► crypto.decrypt_baseline()  →  dict en mémoire
                └─► scanner.scan(baseline)
```

---

## 2. Modules détaillés

### `core/crypto.py`

```python
def encrypt_baseline(path: str, key: str) -> str:
    # Lit db/baseline.json
    # Dérive une clé AES via PBKDF2-HMAC-SHA256 (sel aléatoire 16 bytes)
    # Chiffre en AES-256-GCM (nonce 12 bytes)
    # Écrit db/baseline.enc : [sel(16) + nonce(12) + tag(16) + ciphertext]
    # chmod 400 sur .enc
    # Retourne le chemin du fichier chiffré

def decrypt_baseline(enc_path: str, key: str) -> dict:
    # Lit db/baseline.enc
    # Extrait sel, nonce, tag, ciphertext
    # Dérive la clé (même sel), déchiffre AES-256-GCM
    # Retourne le dict des fichiers

def sign_baseline(path: str) -> str:
    # Calcule SHA-256 de db/baseline.json
    # Écrit db/baseline.sig (hexdigest)
    # chmod 400 sur .sig
    # Retourne le hexdigest

def verify_signature(path: str, sig_path: str) -> None:
    # Recalcule SHA-256 du fichier
    # Compare avec db/baseline.sig
    # Lève SignatureError si différent
```

**Dépendance :** module `cryptography` (`pip install cryptography`)  
**Clé :** uniquement depuis `ROOTGUARD_ENCRYPT_KEY` (env var), jamais loggée ni stockée  
**Format `.enc` :** `[sel 16B][nonce 12B][tag 16B][ciphertext]` — tout en binaire, auto-suffisant

### `core/alerting.py`

```python
def notify(results: dict, cfg: dict) -> None:
    # Envoie uniquement si anomalies > 0
    # Dispatche vers les canaux configurés

def send_email(results: dict, cfg: dict) -> None:
    # smtplib stdlib (pas de requests)
    # Corps texte : résumé + listes modified/new/missing
    # cfg keys : host, port, user, password, to, use_tls

def send_slack(results: dict, cfg: dict) -> None:
    # urllib.request (pas de requests)
    # Payload JSON avec blocs de texte formatés
    # cfg keys : webhook_url
```

**Config depuis env vars :**
- `ROOTGUARD_SMTP_HOST`, `ROOTGUARD_SMTP_PORT`, `ROOTGUARD_SMTP_USER`, `ROOTGUARD_SMTP_PASSWORD`, `ROOTGUARD_SMTP_TO`
- `ROOTGUARD_SLACK_WEBHOOK`

### `core/scheduler.py`

```python
def run_daemon(
    interval_seconds: int,
    baseline_path: str,
    encrypt_key: str | None,
) -> None:
    # Boucle infinie avec signal.signal(SIGINT/SIGTERM) pour arrêt gracieux
    # À chaque cycle :
    #   1. load_baseline (ou decrypt_baseline si clé présente)
    #   2. verify_signature si .sig présent
    #   3. scanner.scan()
    #   4. reporter.report()
    #   5. alerting.notify() si anomalies
    #   6. sleep(interval_seconds)
    # Log : "[DAEMON] Cycle N — X fichiers — Y anomalies — prochain scan dans Zs"
```

### `core/exceptions.py` (étendu)

```python
class SignatureError(Exception):
    # Levée si hash actuel ≠ hash dans .sig
    def __init__(self, path: str) -> None: ...
```

### `config/settings.py` (étendu)

```python
# Daemon
DAEMON_INTERVAL: int = int(os.environ.get("ROOTGUARD_INTERVAL", "3600"))

# Alerting — valeurs depuis env vars uniquement
SMTP_HOST: str = os.environ.get("ROOTGUARD_SMTP_HOST", "")
SMTP_PORT: int = int(os.environ.get("ROOTGUARD_SMTP_PORT", "587"))
SMTP_USER: str = os.environ.get("ROOTGUARD_SMTP_USER", "")
SMTP_PASSWORD: str = os.environ.get("ROOTGUARD_SMTP_PASSWORD", "")
SMTP_TO: str = os.environ.get("ROOTGUARD_SMTP_TO", "")
SMTP_USE_TLS: bool = os.environ.get("ROOTGUARD_SMTP_TLS", "true").lower() == "true"
SLACK_WEBHOOK: str = os.environ.get("ROOTGUARD_SLACK_WEBHOOK", "")

# Crypto
BASELINE_ENC_PATH: str = "db/baseline.enc"
BASELINE_SIG_PATH: str = "db/baseline.sig"
```

### `main.py` (étendu)

Nouvelles commandes :

```
python main.py baseline --encrypt       # génère, signe, chiffre
python main.py scan --verify            # vérifie signature avant scan
python main.py daemon                   # lance le daemon (intervalle depuis settings)
python main.py daemon --interval 1800   # override de l'intervalle
```

---

## 3. Sécurité

- `ROOTGUARD_ENCRYPT_KEY` — jamais loggée, jamais dans settings.py, jamais dans le fichier .enc
- PBKDF2-HMAC-SHA256 : 100 000 itérations, sel aléatoire par chiffrement → résistant aux attaques par dictionnaire
- AES-256-GCM : authentifié (intégrité + confidentialité), le tag de 16 bytes détecte toute altération
- `db/baseline.enc` et `db/baseline.sig` → `chmod 400` immédiatement après création
- Alerting : credentials SMTP/Slack uniquement depuis env vars, jamais affichés dans les logs

---

## 4. Tests

### `tests/test_crypto.py`
- Chiffrement + déchiffrement retourne les données originales
- Mauvaise clé lève une exception (InvalidTag)
- Signature valide → `verify_signature` ne lève rien
- Signature altérée → lève `SignatureError`

### `tests/test_alerting.py`
- `notify()` n'appelle pas les canaux si 0 anomalies
- `send_email()` construit le bon message (mock SMTP)
- `send_slack()` envoie le bon payload JSON (mock urllib)

### `tests/test_scheduler.py`
- `run_daemon()` appelle `scan()` et `notify()` à chaque cycle (mock sleep + 2 itérations)
- Arrêt propre sur `KeyboardInterrupt`

---

## 5. Codes de sortie (inchangés)

| Code | Signification |
|---|---|
| `0` | Aucune anomalie |
| `1` | Anomalies détectées |
| `2` | Erreur de configuration |
