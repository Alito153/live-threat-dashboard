Parfait 👌 je te fais une **version README Beta améliorée** avec :

✅ commandes de test
✅ exemples concrets
✅ explications simples
✅ prêt à coller dans GitHub

---

````markdown
# 🛡️ Live Threat Dashboard (Beta)

Live Threat Dashboard est une API de **Threat Intelligence** permettant  
d’enrichir des IOC (Indicators of Compromise) en temps quasi réel.

Le backend FastAPI interroge plusieurs sources :

- AbuseIPDB → réputation IP
- AlienVault OTX → pulses & tags
- VirusTotal → détections moteurs AV

Les données sont ensuite normalisées et scorées pour produire un **risk_level**.

---

# 🚀 Fonctionnalités

✅ Détection automatique du type d’IOC :

- IP address
- Domain
- URL
- Hash (MD5 / SHA1 / SHA256)

✅ Enrichissement multi-sources

✅ Calcul d’un score de risque :

- risk_points
- risk_level (low / medium / high)

✅ API REST FastAPI

---

# ⚙️ Stack technique

- **Backend** : FastAPI / Uvicorn
- **HTTP client** : requests
- **Threat Intel APIs** :
  - AbuseIPDB
  - AlienVault OTX
  - VirusTotal
- **Configuration** : python-dotenv (.env)
- **Dashboard** : Grafana (en cours)

---

# 📦 Installation

## 1️⃣ Cloner le repo

```bash
git clone <repo_url>
cd live-threat-dashboard
````

---

## 2️⃣ Créer un environnement virtuel (recommandé)

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## 3️⃣ Installer les dépendances

```bash
pip install -r requirements.txt
```

---

## 4️⃣ Configurer `.env`

Créer :

```
backend/.env
```

Exemple :

```env
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
HTTP_TIMEOUT=10
```

⚠️ Important :

* Pas de guillemets
* Pas d’espaces
* Ne jamais commit `.env`

---

# ▶️ Lancer le backend

Depuis le dossier `backend/` :

```bash
cd backend
python -m uvicorn app.main:app --reload
```

Résultat attendu :

```
Uvicorn running on http://127.0.0.1:8000
Application startup complete
```

---

# 🔎 Tester l’API

## ✅ 1) Vérifier que l’API fonctionne

```bash
curl http://127.0.0.1:8000/health
```

Réponse attendue :

```json
{"status": "ok"}
```

---

## ✅ 2) Lookup d’une IP

```bash
curl http://127.0.0.1:8000/lookup/8.8.8.8
```

👉 L’API va :

* détecter type = IP
* appeler AbuseIPDB
* appeler OTX
* appeler VirusTotal
* calculer risk_level

---

## ✅ 3) Lookup d’un domaine

```bash
curl http://127.0.0.1:8000/lookup/example.com
```

---

## ✅ 4) Lookup d’une URL

```bash
curl http://127.0.0.1:8000/lookup/https://example.com
```

---

## ✅ 5) Lookup d’un hash

```bash
curl http://127.0.0.1:8000/lookup/44d88612fea8a8f36de82e1278abb02f
```

(MD5 de test)

---

# 🧪 Mode Debug

Pour afficher les réponses complètes des sources :

```bash
curl "http://127.0.0.1:8000/lookup/8.8.8.8?debug=true"
```

👉 Inclut :

* raw AbuseIPDB
* raw OTX
* raw VirusTotal

---

# 📊 Exemple de réponse

```json
{
  "ioc": "8.8.8.8",
  "type": "ip",
  "summary": {
    "risk_level": "low",
    "risk_points": 0,
    "signals": []
  },
  "abuseipdb": {...},
  "otx": {...},
  "virustotal": {...}
}
```

---

# ⚠️ Limitations Beta

* Pas encore de cache IOC
* Pas encore de persistance DB complète
* Appels APIs synchrones
* Pas encore de gestion avancée des quotas API

---

# 🎯 Roadmap

* [ ] Cache IOC
* [ ] Stockage PostgreSQL
* [ ] Metrics temps réel
* [ ] Enrichissement async (httpx / asyncio)
* [ ] Panels Grafana avancés

---

# 👨‍💻 Objectif du projet

Projet développé pour :

🎓 Apprentissage cybersécurité / threat intelligence
💼 Portfolio GitHub / démonstration SOC-like
🛡️ Compréhension des APIs de réputation / scoring

---

```
