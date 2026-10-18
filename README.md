
## Installation et lancement (Windows / PowerShell)

### 1. Ouvrir le dossier du projet

```powershell
# Se placer dans le dossier du projet
Set-Location "$HOME\Desktop\log-analyzer"
```

### 2. Vérifier l'installation de Python

```powershell
# Afficher la version de Python installée
python --version
```

Python 3.14 ou une version compatible doit être installée.

### 3. Lancer l'analyseur de journaux

```powershell
# Analyser les journaux contenus dans sample_logs.csv
python log_analyzer.py
```

Le programme compte les échecs de connexion, détecte les activités suspectes et affiche les résultats dans le terminal.

### 4. Générer le rapport CSV

Le rapport `alerts_report.csv` est créé automatiquement lors du lancement de l'analyseur.

```powershell
# Vérifier que le rapport a été créé
Test-Path .\alerts_report.csv

# Ouvrir le rapport avec Excel, si Excel est installé
Invoke-Item .\alerts_report.csv
```

Le rapport contient l'adresse IP suspecte, le nombre de tentatives détectées et la période correspondante.

### 5. Exécuter les tests automatisés

```powershell
# Lancer tous les tests et afficher les détails
python -m unittest -v
```

Résultat attendu : **6 tests réussis et `OK`**.

Les tests vérifient le comptage des échecs, la détection temporelle, l'ignorance des connexions réussies et l'export CSV.

### 6. Fichiers principaux

- `log_analyzer.py` : code principal de l'analyseur.
- `sample_logs.csv` : données fictives utilisées pour l'analyse.
- `test_log_analyzer.py` : tests automatisés.
- `alerts_report.csv` : rapport généré automatiquement.
- `README.md` : documentation du projet.

### Technologies utilisées

- Python
- CSV
- `collections` (`Counter`, `defaultdict`)
- `datetime`
- `unittest`

### Limites

Ce projet est un outil pédagogique de détection défensive utilisant des journaux fictifs. Une alerte indique une activité potentiellement suspecte, mais ne prouve pas à elle seule qu'une attaque a eu lieu.
