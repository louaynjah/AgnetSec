# 🔒 AgentSec - Système Multi-Agents IA pour l'Audit de Sécurité

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28-red.svg)](https://streamlit.io/)
[![n8n](https://img.shields.io/badge/n8n-1.0-green.svg)](https://n8n.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📋 Description

**AgentSec** est une plateforme d'audit de sécurité automatisée utilisant une architecture multi-agents. Elle orchestre plusieurs scanners de vulnérabilités, analyse les résultats avec l'IA (Groq) et fournit des rapports détaillés avec des recommandations actionnables.

### Architecture Multi-Agents

| Agent | Rôle |
|-------|------|
| **Nmap** | Détection des ports et services |
| **Nuclei** | Vulnérabilités web (7000+ templates) |
| **Nikto** | Vulnérabilités web |
| **SSLScan** | Analyse SSL/TLS |
| **WhatWeb** | Détection des technologies |
| **Gobuster** | Découverte de répertoires |
| **WPScan** | Vulnérabilités WordPress |
| **Hydra** | Tests de force brute |
| **Groq AI** | Analyse intelligente des résultats |

## ✨ Fonctionnalités

- ✅ **Scan automatisé** - Lancement depuis interface web
- ✅ **Multi-scanners** - 8 scanners intégrés
- ✅ **Analyse IA** - Groq (LLaMA 3.3 70B)
- ✅ **Base de données** - SQLite pour l'historique
- ✅ **Tendances** - Graphiques d'évolution
- ✅ **Exports** - CSV, Excel, JSON, PDF
- ✅ **Interface moderne** - Streamlit


## 🚀 Installation

### Prérequis

- Ubuntu 22.04 / Kali Linux
- Python 3.12+
- Node.js 22+
- Docker (optionnel)
- n8n

### Installation rapide
# Cloner le dépôt
git clone https://github.com/votre-username/AgentSec.git

cd AgentSec

# Installer les dépendances
chmod +x scripts/install.sh


./scripts/install.sh

# Lancer n8n
n8n start

# Lancer Streamlit
streamlit run app.py
