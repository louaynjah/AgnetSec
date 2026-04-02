#!/usr/bin/env python3
"""
Scanner de Vulnérabilités - Interface Streamlit
Auteur: Louay
Version: 2.0
"""

import streamlit as st
import requests
import json
import pandas as pd
import time
import os
from datetime import datetime
import base64
import glob
import plotly.express as px
import plotly.graph_objects as go
from database import *
init_database()
def display_historical_trends():
    """Afficher les graphiques de tendances"""
    st.subheader("📈 Évolution dans le temps")
    
    # Onglets pour les différents graphiques
    trend_tab1, trend_tab2, trend_tab3, trend_tab4 = st.tabs([
        "📊 Score de sécurité", "🔴 Vulnérabilités", "🎯 Cibles", "📋 Historique"
    ])
    
    with trend_tab1:
        # Graphique d'évolution du score
        trends = get_trends(days=30)
        
        if not trends.empty:
            fig = px.line(
                trends, 
                x='date', 
                y='avg_score',
                title='Évolution du score de sécurité moyen (30 jours)',
                labels={'date': 'Date', 'avg_score': 'Score de sécurité'},
                markers=True
            )
            fig.update_layout(height=400)
            fig.update_traces(line=dict(color='#2ecc71', width=3))
            st.plotly_chart(fig, use_container_width=True)
            
            # Statistiques
            col1, col2, col3 = st.columns(3)
            with col1:
                latest_score = trends.iloc[-1]['avg_score'] if not trends.empty else 0
                st.metric("Score actuel", f"{latest_score:.1f}/100")
            with col2:
                best_score = trends['avg_score'].max()
                st.metric("Meilleur score", f"{best_score:.1f}/100")
            with col3:
                trend = trends['avg_score'].iloc[-1] - trends['avg_score'].iloc[0] if len(trends) > 1 else 0
                st.metric("Tendance", f"{trend:+.1f}")
        else:
            st.info("📊 Pas assez de données pour afficher les tendances. Lancez quelques scans d'abord.")
    
    with trend_tab2:
        # Graphique d'évolution des vulnérabilités
        trends = get_trends(days=30)
        
        if not trends.empty:
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=trends['date'], y=trends['avg_critical'], 
                                     name='Critiques', line=dict(color='#c0392b', width=2)))
            fig.add_trace(go.Scatter(x=trends['date'], y=trends['avg_high'], 
                                     name='Élevés', line=dict(color='#e67e22', width=2)))
            fig.add_trace(go.Scatter(x=trends['date'], y=trends['avg_medium'], 
                                     name='Moyens', line=dict(color='#f39c12', width=2)))
            fig.add_trace(go.Scatter(x=trends['date'], y=trends['avg_low'], 
                                     name='Faibles', line=dict(color='#27ae60', width=2)))
            
            fig.update_layout(
                title='Évolution du nombre moyen de vulnérabilités',
                xaxis_title='Date',
                yaxis_title='Nombre moyen de vulnérabilités',
                height=400,
                legend_title="Sévérité"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with trend_tab3:
        # Top cibles vulnérables
        st.subheader("🎯 Cibles les plus vulnérables")
        
        top_targets = get_top_vulnerable_targets(limit=10)
        
        if not top_targets.empty:
            fig = px.bar(
                top_targets,
                x='target',
                y='avg_score',
                color='avg_critical',
                title='Top 10 des cibles avec le plus faible score de sécurité',
                labels={'target': 'Cible', 'avg_score': 'Score moyen', 'avg_critical': 'Moy. critiques'},
                color_continuous_scale='Reds'
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            # Tableau des cibles
            st.dataframe(
                top_targets[['target', 'scan_count', 'avg_score', 'avg_critical', 'avg_high', 'last_scan']],
                use_container_width=True
            )
    
    with trend_tab4:
        # Historique complet
        st.subheader("📋 Historique des scans")
        
        history = get_scan_history(limit=50)
        
        if not history.empty:
            # Filtres
            col1, col2 = st.columns(2)
            with col1:
                target_filter = st.selectbox("Filtrer par cible", ["Toutes"] + list(history['target'].unique()))
            with col2:
                sort_by = st.selectbox("Trier par", ["Date (récent)", "Score (décroissant)", "Score (croissant)"])
            
            # Appliquer filtres
            if target_filter != "Toutes":
                history = history[history['target'] == target_filter]
            
            if sort_by == "Score (décroissant)":
                history = history.sort_values('security_score', ascending=False)
            elif sort_by == "Score (croissant)":
                history = history.sort_values('security_score', ascending=True)
            else:
                history = history.sort_values('completed_at', ascending=False)
            
            # Affichage
            st.dataframe(
                history[['target', 'completed_at', 'security_score', 'risk_level', 
                         'total_findings', 'critical', 'high', 'weak_credentials']],
                use_container_width=True
            )
            
            # Bouton pour exporter l'historique
            if st.button("📥 Exporter l'historique (CSV)"):
                csv = history.to_csv(index=False)
                st.download_button(
                    label="Télécharger",
                    data=csv,
                    file_name="scan_history.csv",
                    mime="text/csv"
                )
        else:
            st.info("📭 Aucun historique disponible. Lancez quelques scans pour commencer.")
# Configuration de la page
st.set_page_config(
    page_title="Scanner de Vulnérabilités - AgentSec",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configuration
N8N_WEBHOOK_URL = "http://localhost:5678/webhook-test/scan"
RESULTS_DIR = "/tmp/vulnscan/results"

# Styles CSS personnalisés
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        color: white;
    }
    .risk-critical {
        background-color: #c0392b;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        text-align: center;
        font-weight: bold;
    }
    .risk-high {
        background-color: #e67e22;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        text-align: center;
        font-weight: bold;
    }
    .risk-medium {
        background-color: #f39c12;
        color: #333;
        padding: 0.5rem;
        border-radius: 5px;
        text-align: center;
        font-weight: bold;
    }
    .risk-low {
        background-color: #27ae60;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        text-align: center;
        font-weight: bold;
    }
    .metric-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    .vuln-card {
        border-left: 4px solid;
        padding: 1rem;
        margin: 1rem 0;
        background-color: #fff;
        border-radius: 5px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .stButton button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        font-weight: bold;
        border: none;
        padding: 0.5rem 2rem;
        border-radius: 8px;
        transition: all 0.3s ease;
    }
    .stButton button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
    }
</style>
""", unsafe_allow_html=True)

# Initialisation de la session
if 'scan_status' not in st.session_state:
    st.session_state.scan_status = None
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'scan_id' not in st.session_state:
    st.session_state.scan_id = None

# ==================== FONCTIONS ====================

def trigger_scan(target, email, ports):
    """Déclencher le scan via n8n webhook"""
    try:
        payload = {
            "target": target,
            "email": email,
            "ports": ports if ports else "1-1000"
        }
        
        with st.spinner("🚀 Lancement du scan..."):
            response = requests.post(
                N8N_WEBHOOK_URL,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "scan_id": data.get("scanId", f"scan_{int(time.time())}"),
                    "message": "Scan lancé avec succès"
                }
            else:
                return {
                    "success": False,
                    "error": f"Erreur HTTP {response.status_code}: {response.text}"
                }
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "Impossible de se connecter à n8n. Vérifie que n8n est lancé sur le port 5678"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def wait_for_scan(scan_id, timeout=300):
    """Attendre la fin du scan - prend le dernier fichier créé"""
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Créer le dossier si nécessaire
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    # Compter les fichiers avant le scan
    before_files = set(glob.glob(f"{RESULTS_DIR}/*.json"))
    
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        # Voir s'il y a de nouveaux fichiers
        current_files = set(glob.glob(f"{RESULTS_DIR}/*.json"))
        new_files = current_files - before_files
        
        if new_files:
            # Prendre le plus récent
            latest = max(new_files, key=os.path.getctime)
            progress_bar.progress(100)
            elapsed = int(time.time() - start_time)
            status_text.success(f"✅ Scan terminé en {elapsed} secondes")
            
            with open(latest, 'r') as f:
                return json.load(f)
        
        elapsed = int(time.time() - start_time)
        progress = min(elapsed / 60, 0.95)
        progress_bar.progress(progress)
        status_text.info(f"⏳ Scan en cours... ({elapsed} secondes)")
        
        time.sleep(5)
    
    # Si timeout, vérifier s'il y a eu des fichiers créés récemment
    all_files = glob.glob(f"{RESULTS_DIR}/*.json")
    if all_files:
        latest = max(all_files, key=os.path.getctime)
        if time.time() - os.path.getctime(latest) < timeout + 10:
            st.warning(f"⚠️ Délai dépassé mais résultat trouvé")
            with open(latest, 'r') as f:
                return json.load(f)
    
    status_text.error("⏰ Aucun résultat trouvé")
    
    return None

def export_to_csv(results):
    """Exporter les vulnérabilités en CSV"""
    findings = []
    
    if results.get('aiAnalysis'):
        for f in results['aiAnalysis'].get('findings_valides', []):
            findings.append({
                'ID': f.get('id', ''),
                'Titre': f.get('titre', ''),
                'Description': f.get('description', ''),
                'Sévérité': f.get('severite', ''),
                'CVSS Score': f.get('cvss_score', 0),
                'Impact': f.get('impact', ''),
                'Remédiation': f.get('remediation', ''),
                'Source': f.get('source', ''),
                'Urgence': f.get('urgence', ''),
                'Effort': f.get('effort', '')
            })
    
    df = pd.DataFrame(findings)
    filename = f"/tmp/vulnscan/report_{results.get('scanId', 'scan')}.csv"
    df.to_csv(filename, index=False, encoding='utf-8-sig')
    return filename

def export_to_excel(results):
    """Exporter en Excel"""
    findings = []
    
    if results.get('aiAnalysis'):
        for f in results['aiAnalysis'].get('findings_valides', []):
            findings.append({
                'ID': f.get('id', ''),
                'Titre': f.get('titre', ''),
                'Description': f.get('description', ''),
                'Sévérité': f.get('severite', ''),
                'CVSS Score': f.get('cvss_score', 0),
                'CVSS Vector': f.get('cvss_vector', ''),
                'Impact': f.get('impact', ''),
                'Remédiation': f.get('remediation', ''),
                'Source': f.get('source', ''),
                'Urgence': f.get('urgence', ''),
                'Effort': f.get('effort', '')
            })
    
    df = pd.DataFrame(findings)
    filename = f"/tmp/vulnscan/report_{results.get('scanId', 'scan')}.xlsx"
    df.to_excel(filename, index=False, engine='openpyxl')
    return filename

def export_to_json(results):
    """Exporter en JSON"""
    filename = f"/tmp/vulnscan/report_{results.get('scanId', 'scan')}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    return filename

def get_download_link(filepath, label):
    """Générer un lien de téléchargement"""
    with open(filepath, 'rb') as f:
        data = f.read()
    b64 = base64.b64encode(data).decode()
    href = f'<a href="data:application/octet-stream;base64,{b64}" download="{os.path.basename(filepath)}">{label}</a>'
    return href

# ==================== INTERFACE PRINCIPALE ====================

# En-tête
st.markdown("""
<div class="main-header">
    <h1>🔒 AgentSec - Scanner de Vulnérabilités</h1>
    <p>Scan complet de votre infrastructure avec analyse IA</p>
    <p style="font-size: 14px; opacity: 0.9;">🔍 Nmap | 🎯 WPScan | 🔐 SSLScan | 🔑 Hydra | 🌐 WhatWeb | 📁 Gobuster</p>
</div>
""", unsafe_allow_html=True)

# Sidebar - Configuration
with st.sidebar:
    st.header("⚙️ Configuration")
    st.info("📡 n8n doit être actif sur localhost:5678")
    
    st.divider()
    
    st.subheader("📊 À propos")
    st.write("""
    **AgentSec** utilise :
    - **n8n** pour l'orchestration des scans
    - **Groq AI** pour l'analyse des résultats
    - **Nmap, WPScan, Hydra, etc.** pour la détection
    
    Les rapports sont générés en PDF et sauvegardés localement.
    """)
    
    st.divider()
    
    if st.button("🔄 Vérifier connexion n8n"):
        try:
            r = requests.get("http://localhost:5678/healthz", timeout=5)
            if r.status_code == 200:
                st.success("✅ n8n est accessible")
            else:
                st.error(f"❌ n8n répond avec code {r.status_code}")
        except Exception as e:
            st.error(f"❌ n8n inaccessible: {e}")

# Colonnes pour les inputs
col1, col2, col3 = st.columns(3)

with col1:
    target = st.text_input(
        "🎯 Cible (IP ou domaine)",
        placeholder="ex: scanme.nmap.org, 192.168.1.1, exemple.com",
        help="Adresse IP ou nom de domaine à scanner"
    )

with col2:
    email = st.text_input(
        "📧 Email destinataire",
        placeholder="ex: security@entreprise.com",
        help="Email pour recevoir le rapport PDF"
    )

with col3:
    ports = st.text_input(
        "🔌 Plage de ports",
        placeholder="ex: 1-1000 ou 22,80,443,8080",
        value="22,80,443,8080",
        help="Ports à scanner (format: 1-1000 ou 22,80,443)"
    )

# Bouton de scan
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    scan_button = st.button(
        "🚀 LANCER LE SCAN",
        type="primary",
        use_container_width=True,
        disabled=not target or not email
    )

# Zone de progression
if scan_button:
    with st.container():
        st.markdown("---")
        st.subheader("📊 Progression du Scan")
        
        # Étape 1: Lancer le scan
        result = trigger_scan(target, email, ports)
        
        if result["success"]:
            st.success(f"✅ Scan lancé avec succès")
            st.info(f"🆔 ID du scan: `{result['scan_id']}`")
            
            # Étape 2: Attendre la fin
            results = wait_for_scan(result["scan_id"])
            
            if results:
                st.session_state.scan_results = results
                st.session_state.scan_id = result["scan_id"]
    
                # Sauvegarder dans la base de données
                try:
                    save_scan_results(results)
                    st.success("✅ Résultats sauvegardés dans l'historique")
                except Exception as e:
                    st.warning(f"⚠️ Erreur lors de la sauvegarde historique: {e}")
    
                st.success("🎉 Scan terminé avec succès!")
                st.balloons()
                st.rerun()
            else:
                st.error("❌ Le scan a échoué ou a dépassé le délai")
        else:
            st.error(f"❌ Erreur: {result.get('error', 'Inconnue')}")

# Affichage des résultats
if st.session_state.scan_results:
    results = st.session_state.scan_results
    
    # Informations de base
    st.markdown("---")
    
    # En-tête des résultats
    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%); border-radius: 10px; padding: 20px; margin-bottom: 20px;">
        <h2 style="color: white; margin: 0;">📊 Rapport de Scan</h2>
        <p style="color: white; margin: 5px 0 0 0;">Cible: {results.get('target', 'N/A')} | ID: {results.get('scanId', 'N/A')}</p>
        <p style="color: white; margin: 0; font-size: 12px;">Terminé le: {results.get('completedAt', 'N/A')}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Onglets
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 Résumé IA", "🔍 Détails des vulnérabilités", "📈 Services détectés", "📤 Export","📜 Historique & Tendances" ])
    
    with tab1:
        st.subheader("🤖 Analyse IA - Résumé Exécutif")
        
        if results.get('aiAnalysis'):
            ai = results['aiAnalysis']
            
            # Score et risque
            col1, col2, col3 = st.columns(3)
            with col1:
                score = ai.get('score_securite', 50)
                st.metric("Score de Sécurité", f"{score}/100", 
                          delta=f"{score - 50:+d}" if score != 50 else None)
            with col2:
                risk = ai.get('risque_global', 'INCONNU')
                risk_class = f"risk-{risk.lower()}" if risk.lower() in ['critical', 'high', 'medium', 'low'] else "risk-medium"
                st.markdown(f"""
                <div class="{risk_class}">
                    <strong>Niveau de risque</strong><br>
                    <span style="font-size: 24px;">{risk}</span>
                </div>
                """, unsafe_allow_html=True)
            with col3:
                stats = ai.get('stats', {})
                st.metric("Total findings", stats.get('total_findings', 0))
            
            # Résumé exécutif
            st.markdown("---")
            st.markdown("### 📝 Résumé Exécutif")
            st.info(ai.get('resume_executif', 'Aucun résumé disponible'))
            
            # Vecteurs d'attaque
            if ai.get('vecteurs_attaque'):
                st.markdown("### 🎯 Vecteurs d'Attaque Prioritaires")
                for v in ai['vecteurs_attaque']:
                    st.warning(f"⚠️ {v}")
            
            # Recommandations
            if ai.get('recommandations_globales'):
                st.markdown("### 💡 Recommandations Stratégiques")
                for r in ai['recommandations_globales']:
                    st.success(f"✅ {r}")
            
            # Plan d'action
            if ai.get('plan_action'):
                st.markdown("### 📋 Plan d'Action")
                plan = ai['plan_action']
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.markdown("**🚨 IMMÉDIAT (24h)**")
                    for a in plan.get('immediat', []):
                        st.write(f"- {a}")
                with col2:
                    st.markdown("**📅 COURT TERME (1 semaine)**")
                    for a in plan.get('court_terme', []):
                        st.write(f"- {a}")
                with col3:
                    st.markdown("**📈 MOYEN TERME (1 mois)**")
                    for a in plan.get('moyen_terme', []):
                        st.write(f"- {a}")
        else:
            st.warning("⚠️ Analyse IA non disponible. Vérifie la configuration Groq dans n8n.")
    
    with tab2:
        st.subheader("🔍 Détail des Vulnérabilités")
        
        if results.get('aiAnalysis'):
            findings = results['aiAnalysis'].get('findings_valides', [])
            
            if findings:
                for f in findings:
                    severity = f.get('severite', 'info').lower()
                    border_color = {
                        'critical': '#c0392b',
                        'high': '#e67e22',
                        'medium': '#f39c12',
                        'low': '#27ae60'
                    }.get(severity, '#95a5a6')
                    
                    with st.expander(f"[{f.get('severite', 'INFO')}] {f.get('titre', 'Vulnérabilité')}"):
                        st.markdown(f"""
                        <div style="border-left: 4px solid {border_color}; padding-left: 15px;">
                            <p><strong>📝 Description:</strong> {f.get('description', '')}</p>
                            <p><strong>💥 Impact:</strong> {f.get('impact', '')}</p>
                            <p><strong>🔧 Remédiation:</strong> {f.get('remediation', '')}</p>
                            <p><strong>📊 CVSS Score:</strong> {f.get('cvss_score', 'N/A')}</p>
                            <p><strong>🎯 Source:</strong> {f.get('source', '')}</p>
                            <p><strong>⏱️ Urgence:</strong> {f.get('urgence', 'NORMALE')} | <strong>⚡ Effort:</strong> {f.get('effort', 'MOYEN')}</p>
                        </div>
                        """, unsafe_allow_html=True)
            else:
                st.info("✅ Aucune vulnérabilité détectée")
        else:
            st.info("📊 Aucune donnée disponible")
    
    with tab3:
        st.subheader("🖥️ Services Détectés")
        
        services = results.get('services', [])
        cves = results.get('cves', [])
        
        if services:
            for s in services:
                with st.expander(f"{s.get('ip', 'N/A')}:{s.get('port', 'N/A')} - {s.get('service', 'unknown')}"):
                    st.write(f"**Version:** {s.get('version', 'N/A')}")
                    st.write(f"**Produit:** {s.get('product', 'N/A')}")
                    if s.get('cpe'):
                        st.write(f"**CPE:** `{s.get('cpe')}`")
            
            # CVEs associées
            if cves:
                st.markdown("### 🛡️ CVEs Associées")
                cve_df = pd.DataFrame(cves)
                st.dataframe(cve_df[['cveId', 'severity', 'cvssScore', 'cveSummary']].head(10), use_container_width=True)
        else:
            st.info("Aucun service détecté")
        
        # Scans additionnels
        st.markdown("### 🔍 Résultats des scans additionnels")
        
        scans = results.get('scans', {})
        
        if scans.get('nikto'):
            with st.expander(f"📋 Nikto ({len(scans['nikto'])} résultats)"):
                for n in scans['nikto'][:10]:
                    st.write(f"- {n.get('msg', '')[:200]}")
        
        if scans.get('ssl'):
            with st.expander(f"🔐 SSL/TLS ({len(scans['ssl'])} résultats)"):
                for s in scans['ssl']:
                    st.write(f"- {s.get('issue', '')} - {s.get('severity', '')}")
        
        if scans.get('hydra'):
            weak_creds = [h for h in scans['hydra'] if h.get('type') == 'credential']
            if weak_creds:
                with st.expander(f"🔑 Mots de passe faibles ({len(weak_creds)} trouvés)"):
                    for h in weak_creds:
                        st.error(f"**{h.get('service', '').upper()}** - {h.get('username', '')}:{h.get('password', '')}")
    
    with tab4:
        st.subheader("📤 Exporter les Résultats")
        
        export_format = st.selectbox(
            "Format d'export",
            ["CSV", "Excel", "JSON"]
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📥 Générer et télécharger", type="primary", use_container_width=True):
                with st.spinner("Génération de l'export..."):
                    filename = None
                    if export_format == "CSV":
                        filename = export_to_csv(results)
                    elif export_format == "Excel":
                        filename = export_to_excel(results)
                    elif export_format == "JSON":
                        filename = export_to_json(results)
                    
                    if filename and os.path.exists(filename):
                        st.success("✅ Export généré avec succès!")
                        with open(filename, 'rb') as f:
                            st.download_button(
                                label=f"📥 Télécharger {export_format}",
                                data=f,
                                file_name=os.path.basename(filename),
                                mime="application/octet-stream"
                            )
        
        with col2:
            if results.get('pdfInfo') and results['pdfInfo'].get('pdfPath'):
                pdf_path = results['pdfInfo']['pdfPath']
                if os.path.exists(pdf_path):
                    with open(pdf_path, 'rb') as f:
                        st.download_button(
                            label="📄 Télécharger le rapport PDF",
                            data=f,
                            file_name=results['pdfInfo'].get('filename', 'rapport.pdf'),
                            mime="application/pdf",
                            use_container_width=True
                        )
        
        st.divider()
        
        # Visualisation rapide des données
        st.subheader("📊 Aperçu des données")
        if results.get('aiAnalysis'):
            stats = results['aiAnalysis'].get('stats', {})
            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                st.metric("Critiques", stats.get('critical', 0))
            with col2:
                st.metric("Élevés", stats.get('high', 0))
            with col3:
                st.metric("Moyens", stats.get('medium', 0))
            with col4:
                st.metric("Faibles", stats.get('low', 0))
            with col5:
                st.metric("Infos", stats.get('info', 0))
    with tab5:
        display_historical_trends()
# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #888; padding: 20px;'>"
    "🔒 AgentSec v2.0 | Powered by n8n + Groq AI | Scanner de Vulnérabilités"
    "</div>",
    unsafe_allow_html=True
)
    
