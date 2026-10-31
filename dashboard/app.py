"""Tableau de bord analyste. Lancer : streamlit run dashboard/app.py"""
import pandas as pd
import streamlit as st

import logic

st.set_page_config(page_title="Détection d'anomalies", layout="wide")
st.title("Détection d'anomalies par Machine Learning")

analyst = st.sidebar.text_input("Analyste", value="")
st.sidebar.caption("Identité enregistrée avec chaque décision (FR-18).")

tab_alerts, tab_metrics, tab_demo = st.tabs(["Alertes en attente", "Métriques", "Mode démo"])

with tab_alerts:
    sev = st.selectbox("Sévérité", ["toutes", "élevée", "moyenne", "faible"])
    rows = logic.pending_rows(limit=200, severity=None if sev == "toutes" else sev)
    st.write(f"{len(rows)} alerte(s) en attente (les plus anormales d'abord)")
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        st.subheader("Qualifier une alerte")
        c1, c2 = st.columns([1, 3])
        alert_id = c1.selectbox("Alerte n°", [r["id"] for r in rows])
        comment = c2.text_input("Commentaire")
        b1, b2, _ = st.columns([1, 1, 4])
        for col, label, verdict in ((b1, "Vrai positif", "vrai_positif"), (b2, "Faux positif", "faux_positif")):
            if col.button(label):
                if not analyst.strip():
                    st.error("Renseigne ton nom d'analyste dans la barre latérale.")
                else:
                    logic.qualify(alert_id, verdict, analyst, comment)
                    st.success(f"Alerte {alert_id} : {label.lower()}")
                    st.rerun()

with tab_metrics:
    m = logic.metrics()
    c = st.columns(4)
    c[0].metric("Alertes", m["total"])
    c[1].metric("En attente", m["en_attente"])
    c[2].metric("Faux positifs", m["faux_positif"])
    rate = m["taux_faux_positifs"]
    c[3].metric("Taux de faux positifs", "-" if rate is None else f"{rate:.1%}")
    prec = m["precision_mesuree"]
    st.write("Précision mesurée par le feedback :", "-" if prec is None else f"{prec:.1%}")
    ready, needed = logic.feedback_count_ready()
    st.write(f"Faux positifs prêts pour le réentraînement : {ready} / {needed} minimum")
    hist = logic.score_history()
    if hist:
        df = pd.DataFrame(hist)
        st.subheader("Score des alertes dans le temps")
        st.line_chart(df.set_index("id")["score"])

with tab_demo:
    st.write("Injecte des événements du jeu de validation, scorés par le modèle actif.")
    n = st.slider("Nombre d'événements", 10, 200, 30)
    ratio = st.slider("Part d'attaques", 0.0, 1.0, 0.7)
    if st.button("Lancer la démo"):
        r = logic.demo_inject(n=n, attack_ratio=ratio)
        st.success(f"{r['alerts']} alertes créées sur {r['events']} événements "
                   f"(modèle {r['model']}, dont {r['true_attacks_among_alerts']} vraies attaques).")
        st.rerun()
