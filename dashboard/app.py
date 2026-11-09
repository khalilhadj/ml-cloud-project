"""Tableau de bord analyste. Lancer : streamlit run dashboard/app.py"""
import numpy as np
import pandas as pd
import streamlit as st

import logic

st.set_page_config(page_title="Détection d'anomalies", page_icon="🛡️", layout="wide")

import hmac
import os

_pwd = os.environ.get("DASHBOARD_PASSWORD", "")
if _pwd:
    if not st.session_state.get("auth"):
        st.title("🛡️ Accès réservé")
        entered = st.text_input("Mot de passe", type="password")
        if entered:
            if hmac.compare_digest(entered.encode(), _pwd.encode()):
                st.session_state["auth"] = True
                st.rerun()
            else:
                st.error("Mot de passe incorrect.")
        st.stop()

# ------------------------------------------------------------------ barre latérale
st.sidebar.header("Analyste")
analyst = st.sidebar.text_input("Nom", value="", placeholder="ex. khalil")
st.sidebar.caption("Enregistré avec chaque décision (FR-18).")
if st.sidebar.button("Actualiser"):
    st.rerun()

try:
    info = logic.model_info()
except Exception as e:  # modèle absent : message clair au lieu d'une page cassée
    st.error(f"Aucun modèle actif : {e}. Lance python app-ml/train.py puis evaluate.py.")
    st.stop()

st.sidebar.divider()
st.sidebar.metric("Modèle actif", info["active"])
st.sidebar.metric("Seuil d'alerte", f"{info['threshold']:.4f}" if info["threshold"] else "-")
st.sidebar.caption("Sévérité : "
                   + " / ".join(f"{k} ≥ {v:.3f}" for k, v in info["severity"].items() if v is not None))

st.title("🛡️ Détection d'anomalies par Machine Learning")
status = logic.status_counts()
total = sum(status.values())

tabs = st.tabs(["Vue d'ensemble", "Alertes", "Feedback et réentraînement",
                "Modèle et cloud", "Démo et administration"])

# ------------------------------------------------------------------ 1. vue d'ensemble
with tabs[0]:
    m = logic.metrics()
    c = st.columns(5)
    c[0].metric("Alertes", total)
    c[1].metric("En attente", status["en_attente"])
    c[2].metric("Vrais positifs", status["vrai_positif"])
    c[3].metric("Faux positifs", status["faux_positif"])
    rate = m["taux_faux_positifs"]
    c[4].metric("Taux de faux positifs", "-" if rate is None else f"{rate:.1%}")

    if total == 0:
        st.info("Aucune alerte. Va dans « Démo et administration » pour en générer.")
    else:
        left, right = st.columns(2)
        with left:
            st.subheader("Alertes par sévérité")
            st.bar_chart(pd.Series(logic.severity_counts()))
        with right:
            st.subheader("Alertes par statut")
            st.bar_chart(pd.Series(status))
        hist = pd.DataFrame(logic.score_history())
        left, right = st.columns(2)
        with left:
            st.subheader("Distribution des scores")
            counts, edges = np.histogram(hist["score"], bins=15)
            st.bar_chart(pd.Series(counts, index=[f"{e:.2f}" for e in edges[:-1]]))
        with right:
            st.subheader("Score des alertes dans le temps")
            st.line_chart(hist.set_index("id")["score"])
        prec = m["precision_mesuree"]
        st.caption("Précision mesurée par le feedback : " + ("-" if prec is None else f"{prec:.1%}"))

# ------------------------------------------------------------------ 2. alertes
with tabs[1]:
    f1, f2, f3 = st.columns(3)
    sev = f1.selectbox("Sévérité", ["toutes", *logic.SEVERITIES])
    sta = f2.selectbox("Statut", ["en_attente", "toutes", "vrai_positif", "faux_positif"])
    lim = f3.number_input("Maximum affiché", 10, 1000, 200, step=10)
    rows = logic.all_alerts(status=None if sta == "toutes" else sta,
                            severity=None if sev == "toutes" else sev, limit=int(lim))
    st.write(f"{len(rows)} alerte(s), les plus anormales d'abord.")

    if rows:
        df = pd.DataFrame(rows)
        df.insert(0, "choisir", False)
        edited = st.data_editor(df, hide_index=True, width="stretch", key="table",
                                disabled=[c for c in df.columns if c != "choisir"])
        chosen = [int(i) for i in edited.loc[edited["choisir"], "id"]]

        st.subheader(f"Qualification en masse ({len(chosen)} sélectionnée(s))")
        comment = st.text_input("Commentaire (facultatif)", key="bulk_comment")
        b1, b2, _ = st.columns([1, 1, 4])
        for col, label, verdict in ((b1, "Vrai positif", "vrai_positif"), (b2, "Faux positif", "faux_positif")):
            if col.button(f"{label} ({len(chosen)})", key=f"bulk_{verdict}"):
                if not analyst.strip():
                    st.error("Renseigne ton nom dans la barre latérale.")
                elif not chosen:
                    st.warning("Coche au moins une alerte.")
                else:
                    n = logic.bulk_qualify(chosen, verdict, analyst, comment)
                    st.success(f"{n} alerte(s) qualifiée(s) : {label.lower()}")
                    st.rerun()

        st.subheader("Fiche détaillée")
        aid = st.selectbox("Alerte n°", [r["id"] for r in rows])
        d = logic.alert_detail(aid)
        if d:
            k = st.columns(4)
            k[0].metric("Score", f"{d['score']:.3f}")
            k[1].metric("Sévérité", d["severity"])
            k[2].metric("Statut", d["status"])
            k[3].metric("Modèle", d["model_version"])
            st.write("**Variables les plus déviantes** (écarts-types par rapport au trafic normal appris) :")
            st.bar_chart(pd.Series({n: v for n, v in d["top_features"]}))
            if d["feedback"]:
                fb = d["feedback"]
                st.info(f"Décision : {fb['verdict']} par {fb['analyst']} le {fb['created_at']}"
                        + (f" — « {fb['comment']} »" if fb["comment"] else ""))

# ------------------------------------------------------------------ 3. feedback et réentraînement
with tabs[2]:
    ready, needed = logic.feedback_count_ready()
    st.subheader("Boucle de feedback")
    st.progress(min(ready / needed, 1.0), text=f"Faux positifs prêts pour le réentraînement : {ready} / {needed}")
    st.caption("Règle (FR-20) : le nouveau modèle remplace l'ancien seulement si son F1 est au moins égal "
               "et son taux de faux positifs strictement inférieur.")

    st.subheader("Journal des décisions")
    fb_rows = logic.feedback_table()
    if fb_rows:
        st.dataframe(pd.DataFrame(fb_rows), hide_index=True, width="stretch")
    else:
        st.write("Aucune décision enregistrée.")

    st.subheader("Historique des cycles de réentraînement")
    h = logic.retrain_history()
    if h:
        st.dataframe(pd.DataFrame(h), hide_index=True, width="stretch")
    else:
        st.write("Aucun cycle exécuté.")

    st.subheader("Lancer un cycle maintenant")
    st.warning("Si le nouveau modèle est promu, le modèle actif, le seuil de config.yaml et S3 sont mis à jour.")
    ok = st.checkbox("Je confirme le lancement")
    if st.button("Lancer le réentraînement", disabled=not ok):
        with st.spinner("Réentraînement en cours..."):
            res = logic.run_retrain_now()
        if res["status"] == "skipped":
            st.info(res["reason"])
        else:
            st.success(f"Résultat : {res['status']} (actif : {res['active']})")
            st.json({k: res[k] for k in ("old", "new") if k in res})

# ------------------------------------------------------------------ 4. modèle et cloud
with tabs[3]:
    left, right = st.columns(2)
    with left:
        st.subheader("Modèle")
        st.write(f"Version active : **{info['active']}** (créée le {info['created_at']})")
        st.write(f"Entraîné sur {info['train_samples']} événements normaux, {info['n_features']} variables.")
        st.write("Versions disponibles : " + ", ".join(info["versions"]))
        mt = info["metrics"]
        if mt:
            rows_m = []
            for part in ("validation", "test"):
                if part in mt:
                    rows_m.append({"jeu": part, **{k: mt[part].get(k) for k in
                                                   ("f1", "precision", "recall", "false_positive_rate", "auc")}})
            st.dataframe(pd.DataFrame(rows_m), hide_index=True, width="stretch")
            t = mt.get("test", {})
            if t.get("f1") is not None:
                st.caption(f"ACC-3 (F1 test ≥ 0,80) : {'atteint' if t['f1'] >= 0.8 else 'non atteint'} "
                           f"(F1 = {t['f1']:.3f}).")
    with right:
        st.subheader("Cloud AWS")
        for k, v in logic.cloud_status().items():
            st.write(f"**{k}** : {v}")
        st.caption("Les modèles sont envoyés sur S3 chiffré après chaque entraînement.")

# ------------------------------------------------------------------ 5. démo et administration
with tabs[4]:
    st.subheader("Mode démo (FR-23)")
    st.write("Injecte des événements du jeu de validation, scorés par le modèle actif.")
    n = st.slider("Nombre d'événements", 10, 200, 30)
    ratio = st.slider("Part d'attaques", 0.0, 1.0, 0.7)
    if st.button("Lancer la démo"):
        r = logic.demo_inject(n=n, attack_ratio=ratio)
        st.success(f"{r['alerts']} alertes créées sur {r['events']} événements "
                   f"(modèle {r['model']}, dont {r['true_attacks_among_alerts']} vraies attaques).")
        st.rerun()

    st.subheader("Export")
    all_rows = logic.all_alerts(limit=1000)
    st.download_button("Télécharger les alertes (CSV)", logic.to_csv(all_rows), "alertes.csv",
                       "text/csv", disabled=not all_rows)

    st.subheader("Remise à zéro")
    sure = st.checkbox("Je confirme la suppression de toutes les alertes et décisions")
    if st.button("Vider la base", disabled=not sure):
        st.success(f"{logic.reset_db()} alerte(s) supprimée(s).")
        st.rerun()
