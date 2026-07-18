from __future__ import annotations

from datetime import date, datetime, timedelta
from io import BytesIO
from pathlib import Path
import hashlib
import json
import re
import uuid

import pandas as pd
import plotly.express as px
import streamlit as st
from pypdf import PdfReader

from cei_core.db import (
    KB_DIR,
    UPLOAD_DIR,
    execute,
    get_setting,
    init_db,
    log_action,
    one,
    query,
    set_setting,
)
from cei_core.domain import (
    ANSWER_OPTIONS,
    PROTOCOL_STATUSES,
    RECOMMENDATIONS,
    REVIEW_CHECKLIST,
    RISK_LEVELS,
    STUDY_TYPES,
    analyze_consent_text,
    business_days_between,
    generate_observations,
    iso_now,
    quorum_evaluation,
    summarize_review,
)
from cei_core.kb import extract_pdf_text, load_sources, search_sources
from cei_core.reports import build_review_pdf
from cei_core.security import verify_password


BASE_DIR = Path(__file__).resolve().parent
CSS_PATH = BASE_DIR / "assets" / "styles.css"
LOCAL_GUIDE = KB_DIR / "Guia_etica_revision_ensayos_clinicos.pdf"

st.set_page_config(
    page_title="CEI Nexus",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()


@st.cache_data(show_spinner=False)
def load_css() -> str:
    return CSS_PATH.read_text(encoding="utf-8") if CSS_PATH.exists() else ""


@st.cache_data(show_spinner=False)
def local_guide_text() -> str:
    if not LOCAL_GUIDE.exists():
        return ""
    try:
        return extract_pdf_text(LOCAL_GUIDE)
    except Exception:
        return ""


st.markdown(f"<style>{load_css()}</style>", unsafe_allow_html=True)


def clean_filename(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name or "documento")
    return safe[:140]


def df_to_csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8-sig")


def page_header(title: str, subtitle: str, badge: str = "CEI Nexus") -> None:
    st.markdown(
        f"""
        <div class="cei-header">
          <span class="cei-badge">{badge}</span>
          <h1>{title}</h1>
          <p>{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def kpi_card(label: str, value: str, note: str = "") -> None:
    st.markdown(
        f"""
        <div class="cei-card">
          <div class="cei-kpi-label">{label}</div>
          <div class="cei-kpi-value">{value}</div>
          <div class="cei-kpi-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def authenticate(username: str, password: str) -> dict | None:
    user = one("SELECT * FROM users WHERE username=? AND active=1", (username.strip(),))
    if user and verify_password(password, user["password_hash"]):
        execute("UPDATE users SET last_login=? WHERE id=?", (iso_now(), user["id"]))
        log_action(user["id"], "Inicio de sesión", "user", user["id"])
        return user
    return None


def login_screen() -> None:
    st.markdown(
        """
        <div class="cei-login-shell">
          <div class="cei-header" style="margin-bottom:18px;">
            <span class="cei-badge">Plataforma institucional</span>
            <h1>CEI Nexus</h1>
            <p>Gestión ética, científica y operacional de investigaciones en salud.</p>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    left, center, right = st.columns([1, 1.25, 1])
    with center:
        with st.form("login_form"):
            username = st.text_input("Usuario")
            password = st.text_input("Contraseña", type="password")
            submitted = st.form_submit_button("Ingresar", type="primary", use_container_width=True)
        if submitted:
            user = authenticate(username, password)
            if user:
                st.session_state["user"] = user
                st.rerun()
            st.error("Credenciales incorrectas o usuario inactivo.")

        with st.expander("Accesos de demostración"):
            st.caption("Cambiar estas credenciales antes de usar la plataforma con información real.")
            st.code(
                "admin / admin2026\n"
                "secretaria / secretaria2026\n"
                "presidente / presidente2026\n"
                "revisor / revisor2026\n"
                "monitor / monitor2026\n"
                "investigador / investigador2026"
            )


if "user" not in st.session_state:
    login_screen()
    st.stop()

user = st.session_state["user"]

ROLE_PAGES = {
    "Administrador": ["Dashboard", "Protocolos", "Evaluaciones", "Sesiones", "Seguridad", "Enmiendas", "Supervisión", "Miembros", "Base de conocimiento", "Administración"],
    "Secretaría": ["Dashboard", "Protocolos", "Sesiones", "Seguridad", "Enmiendas", "Supervisión", "Miembros", "Base de conocimiento"],
    "Presidencia": ["Dashboard", "Protocolos", "Evaluaciones", "Sesiones", "Seguridad", "Enmiendas", "Supervisión", "Miembros", "Base de conocimiento"],
    "Revisor": ["Dashboard", "Protocolos", "Evaluaciones", "Sesiones", "Base de conocimiento"],
    "Monitor": ["Dashboard", "Protocolos", "Seguridad", "Supervisión", "Base de conocimiento"],
    "Investigador": ["Dashboard", "Protocolos", "Seguridad", "Enmiendas", "Base de conocimiento"],
}

with st.sidebar:
    st.markdown("## ⚖️ CEI Nexus")
    st.caption(get_setting("committee_name", "Comité de Ética en Investigación"))
    st.markdown("---")
    st.markdown(f"**{user['full_name']}**")
    st.caption(f"{user['role']} · {user.get('discipline') or 'Sin disciplina'}")
    pages = ROLE_PAGES.get(user["role"], ["Dashboard"])
    current_page = st.radio("Navegación", pages, label_visibility="collapsed")
    st.markdown("---")
    st.caption("MVP clínico-regulatorio. La decisión final siempre corresponde al comité.")
    if st.button("Cerrar sesión", use_container_width=True):
        log_action(user["id"], "Cierre de sesión", "user", user["id"])
        st.session_state.clear()
        st.rerun()


def protocol_label(p: dict) -> str:
    return f"{p['code']} · {p['title'][:85]}"


def protocol_options() -> tuple[list[dict], dict[str, dict]]:
    rows = query("SELECT * FROM protocols ORDER BY created_at DESC")
    mapping = {protocol_label(p): p for p in rows}
    return rows, mapping


def render_dashboard() -> None:
    page_header(
        "Centro de control del Comité",
        "Visión ejecutiva de oportunidad, calidad, seguridad y carga de trabajo.",
        "Métricas en tiempo real",
    )
    protocols = query("SELECT * FROM protocols ORDER BY created_at DESC")
    reviews = query("SELECT * FROM reviews")
    safety = query("SELECT * FROM safety_events")
    deviations = query("SELECT * FROM deviations")
    training = query(
        """SELECT t.*, u.full_name FROM training t
           JOIN users u ON u.id=t.user_id ORDER BY expires_at"""
    )

    active = [p for p in protocols if p["status"] not in {"Aprobado", "Rechazado", "Cerrado"}]
    observed = [p for p in protocols if p["status"] == "Observado"]

    tpo = []
    tdf = []
    for p in protocols:
        if p.get("submitted_at") and p.get("first_observation_at"):
            tpo.append((date.fromisoformat(p["first_observation_at"]) - date.fromisoformat(p["submitted_at"])).days)
        if p.get("submitted_at") and p.get("final_decision_at"):
            tdf.append((date.fromisoformat(p["final_decision_at"]) - date.fromisoformat(p["submitted_at"])).days)

    target_sae = int(get_setting("sae_target_business_days", "2"))
    late_safety = []
    for e in safety:
        delay = business_days_between(date.fromisoformat(e["awareness_date"]), date.fromisoformat(e["reported_at"]))
        if delay > target_sae:
            late_safety.append(e)

    alert_days = int(get_setting("training_alert_days", "60"))
    expiring = []
    for t in training:
        if t.get("expires_at"):
            days = (date.fromisoformat(t["expires_at"]) - date.today()).days
            if days <= alert_days:
                expiring.append((t, days))

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        kpi_card("Protocolos activos", str(len(active)), f"{len(protocols)} expedientes totales")
    with c2:
        kpi_card("Tiempo 1.ª observación", f"{sum(tpo)/len(tpo):.1f} d" if tpo else "—", f"Meta interna: ≤ {get_setting('first_observation_target_days','9')} días")
    with c3:
        kpi_card("Tiempo al dictamen", f"{sum(tdf)/len(tdf):.1f} d" if tdf else "—", f"Meta interna: ≤ {get_setting('protocol_target_days','60')} días")
    with c4:
        rate = (len(observed) / len(protocols) * 100) if protocols else 0
        kpi_card("Protocolos observados", f"{rate:.0f}%", f"{len(observed)} con respuesta pendiente")

    st.markdown("### Alertas prioritarias")
    a1, a2, a3 = st.columns(3)
    with a1:
        st.metric("EAS fuera de meta", len(late_safety), delta=f"Meta {target_sae} días hábiles", delta_color="inverse")
        if late_safety:
            st.caption("Revisar demoras de notificación y documentar causa raíz.")
    with a2:
        overdue_devs = [
            d for d in deviations
            if d.get("due_date") and d["status"] != "Cerrado" and date.fromisoformat(d["due_date"]) < date.today()
        ]
        st.metric("CAPA/desvíos vencidos", len(overdue_devs), delta="Requieren seguimiento", delta_color="inverse")
    with a3:
        st.metric("Capacitaciones por vencer", len(expiring), delta=f"Próximos {alert_days} días", delta_color="inverse")

    left, right = st.columns([1.35, 1])
    with left:
        status_df = pd.DataFrame(protocols)
        if not status_df.empty:
            status_count = status_df.groupby("status", as_index=False).size().sort_values("size", ascending=False)
            fig = px.bar(
                status_count,
                x="status",
                y="size",
                labels={"status": "Estado", "size": "Protocolos"},
                title="Distribución del portafolio por estado",
            )
            fig.update_layout(height=365, margin=dict(l=15, r=15, t=55, b=90), showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Todavía no hay protocolos.")
    with right:
        workload = query(
            """SELECT u.full_name AS revisor, COUNT(p.id) AS protocolos
               FROM users u LEFT JOIN protocols p ON p.assigned_reviewer_id=u.id
               WHERE u.role IN ('Revisor','Presidencia')
               GROUP BY u.id, u.full_name ORDER BY protocolos DESC"""
        )
        if workload:
            fig = px.pie(
                pd.DataFrame(workload),
                names="revisor",
                values="protocolos",
                hole=0.58,
                title="Carga asignada por evaluador",
            )
            fig.update_layout(height=365, margin=dict(l=10, r=10, t=55, b=20))
            st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Expedientes que requieren atención")
    attention = [
        p for p in protocols
        if p["status"] in {"Observado", "En revisión", "Respuesta recibida", "Suspendido"}
    ]
    if attention:
        df = pd.DataFrame(attention)[["code", "title", "principal_investigator", "risk_level", "status", "submitted_at"]]
        df.columns = ["Código", "Título", "Investigador", "Riesgo", "Estado", "Ingreso"]
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.success("No hay expedientes prioritarios pendientes.")


def render_protocols() -> None:
    page_header(
        "Expedientes y documentos",
        "Registro, asignación, versionado y trazabilidad documental del protocolo.",
        "Workflow integral",
    )
    protocols, mapping = protocol_options()
    tabs = st.tabs(["Cartera", "Nuevo protocolo", "Actualizar expediente", "Documentos"])

    with tabs[0]:
        status_filter = st.multiselect("Filtrar por estado", PROTOCOL_STATUSES, default=[])
        risk_filter = st.multiselect("Filtrar por riesgo", RISK_LEVELS, default=[])
        rows = protocols
        if status_filter:
            rows = [r for r in rows if r["status"] in status_filter]
        if risk_filter:
            rows = [r for r in rows if r["risk_level"] in risk_filter]
        if rows:
            df = pd.DataFrame(rows)
            display_cols = [
                "code", "title", "principal_investigator", "institution", "study_type",
                "risk_level", "status", "submitted_at", "current_version"
            ]
            df = df[display_cols]
            df.columns = ["Código", "Título", "IP", "Institución", "Tipo", "Riesgo", "Estado", "Ingreso", "Versión"]
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.download_button(
                "Exportar cartera CSV",
                df_to_csv_bytes(df),
                "protocolos_cei.csv",
                "text/csv",
            )
        else:
            st.info("No hay protocolos con esos filtros.")

    with tabs[1]:
        if user["role"] not in {"Administrador", "Secretaría", "Investigador", "Presidencia"}:
            st.warning("Su rol dispone de acceso de consulta.")
        else:
            reviewers = query("SELECT id, full_name FROM users WHERE active=1 AND role IN ('Revisor','Presidencia') ORDER BY full_name")
            reviewer_map = {"Sin asignar": None, **{r["full_name"]: r["id"] for r in reviewers}}
            with st.form("new_protocol"):
                c1, c2 = st.columns(2)
                code = c1.text_input("Código interno*", value=f"CEI-{date.today().year}-")
                title = c2.text_input("Título completo*")
                c3, c4 = st.columns(2)
                pi = c3.text_input("Investigador principal*")
                sponsor = c4.text_input("Patrocinador / fuente de financiamiento")
                c5, c6 = st.columns(2)
                institution = c5.text_input("Institución / centro")
                study_type = c6.selectbox("Tipo de investigación*", STUDY_TYPES)
                c7, c8, c9 = st.columns(3)
                phase = c7.text_input("Fase", value="N/A")
                risk = c8.selectbox("Nivel de riesgo*", RISK_LEVELS, index=2)
                version = c9.text_input("Versión", value="1.0")
                vulnerable = st.text_input("Población vulnerable o salvaguardas especiales")
                assigned_name = st.selectbox("Evaluador asignado", list(reviewer_map))
                notes = st.text_area("Notas de recepción / pre-evaluación")
                create = st.form_submit_button("Crear expediente", type="primary")
            if create:
                if not code.strip() or not title.strip() or not pi.strip():
                    st.error("Complete código, título e investigador principal.")
                elif one("SELECT id FROM protocols WHERE code=?", (code.strip(),)):
                    st.error("El código ya existe.")
                else:
                    now = iso_now()
                    pid = execute(
                        """INSERT INTO protocols
                        (code, title, principal_investigator, sponsor, institution, phase, study_type,
                         risk_level, vulnerable_population, status, submitted_at, current_version,
                         assigned_reviewer_id, created_by, notes, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Recibido', ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            code.strip(), title.strip(), pi.strip(), sponsor.strip(), institution.strip(),
                            phase.strip(), study_type, risk, vulnerable.strip(), date.today().isoformat(),
                            version.strip() or "1.0", reviewer_map[assigned_name], user["id"], notes.strip(),
                            now, now,
                        ),
                    )
                    log_action(user["id"], "Creó protocolo", "protocol", pid, {"code": code.strip()})
                    st.success("Expediente creado.")
                    st.rerun()

    with tabs[2]:
        if not mapping:
            st.info("No hay protocolos.")
        else:
            selected_label = st.selectbox("Seleccionar expediente", list(mapping), key="protocol_update_sel")
            p = mapping[selected_label]
            reviewers = query("SELECT id, full_name FROM users WHERE active=1 AND role IN ('Revisor','Presidencia') ORDER BY full_name")
            reviewer_names = ["Sin asignar"] + [r["full_name"] for r in reviewers]
            current_reviewer = one("SELECT full_name FROM users WHERE id=?", (p.get("assigned_reviewer_id"),)) if p.get("assigned_reviewer_id") else None
            current_name = current_reviewer["full_name"] if current_reviewer else "Sin asignar"
            with st.form("update_protocol"):
                c1, c2, c3 = st.columns(3)
                status = c1.selectbox("Estado", PROTOCOL_STATUSES, index=PROTOCOL_STATUSES.index(p["status"]))
                risk = c2.selectbox("Riesgo", RISK_LEVELS, index=RISK_LEVELS.index(p["risk_level"]))
                version = c3.text_input("Versión vigente", value=p.get("current_version") or "1.0")
                assigned_name = st.selectbox(
                    "Evaluador asignado",
                    reviewer_names,
                    index=reviewer_names.index(current_name) if current_name in reviewer_names else 0,
                )
                notes = st.text_area("Notas", value=p.get("notes") or "", height=140)
                update = st.form_submit_button("Guardar cambios", type="primary")
            if update:
                assigned_id = next((r["id"] for r in reviewers if r["full_name"] == assigned_name), None)
                final_date = p.get("final_decision_at")
                if status in {"Aprobado", "Aprobado con condiciones", "Rechazado", "Cerrado"} and not final_date:
                    final_date = date.today().isoformat()
                execute(
                    """UPDATE protocols SET status=?, risk_level=?, current_version=?, assigned_reviewer_id=?,
                       notes=?, final_decision_at=?, updated_at=? WHERE id=?""",
                    (status, risk, version.strip(), assigned_id, notes.strip(), final_date, iso_now(), p["id"]),
                )
                log_action(user["id"], "Actualizó protocolo", "protocol", p["id"], {"status": status, "version": version})
                st.success("Expediente actualizado.")
                st.rerun()

    with tabs[3]:
        if not mapping:
            st.info("No hay protocolos.")
        else:
            selected_label = st.selectbox("Expediente", list(mapping), key="doc_protocol")
            p = mapping[selected_label]
            c1, c2, c3 = st.columns([1.1, 1, 1])
            category = c1.selectbox(
                "Categoría",
                [
                    "Protocolo", "Consentimiento informado", "Manual del investigador",
                    "CV / capacitación", "Seguro", "Contrato / presupuesto",
                    "Material de reclutamiento", "Enmienda", "Informe de seguridad",
                    "Respuesta a observaciones", "Otro",
                ],
            )
            version = c2.text_input("Versión", value=p.get("current_version") or "1.0")
            uploaded = c3.file_uploader("Archivo", type=["pdf", "docx", "xlsx", "csv", "txt"], key="protocol_doc")
            if st.button("Incorporar documento", type="primary", disabled=uploaded is None):
                content = uploaded.getvalue()
                digest = hashlib.sha256(content).hexdigest()
                safe = clean_filename(uploaded.name)
                stored_name = f"{p['code']}_{uuid.uuid4().hex[:10]}_{safe}"
                path = UPLOAD_DIR / stored_name
                path.write_bytes(content)
                did = execute(
                    """INSERT INTO documents
                    (protocol_id, category, version, filename, stored_path, sha256, uploaded_at, uploaded_by, is_current)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (p["id"], category, version.strip(), uploaded.name, str(path), digest, iso_now(), user["id"]),
                )
                log_action(user["id"], "Incorporó documento", "document", did, {"protocol": p["code"], "sha256": digest})
                st.success("Documento incorporado con huella de integridad.")

            docs = query(
                """SELECT d.id, d.category, d.version, d.filename, d.sha256, d.uploaded_at,
                          u.full_name AS uploaded_by
                   FROM documents d LEFT JOIN users u ON u.id=d.uploaded_by
                   WHERE d.protocol_id=? ORDER BY d.uploaded_at DESC""",
                (p["id"],),
            )
            if docs:
                ddf = pd.DataFrame(docs)
                ddf.columns = ["ID", "Categoría", "Versión", "Archivo", "SHA-256", "Carga", "Usuario"]
                st.dataframe(ddf, use_container_width=True, hide_index=True)
            else:
                st.caption("Aún no hay documentos vinculados.")


def render_reviews() -> None:
    page_header(
        "Evaluación ética y científica",
        "Checklist trazable, priorización de hallazgos y generación de observaciones.",
        "Asistencia al evaluador",
    )
    protocols, mapping = protocol_options()
    if not mapping:
        st.info("No hay protocolos para evaluar.")
        return

    selected_label = st.selectbox("Expediente", list(mapping))
    p = mapping[selected_label]
    st.markdown(
        f"<div class='cei-info'><b>{p['code']}</b> · {p['title']}<br>"
        f"Riesgo: <b>{p['risk_level']}</b> · Estado: <b>{p['status']}</b> · Versión: <b>{p['current_version']}</b></div>",
        unsafe_allow_html=True,
    )
    tabs = st.tabs(["Nueva evaluación", "Analizador de consentimiento", "Historial e informe"])

    with tabs[0]:
        st.caption("El puntaje es orientativo. Cualquier hallazgo crítico requiere deliberación y justificación.")
        with st.form("review_form"):
            review_type = st.selectbox("Tipo de revisión", ["Inicial", "Expeditiva", "Continuada", "Enmienda", "Seguridad"])
            grouped: dict[str, list[dict]] = {}
            for item in REVIEW_CHECKLIST:
                grouped.setdefault(item["domain"], []).append(item)
            answers = []
            for domain, items in grouped.items():
                st.markdown(f"#### {domain}")
                for idx, item in enumerate(items):
                    c1, c2 = st.columns([1.15, 1])
                    answer = c1.selectbox(
                        item["text"],
                        ANSWER_OPTIONS,
                        index=0,
                        key=f"ans_{p['id']}_{item['key']}",
                    )
                    comment = c2.text_input(
                        f"Comentario · {item['severity']}",
                        key=f"com_{p['id']}_{item['key']}",
                        placeholder="Fundamento, documento o cambio requerido",
                    )
                    answers.append({**item, "answer": answer, "comment": comment})
            recommendation = st.selectbox("Recomendación del evaluador", RECOMMENDATIONS, index=2)
            general_comments = st.text_area("Síntesis y fundamento", height=160)
            save = st.form_submit_button("Guardar evaluación", type="primary")

        if save:
            summary = summarize_review(answers)
            rid = execute(
                """INSERT INTO reviews
                (protocol_id, reviewer_id, review_type, status, started_at, completed_at,
                 total_score, recommendation, general_comments, created_at)
                VALUES (?, ?, ?, 'Completada', ?, ?, ?, ?, ?, ?)""",
                (
                    p["id"], user["id"], review_type, iso_now(), iso_now(),
                    summary["total_score"], recommendation, general_comments.strip(), iso_now(),
                ),
            )
            for item in answers:
                execute(
                    """INSERT INTO review_items
                    (review_id, domain, item_key, item_text, answer, severity, comment)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        rid, item["domain"], item["key"], item["text"],
                        item["answer"], item["severity"], item["comment"].strip(),
                    ),
                )
            observations = generate_observations(answers)
            if observations and not p.get("first_observation_at"):
                execute(
                    "UPDATE protocols SET first_observation_at=?, status='Observado', updated_at=? WHERE id=?",
                    (date.today().isoformat(), iso_now(), p["id"]),
                )
            log_action(
                user["id"], "Completó evaluación", "review", rid,
                {"protocol": p["code"], "score": summary["total_score"], "recommendation": recommendation},
            )
            st.success(f"Evaluación guardada. Puntaje orientativo: {summary['total_score']}%.")
            if summary["critical_open"]:
                st.error(f"Hallazgos críticos abiertos: {len(summary['critical_open'])}")
            st.write("**Sugerencia del motor de reglas:**", summary["suggested_recommendation"])
            with st.expander("Observaciones generadas"):
                for obs in observations:
                    st.write("•", obs)

    with tabs[1]:
        st.markdown("#### Revisión orientativa de cobertura y legibilidad")
        ci_file = st.file_uploader("Consentimiento en PDF", type=["pdf"], key="ci_analyzer_pdf")
        ci_text = st.text_area(
            "O pegue el texto",
            height=220,
            placeholder="El texto no sale de la institución. La revisión automática no reemplaza la lectura del evaluador.",
        )
        extracted = ""
        if ci_file is not None:
            try:
                reader = PdfReader(BytesIO(ci_file.getvalue()))
                extracted = "\n".join(page.extract_text() or "" for page in reader.pages)
                st.caption(f"Texto extraído: {len(extracted):,} caracteres.")
            except Exception as exc:
                st.error(f"No fue posible extraer texto: {exc}")
        text = extracted or ci_text
        if st.button("Analizar consentimiento", type="primary", disabled=not bool(text.strip())):
            result = analyze_consent_text(text)
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Cobertura temática", f"{result['coverage']}%")
            m2.metric("Palabras", result["word_count"])
            m3.metric("Palabras por oración", result["avg_sentence_words"])
            m4.metric("Legibilidad orientativa", result["readability_flag"])
            cdf = pd.DataFrame(result["checks"])
            cdf["Estado"] = cdf["present"].map({True: "Detectado", False: "No detectado"})
            st.dataframe(cdf[["element", "Estado"]].rename(columns={"element": "Elemento"}), use_container_width=True, hide_index=True)
            if result["missing"]:
                st.warning("Elementos no detectados: " + "; ".join(result["missing"]))

    with tabs[2]:
        reviews = query(
            """SELECT r.*, u.full_name AS reviewer_name
               FROM reviews r JOIN users u ON u.id=r.reviewer_id
               WHERE r.protocol_id=? ORDER BY r.created_at DESC""",
            (p["id"],),
        )
        if not reviews:
            st.info("No hay evaluaciones registradas.")
        else:
            rdf = pd.DataFrame(reviews)[["id", "review_type", "reviewer_name", "completed_at", "total_score", "recommendation"]]
            rdf.columns = ["ID", "Tipo", "Revisor", "Fecha", "Puntaje", "Recomendación"]
            st.dataframe(rdf, use_container_width=True, hide_index=True)
            selected_review_id = st.selectbox("Informe a consultar", [r["id"] for r in reviews])
            review = next(r for r in reviews if r["id"] == selected_review_id)
            items = query("SELECT * FROM review_items WHERE review_id=? ORDER BY id", (selected_review_id,))
            open_df = pd.DataFrame([i for i in items if i["answer"] != "Cumple"])
            if not open_df.empty:
                st.dataframe(
                    open_df[["domain", "item_text", "answer", "severity", "comment"]].rename(
                        columns={
                            "domain": "Dominio", "item_text": "Ítem", "answer": "Evaluación",
                            "severity": "Severidad", "comment": "Comentario"
                        }
                    ),
                    use_container_width=True,
                    hide_index=True,
                )
            pdf = build_review_pdf(
                get_setting("committee_name"),
                p,
                review,
                items,
                review["reviewer_name"],
            )
            st.download_button(
                "Descargar informe PDF",
                pdf,
                file_name=f"{p['code']}_revision_{selected_review_id}.pdf",
                mime="application/pdf",
                type="primary",
            )


def render_meetings() -> None:
    page_header(
        "Sesiones, quórum y deliberación",
        "Control de representatividad, conflictos de interés, recusaciones y votos.",
        "Gobernanza del Comité",
    )
    members = query(
        """SELECT id, full_name, role, discipline, is_scientific, is_independent, is_community
           FROM users WHERE active=1 AND role IN ('Presidencia','Revisor') ORDER BY full_name"""
    )
    tabs = st.tabs(["Nueva sesión", "Historial"])

    with tabs[0]:
        if not members:
            st.warning("No hay miembros habilitados.")
            return
        with st.form("meeting_form"):
            c1, c2 = st.columns(2)
            title = c1.text_input("Título de la sesión", value=f"Reunión ordinaria {date.today().strftime('%d/%m/%Y')}")
            meeting_date = c2.date_input("Fecha", value=date.today())
            notes = st.text_area("Agenda / notas")
            st.markdown("#### Asistencia y conflictos")
            attendance_rows = []
            for m in members:
                c1, c2, c3, c4 = st.columns([2.2, .7, .8, .8])
                c1.markdown(
                    f"**{m['full_name']}**  \n"
                    f"<small>{m.get('discipline') or ''} · "
                    f"{'científico' if m['is_scientific'] else 'no científico'}"
                    f"{' · independiente' if m['is_independent'] else ''}"
                    f"{' · comunidad' if m['is_community'] else ''}</small>",
                    unsafe_allow_html=True,
                )
                present = c2.checkbox("Presente", key=f"pres_{m['id']}")
                conflict = c3.checkbox("CoI", key=f"coi_{m['id']}")
                recused = c4.checkbox("Recusado", key=f"rec_{m['id']}", disabled=not conflict)
                attendance_rows.append(
                    {
                        "member_id": m["id"],
                        "full_name": m["full_name"],
                        "present": present,
                        "conflict_declared": conflict,
                        "recused": recused,
                        "is_scientific": bool(m["is_scientific"]),
                        "is_independent": bool(m["is_independent"]),
                        "is_community": bool(m["is_community"]),
                    }
                )
            save = st.form_submit_button("Guardar sesión y verificar quórum", type="primary")
        if save:
            result = quorum_evaluation(
                total_members=len(members),
                present_rows=attendance_rows,
                min_absolute=int(get_setting("quorum_min_absolute", "5")),
                require_non_scientific=get_setting("require_non_scientific", "1") == "1",
                require_independent=get_setting("require_independent", "1") == "1",
                require_community=get_setting("require_community", "1") == "1",
            )
            mid = execute(
                """INSERT INTO meetings(title, meeting_date, status, notes, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    title.strip(), meeting_date.isoformat(),
                    "Quórum válido" if result["valid"] else "Quórum no válido",
                    notes.strip(), user["id"], iso_now(),
                ),
            )
            for row in attendance_rows:
                execute(
                    """INSERT INTO attendance
                    (meeting_id, member_id, present, conflict_declared, recused)
                    VALUES (?, ?, ?, ?, ?)""",
                    (mid, row["member_id"], int(row["present"]), int(row["conflict_declared"]), int(row["recused"])),
                )
            log_action(user["id"], "Registró sesión", "meeting", mid, result)
            if result["valid"]:
                st.success(f"Quórum válido: {result['present_count']} presentes; {result['eligible_to_vote']} habilitados para votar.")
            else:
                st.error(f"Quórum no válido. Presentes: {result['present_count']}; requeridos: {result['required_count']}.")
            for condition, ok in result["conditions"].items():
                st.write("✅" if ok else "❌", condition)

    with tabs[1]:
        meetings = query(
            """SELECT m.*, u.full_name AS created_by_name
               FROM meetings m LEFT JOIN users u ON u.id=m.created_by
               ORDER BY m.meeting_date DESC"""
        )
        if meetings:
            mdf = pd.DataFrame(meetings)[["id", "meeting_date", "title", "status", "created_by_name"]]
            mdf.columns = ["ID", "Fecha", "Sesión", "Estado", "Registró"]
            st.dataframe(mdf, use_container_width=True, hide_index=True)
            mid = st.selectbox("Ver asistencia de sesión", [m["id"] for m in meetings])
            attendance = query(
                """SELECT u.full_name, u.discipline, a.present, a.conflict_declared, a.recused, a.vote
                   FROM attendance a JOIN users u ON u.id=a.member_id
                   WHERE a.meeting_id=? ORDER BY u.full_name""",
                (mid,),
            )
            if attendance:
                adf = pd.DataFrame(attendance)
                adf.columns = ["Miembro", "Disciplina", "Presente", "Conflicto", "Recusado", "Voto"]
                st.dataframe(adf, use_container_width=True, hide_index=True)
        else:
            st.info("No hay sesiones registradas.")


def render_safety() -> None:
    page_header(
        "Seguridad de participantes",
        "Registro de eventos adversos serios, plazos de reporte, desvíos y acciones correctivas.",
        "Vigilancia continua",
    )
    protocols, mapping = protocol_options()
    if not mapping:
        st.info("No hay protocolos.")
        return
    tabs = st.tabs(["EAS / RAMSI", "Desvíos", "Tablero"])

    with tabs[0]:
        selected = st.selectbox("Protocolo", list(mapping), key="safety_protocol")
        p = mapping[selected]
        with st.form("new_safety_event"):
            c1, c2, c3 = st.columns(3)
            event_type = c1.selectbox("Tipo", ["EAS", "RAMSI / SUSAR", "Evento de especial interés", "Otro"])
            participant_code = c2.text_input("Código del participante*")
            event_date = c3.date_input("Fecha del evento", value=date.today())
            c4, c5, c6 = st.columns(3)
            awareness_date = c4.date_input("Fecha de conocimiento", value=date.today())
            reported_at = c5.date_input("Fecha de reporte al CEI", value=date.today())
            status = c6.selectbox("Estado", ["Notificado", "Bajo revisión", "Observado", "En seguimiento", "Cerrado"])
            c7, c8, c9 = st.columns(3)
            seriousness = c7.selectbox("Criterio de seriedad", ["Fallecimiento", "Riesgo de vida", "Hospitalización", "Discapacidad", "Anomalía congénita", "Evento médicamente importante"])
            expectedness = c8.selectbox("Esperabilidad", ["Esperado", "Inesperado", "No determinado"])
            relatedness = c9.selectbox("Relación", ["No relacionada", "Improbable", "Posible", "Probable", "Definida", "No determinada"])
            description = st.text_area("Descripción clínica y evolución*")
            followup_due = st.date_input("Próximo seguimiento", value=date.today() + timedelta(days=30))
            save = st.form_submit_button("Registrar evento", type="primary")
        if save:
            if not participant_code.strip() or not description.strip():
                st.error("Complete código y descripción.")
            else:
                eid = execute(
                    """INSERT INTO safety_events
                    (protocol_id, event_type, participant_code, event_date, awareness_date, reported_at,
                     seriousness, expectedness, relatedness, description, status, followup_due,
                     created_by, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        p["id"], event_type, participant_code.strip(), event_date.isoformat(),
                        awareness_date.isoformat(), reported_at.isoformat(), seriousness,
                        expectedness, relatedness, description.strip(), status,
                        followup_due.isoformat(), user["id"], iso_now(),
                    ),
                )
                delay = business_days_between(awareness_date, reported_at)
                log_action(user["id"], "Registró evento de seguridad", "safety_event", eid, {"delay_business_days": delay})
                target = int(get_setting("sae_target_business_days", "2"))
                if delay > target:
                    st.warning(f"Evento registrado. Demora estimada: {delay} días hábiles, por encima de la meta interna de {target}.")
                else:
                    st.success(f"Evento registrado. Demora estimada: {delay} días hábiles.")

    with tabs[1]:
        selected = st.selectbox("Protocolo", list(mapping), key="deviation_protocol")
        p = mapping[selected]
        with st.form("new_deviation"):
            c1, c2, c3 = st.columns(3)
            participant = c1.text_input("Código de participante")
            deviation_date = c2.date_input("Fecha del desvío", value=date.today())
            deviation_type = c3.selectbox(
                "Tipo",
                ["Consentimiento", "Elegibilidad", "Dosis/medicación", "Cadena de frío", "Procedimiento", "Visita/ventana", "Datos", "Otro"],
            )
            c4, c5, c6 = st.columns(3)
            severity = c4.selectbox("Clasificación", ["Menor", "Mayor", "Crítico / violación"])
            safety_impact = c5.checkbox("Impacto en seguridad")
            data_impact = c6.checkbox("Impacto en integridad de datos")
            description = st.text_area("Descripción objetiva*")
            corrective = st.text_area("Acción correctiva")
            preventive = st.text_area("Acción preventiva")
            c7, c8 = st.columns(2)
            due = c7.date_input("Vencimiento CAPA", value=date.today() + timedelta(days=30))
            status = c8.selectbox("Estado", ["Notificado", "Bajo revisión", "Observado", "CAPA en curso", "Cerrado"])
            save = st.form_submit_button("Registrar desvío", type="primary")
        if save:
            if not description.strip():
                st.error("Describa el desvío.")
            else:
                did = execute(
                    """INSERT INTO deviations
                    (protocol_id, participant_code, deviation_date, deviation_type, severity,
                     safety_impact, data_integrity_impact, description, corrective_action,
                     preventive_action, status, due_date, created_by, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        p["id"], participant.strip(), deviation_date.isoformat(), deviation_type,
                        severity, int(safety_impact), int(data_impact), description.strip(),
                        corrective.strip(), preventive.strip(), status, due.isoformat(),
                        user["id"], iso_now(),
                    ),
                )
                log_action(user["id"], "Registró desvío", "deviation", did, {"severity": severity})
                st.success("Desvío registrado.")

    with tabs[2]:
        events = query(
            """SELECT s.*, p.code FROM safety_events s JOIN protocols p ON p.id=s.protocol_id
               ORDER BY s.reported_at DESC"""
        )
        if events:
            rows = []
            target = int(get_setting("sae_target_business_days", "2"))
            for e in events:
                delay = business_days_between(date.fromisoformat(e["awareness_date"]), date.fromisoformat(e["reported_at"]))
                rows.append({
                    "Protocolo": e["code"], "Tipo": e["event_type"], "Participante": e["participant_code"],
                    "Evento": e["event_date"], "Reporte": e["reported_at"], "Demora hábil": delay,
                    "Dentro de meta": "Sí" if delay <= target else "No", "Estado": e["status"],
                })
            edf = pd.DataFrame(rows)
            st.dataframe(edf, use_container_width=True, hide_index=True)
            st.download_button("Exportar seguridad CSV", df_to_csv_bytes(edf), "seguridad_cei.csv", "text/csv")
        else:
            st.info("No hay eventos de seguridad.")


def render_amendments() -> None:
    page_header(
        "Enmiendas",
        "Clasificación por impacto, aprobación previa y trazabilidad de decisiones.",
        "Control de cambios",
    )
    protocols, mapping = protocol_options()
    if not mapping:
        st.info("No hay protocolos.")
        return
    selected = st.selectbox("Protocolo", list(mapping))
    p = mapping[selected]
    with st.form("new_amendment"):
        c1, c2, c3 = st.columns(3)
        code = c1.text_input("Código de enmienda", value=f"ENM-{date.today().year}-")
        submitted = c2.date_input("Fecha de presentación", value=date.today())
        classification = c3.selectbox("Clasificación propuesta", ["Sustancial", "No sustancial", "Urgente por seguridad", "A determinar"])
        c4, c5, c6 = st.columns(3)
        safety = c4.checkbox("Impacto en seguridad")
        scientific = c5.checkbox("Impacto científico")
        operational = c6.checkbox("Impacto operativo / centros / IP")
        summary = st.text_area("Resumen del cambio*")
        status = st.selectbox("Estado", ["Recibida", "En revisión", "Observada", "Aprobada", "Notificada", "Rechazada"])
        save = st.form_submit_button("Registrar enmienda", type="primary")
    if save:
        if not code.strip() or not summary.strip():
            st.error("Complete código y resumen.")
        else:
            aid = execute(
                """INSERT INTO amendments
                (protocol_id, amendment_code, submitted_at, classification, safety_impact,
                 scientific_impact, operational_impact, summary, status, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    p["id"], code.strip(), submitted.isoformat(), classification,
                    int(safety), int(scientific), int(operational), summary.strip(),
                    status, user["id"], iso_now(),
                ),
            )
            log_action(user["id"], "Registró enmienda", "amendment", aid, {"classification": classification})
            st.success("Enmienda registrada.")

    amendments = query(
        """SELECT a.*, p.code FROM amendments a JOIN protocols p ON p.id=a.protocol_id
           ORDER BY a.submitted_at DESC"""
    )
    if amendments:
        adf = pd.DataFrame(amendments)[
            ["code", "amendment_code", "submitted_at", "classification", "safety_impact", "scientific_impact", "operational_impact", "status", "summary"]
        ]
        adf.columns = ["Protocolo", "Enmienda", "Ingreso", "Clasificación", "Seguridad", "Científico", "Operativo", "Estado", "Resumen"]
        st.dataframe(adf, use_container_width=True, hide_index=True)


def render_supervision() -> None:
    page_header(
        "Supervisión, hallazgos y CAPA",
        "Registro objetivo, cuantificado y respaldado para seguimiento hasta el cierre.",
        "Garantía de calidad",
    )
    protocols, mapping = protocol_options()
    if not mapping:
        st.info("No hay protocolos.")
        return
    selected = st.selectbox("Protocolo", list(mapping))
    p = mapping[selected]
    with st.form("finding_form"):
        c1, c2, c3 = st.columns(3)
        visit_date = c1.date_input("Fecha de visita", value=date.today())
        visit_type = c2.selectbox("Tipo de visita", ["Programada", "Por causa", "Seguimiento de EAS", "Cierre", "Auditoría interna"])
        category = c3.selectbox(
            "Categoría",
            ["Consentimiento informado", "Protocolo", "Seguridad", "Producto de investigación", "Datos fuente/FRC", "Equipo/capacitación", "Farmacia", "Archivo", "Otro"],
        )
        c4, c5, c6 = st.columns(3)
        severity = c4.selectbox("Severidad", ["Menor", "Mayor", "Crítica"])
        numerator = c5.number_input("Registros con hallazgo", min_value=0, step=1)
        denominator = c6.number_input("Registros revisados", min_value=0, step=1)
        description = st.text_area("Hallazgo objetivo y específico*")
        evidence = st.text_input("Referencia de evidencia / anexo")
        capa = st.text_area("Acción correctiva y preventiva requerida")
        c7, c8 = st.columns(2)
        due = c7.date_input("Fecha límite", value=date.today() + timedelta(days=30))
        status = c8.selectbox("Estado", ["Abierto", "Observado", "Respuesta recibida", "Verificación pendiente", "Levantado"])
        save = st.form_submit_button("Registrar hallazgo", type="primary")
    if save:
        if not description.strip():
            st.error("Describa el hallazgo.")
        elif denominator and numerator > denominator:
            st.error("Los registros con hallazgo no pueden superar los revisados.")
        else:
            fid = execute(
                """INSERT INTO findings
                (protocol_id, visit_date, visit_type, category, severity, numerator, denominator,
                 description, evidence_reference, capa, due_date, status, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    p["id"], visit_date.isoformat(), visit_type, category, severity,
                    int(numerator), int(denominator), description.strip(), evidence.strip(),
                    capa.strip(), due.isoformat(), status, user["id"], iso_now(),
                ),
            )
            log_action(user["id"], "Registró hallazgo", "finding", fid, {"severity": severity})
            st.success("Hallazgo registrado.")

    findings = query(
        """SELECT f.*, p.code FROM findings f JOIN protocols p ON p.id=f.protocol_id
           ORDER BY f.visit_date DESC"""
    )
    if findings:
        rows = []
        for f in findings:
            rate = None
            if f.get("denominator"):
                rate = round(f.get("numerator", 0) / f["denominator"] * 100, 1)
            rows.append({
                "Protocolo": f["code"], "Visita": f["visit_date"], "Tipo": f["visit_type"],
                "Categoría": f["category"], "Severidad": f["severity"],
                "Hallazgo": f"{f.get('numerator') or 0}/{f.get('denominator') or 0}",
                "Tasa": f"{rate}%" if rate is not None else "—",
                "Estado": f["status"], "Vence": f["due_date"], "Descripción": f["description"],
            })
        fdf = pd.DataFrame(rows)
        st.dataframe(fdf, use_container_width=True, hide_index=True)
        st.download_button("Exportar hallazgos CSV", df_to_csv_bytes(fdf), "hallazgos_cei.csv", "text/csv")


def render_members() -> None:
    page_header(
        "Miembros y capacitación",
        "Composición multidisciplinaria, independencia, asistencia y vigencia formativa.",
        "Competencia institucional",
    )
    tabs = st.tabs(["Composición", "Registrar capacitación", "Vencimientos"])
    members = query(
        """SELECT id, username, full_name, email, role, discipline, is_scientific,
                  is_independent, is_community, active, last_login
           FROM users ORDER BY role, full_name"""
    )
    with tabs[0]:
        if members:
            mdf = pd.DataFrame(members)
            mdf = mdf[["full_name", "role", "discipline", "is_scientific", "is_independent", "is_community", "active", "last_login"]]
            mdf.columns = ["Miembro", "Rol", "Disciplina", "Científico", "Independiente", "Comunidad", "Activo", "Último acceso"]
            st.dataframe(mdf, use_container_width=True, hide_index=True)
            composition = {
                "Miembros activos": sum(bool(m["active"]) for m in members),
                "No científicos": sum(bool(m["active"]) and not bool(m["is_scientific"]) for m in members),
                "Independientes": sum(bool(m["active"]) and bool(m["is_independent"]) for m in members),
                "Comunidad": sum(bool(m["active"]) and bool(m["is_community"]) for m in members),
            }
            cols = st.columns(4)
            for col, (label, value) in zip(cols, composition.items()):
                col.metric(label, value)

    with tabs[1]:
        eligible = [m for m in members if m["role"] in {"Administrador", "Secretaría", "Presidencia", "Revisor", "Monitor"}]
        mapping = {m["full_name"]: m for m in eligible}
        with st.form("training_form"):
            name = st.selectbox("Miembro", list(mapping))
            course = st.text_input("Curso / actividad*", value="Buenas Prácticas Clínicas ICH E6(R3)")
            provider = st.text_input("Proveedor")
            c1, c2 = st.columns(2)
            issued = c1.date_input("Fecha de emisión", value=date.today())
            expires = c2.date_input("Fecha de vencimiento", value=date.today() + timedelta(days=730))
            certificate = st.text_input("Referencia del certificado")
            save = st.form_submit_button("Registrar capacitación", type="primary")
        if save:
            tid = execute(
                """INSERT INTO training
                (user_id, course_name, provider, issued_at, expires_at, certificate_reference, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    mapping[name]["id"], course.strip(), provider.strip(),
                    issued.isoformat(), expires.isoformat(), certificate.strip(), iso_now(),
                ),
            )
            log_action(user["id"], "Registró capacitación", "training", tid, {"member": name})
            st.success("Capacitación registrada.")

    with tabs[2]:
        training = query(
            """SELECT t.*, u.full_name, u.role FROM training t
               JOIN users u ON u.id=t.user_id ORDER BY t.expires_at"""
        )
        if training:
            rows = []
            for t in training:
                days = (date.fromisoformat(t["expires_at"]) - date.today()).days if t.get("expires_at") else None
                rows.append({
                    "Miembro": t["full_name"], "Rol": t["role"], "Curso": t["course_name"],
                    "Proveedor": t["provider"], "Emisión": t["issued_at"], "Vencimiento": t["expires_at"],
                    "Días restantes": days, "Certificado": t["certificate_reference"],
                })
            tdf = pd.DataFrame(rows)
            st.dataframe(tdf, use_container_width=True, hide_index=True)
            st.download_button("Exportar capacitación CSV", df_to_csv_bytes(tdf), "capacitacion_cei.csv", "text/csv")


def render_kb() -> None:
    page_header(
        "Base de conocimiento",
        "Fuentes versionadas para orientar la evaluación, con prioridad a normativa oficial y documentos institucionales.",
        "Consulta regulatoria",
    )
    sources = load_sources()
    q = st.text_input("Buscar por tema, norma o proceso", placeholder="Ej.: consentimiento, EAS, quórum, datos, enmienda")
    results = search_sources(q, sources, local_guide_text()) if q.strip() else sources
    st.caption(f"{len(results)} fuentes recuperadas. Verifique siempre vigencia, jurisdicción y POE aplicable.")
    for source in results:
        with st.expander(f"{source['title']} · {source.get('version','')}"):
            st.write(f"**Ámbito:** {source.get('jurisdiction','')}")
            st.write(source.get("summary", ""))
            st.caption("Etiquetas: " + source.get("tags", ""))
            if source.get("url"):
                st.link_button("Abrir fuente oficial", source["url"])
            if source.get("local_file"):
                local_path = KB_DIR / source["local_file"]
                if local_path.exists():
                    st.download_button(
                        "Descargar documento local",
                        local_path.read_bytes(),
                        file_name=local_path.name,
                        mime="application/pdf",
                        key=f"kb_{source['title']}",
                    )

    if user["role"] in {"Administrador", "Secretaría", "Presidencia"}:
        st.markdown("---")
        st.markdown("#### Incorporar documento institucional")
        kb_file = st.file_uploader("PDF para la base local", type=["pdf"], key="kb_upload")
        kb_title = st.text_input("Título descriptivo")
        if st.button("Guardar en base local", disabled=kb_file is None or not kb_title.strip()):
            safe = clean_filename(kb_file.name)
            path = KB_DIR / f"{uuid.uuid4().hex[:8]}_{safe}"
            path.write_bytes(kb_file.getvalue())
            log_action(user["id"], "Incorporó fuente a base local", "knowledge_source", path.name, {"title": kb_title})
            st.success("Documento guardado. Para indexación semántica de producción se recomienda un vector store institucional.")


def render_admin() -> None:
    page_header(
        "Administración y auditoría",
        "Parámetros operativos, trazabilidad y controles institucionales.",
        "Acceso restringido",
    )
    tabs = st.tabs(["Parámetros", "Auditoría", "Diagnóstico"])
    with tabs[0]:
        st.warning("Los valores deben validarse contra normativa, acreditación y POE vigentes del comité.")
        with st.form("settings_form"):
            committee_name = st.text_input("Nombre del comité", value=get_setting("committee_name"))
            c1, c2, c3 = st.columns(3)
            quorum = c1.number_input("Mínimo absoluto de quórum", min_value=1, value=int(get_setting("quorum_min_absolute", "5")))
            sae_days = c2.number_input("Meta EAS (días hábiles)", min_value=0, value=int(get_setting("sae_target_business_days", "2")))
            protocol_days = c3.number_input("Meta dictamen final (días)", min_value=1, value=int(get_setting("protocol_target_days", "60")))
            c4, c5, c6 = st.columns(3)
            first_obs = c4.number_input("Meta primera observación (días)", min_value=1, value=int(get_setting("first_observation_target_days", "9")))
            training_days = c5.number_input("Alerta capacitación (días)", min_value=1, value=int(get_setting("training_alert_days", "60")))
            retention = c6.number_input("Retención documental (años)", min_value=1, value=int(get_setting("document_retention_years", "10")))
            req_non = st.checkbox("Exigir miembro no científico", value=get_setting("require_non_scientific", "1") == "1")
            req_ind = st.checkbox("Exigir miembro independiente", value=get_setting("require_independent", "1") == "1")
            req_com = st.checkbox("Exigir representante comunitario", value=get_setting("require_community", "1") == "1")
            save = st.form_submit_button("Guardar parámetros", type="primary")
        if save:
            values = {
                "committee_name": committee_name.strip(),
                "quorum_min_absolute": str(int(quorum)),
                "sae_target_business_days": str(int(sae_days)),
                "protocol_target_days": str(int(protocol_days)),
                "first_observation_target_days": str(int(first_obs)),
                "training_alert_days": str(int(training_days)),
                "document_retention_years": str(int(retention)),
                "require_non_scientific": "1" if req_non else "0",
                "require_independent": "1" if req_ind else "0",
                "require_community": "1" if req_com else "0",
            }
            for key, value in values.items():
                set_setting(key, value)
            log_action(user["id"], "Actualizó parámetros", "settings", "", values)
            st.success("Parámetros actualizados.")

    with tabs[1]:
        logs = query(
            """SELECT a.created_at, u.full_name, u.role, a.action, a.entity_type, a.entity_id, a.detail_json
               FROM audit_log a LEFT JOIN users u ON u.id=a.user_id
               ORDER BY a.created_at DESC LIMIT 1000"""
        )
        if logs:
            ldf = pd.DataFrame(logs)
            ldf.columns = ["Fecha", "Usuario", "Rol", "Acción", "Entidad", "ID", "Detalle"]
            st.dataframe(ldf, use_container_width=True, hide_index=True)
            st.download_button("Exportar auditoría CSV", df_to_csv_bytes(ldf), "auditoria_cei.csv", "text/csv")

    with tabs[2]:
        st.markdown("#### Controles del MVP")
        checks = {
            "Base SQLite disponible": (BASE_DIR / "data" / "cei_nexus.db").exists(),
            "Guía local incorporada": LOCAL_GUIDE.exists(),
            "Directorio de cargas": UPLOAD_DIR.exists(),
            "Fuentes regulatorias": bool(load_sources()),
            "Generación PDF": True,
        }
        for label, ok in checks.items():
            st.write("✅" if ok else "❌", label)
        st.info(
            "Antes del uso institucional: PostgreSQL, almacenamiento de objetos, MFA/SSO, "
            "cifrado, backups verificados, firma digital, registro inmutable y evaluación de seguridad."
        )


PAGE_RENDERERS = {
    "Dashboard": render_dashboard,
    "Protocolos": render_protocols,
    "Evaluaciones": render_reviews,
    "Sesiones": render_meetings,
    "Seguridad": render_safety,
    "Enmiendas": render_amendments,
    "Supervisión": render_supervision,
    "Miembros": render_members,
    "Base de conocimiento": render_kb,
    "Administración": render_admin,
}

PAGE_RENDERERS[current_page]()
