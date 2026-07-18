from __future__ import annotations

from datetime import date, timedelta
from io import BytesIO
from pathlib import Path
import json

import pandas as pd
import plotly.express as px
import streamlit as st
from pypdf import PdfReader

from cei_core.audit import create_audit_anchor, list_audit_anchors
from cei_core.db import (
    KB_DIR,
    ensure_schema,
    execute,
    get_setting,
    log_action,
    one,
    query,
    set_setting,
    set_request_context,
    verify_audit_chain,
)
from cei_core.digital_sign import sign_pdf_with_pkcs12
from cei_core.domain import (
    ANSWER_OPTIONS,
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
from cei_core.security import (
    consume_recovery_code,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_recovery_codes,
    generate_totp_secret,
    hash_password,
    hash_recovery_codes,
    lock_until,
    mfa_is_required_for_role,
    parse_iso_datetime,
    password_needs_rehash,
    totp_provisioning_uri,
    totp_qr_png,
    utc_now,
    verify_password,
    verify_totp,
)
from cei_core.storage import get_storage
from cei_core.workflow import (
    WorkflowError,
    available_transitions,
    get_active_workflow,
    install_workflow,
    load_workflow_yaml,
    transition_protocol,
    workflow_hash,
)


BASE_DIR = Path(__file__).resolve().parent
CSS_PATH = BASE_DIR / "assets" / "styles.css"
LOCAL_GUIDE = KB_DIR / "Guia_etica_revision_ensayos_clinicos.pdf"
FINAL_STATES = {"Aprobado", "Aprobado con condiciones", "Rechazado", "Cerrado"}
PRIVILEGED_ROLES = {"Administrador", "Presidencia", "Secretaría"}

st.set_page_config(
    page_title="CEI Nexus",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded",
)

try:
    ensure_schema()
except Exception as exc:
    st.error("CEI Nexus no pudo conectarse a su base PostgreSQL inicializada.")
    st.code(str(exc))
    st.info("Ejecute primero `python scripts/migrate.py` con DATABASE_ADMIN_URL configurada.")
    st.stop()


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


def refresh_user(user_id: int) -> dict:
    refreshed = one("SELECT * FROM users WHERE id=?", (user_id,))
    if not refreshed:
        raise RuntimeError("El usuario ya no existe.")
    return refreshed


def complete_login(user: dict) -> None:
    execute(
        "UPDATE users SET last_login=?, failed_login_count=0, locked_until=NULL WHERE id=?",
        (iso_now(), user["id"]),
    )
    current = refresh_user(user["id"])
    required = mfa_is_required_for_role(current["role"], get_setting("enforce_mfa_roles", ""))
    st.session_state["user"] = current
    st.session_state["mfa_enrollment_required"] = bool(required and not current.get("mfa_enabled"))
    st.session_state.pop("pending_mfa_user_id", None)
    log_action(current["id"], "Inicio de sesión", "user", current["id"], {"mfa": bool(current.get("mfa_enabled"))})
    st.rerun()


def register_failed_login(user: dict | None) -> None:
    if not user:
        return
    max_failures = int(get_setting("login_max_failures", "5"))
    lock_minutes = int(get_setting("login_lock_minutes", "15"))
    failures = int(user.get("failed_login_count") or 0) + 1
    locked = lock_until(lock_minutes) if failures >= max_failures else None
    execute(
        "UPDATE users SET failed_login_count=?, locked_until=? WHERE id=?",
        (failures, locked, user["id"]),
    )
    log_action(user["id"], "Intento fallido de acceso", "user", user["id"], {"failed_count": failures, "locked": bool(locked)})


def password_step(username: str, password: str) -> tuple[bool, str]:
    user = one("SELECT * FROM users WHERE username=? AND active=true", (username.strip(),))
    if not user:
        return False, "Credenciales incorrectas o usuario inactivo."
    locked_until = parse_iso_datetime(user.get("locked_until"))
    if locked_until and locked_until > utc_now():
        return False, f"Cuenta temporalmente bloqueada hasta {locked_until.astimezone().strftime('%d/%m/%Y %H:%M')}."
    if not verify_password(password, user["password_hash"]):
        register_failed_login(user)
        return False, "Credenciales incorrectas o usuario inactivo."
    if password_needs_rehash(user["password_hash"]):
        try:
            execute("UPDATE users SET password_hash=?, password_changed_at=? WHERE id=?", (hash_password(password), iso_now(), user["id"]))
        except ValueError:
            pass
    if user.get("mfa_enabled"):
        st.session_state["pending_mfa_user_id"] = user["id"]
        return True, "MFA_REQUIRED"
    complete_login(user)
    return True, "OK"


def mfa_step(code: str) -> tuple[bool, str]:
    user_id = st.session_state.get("pending_mfa_user_id")
    if not user_id:
        return False, "La sesión de autenticación venció."
    user = refresh_user(user_id)
    secret_enc = user.get("mfa_secret_enc")
    if not secret_enc:
        return False, "MFA está marcado como activo pero no posee secreto configurado."
    secret = decrypt_totp_secret(secret_enc)
    if verify_totp(secret, code):
        complete_login(user)
        return True, "OK"
    recovery = user.get("recovery_codes") or []
    if isinstance(recovery, str):
        recovery = json.loads(recovery)
    matched, remaining = consume_recovery_code(code, recovery)
    if matched:
        execute("UPDATE users SET recovery_codes=?::jsonb WHERE id=?", (json.dumps(remaining), user["id"]))
        log_action(user["id"], "Usó código de recuperación MFA", "user", user["id"], {"remaining": len(remaining)})
        complete_login(user)
        return True, "OK"
    register_failed_login(user)
    return False, "Código MFA o de recuperación inválido."


def login_screen() -> None:
    st.markdown(
        """
        <div class="cei-login-shell">
          <div class="cei-header" style="margin-bottom:18px;">
            <span class="cei-badge">PostgreSQL · MFA · almacenamiento cifrado</span>
            <h1>CEI Nexus</h1>
            <p>Gestión ética, científica y operacional de investigaciones en salud.</p>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    _, center, _ = st.columns([1, 1.25, 1])
    with center:
        if st.session_state.get("pending_mfa_user_id"):
            st.markdown("#### Segundo factor")
            with st.form("mfa_login_form"):
                code = st.text_input("Código de la aplicación autenticadora o código de recuperación", type="password")
                submitted = st.form_submit_button("Verificar", type="primary", use_container_width=True)
            if submitted:
                ok, message = mfa_step(code)
                if not ok:
                    st.error(message)
            if st.button("Volver al inicio", use_container_width=True):
                st.session_state.pop("pending_mfa_user_id", None)
                st.rerun()
        else:
            with st.form("login_form"):
                username = st.text_input("Usuario")
                password = st.text_input("Contraseña", type="password")
                submitted = st.form_submit_button("Ingresar", type="primary", use_container_width=True)
            if submitted:
                ok, message = password_step(username, password)
                if not ok:
                    st.error(message)
        with st.expander("Credenciales de demostración"):
            st.caption("Solo se crean cuando SEED_DEMO_DATA=true. Cambiarlas antes de ingresar información real.")
            st.code(
                "admin / AdminCEI-2026!\n"
                "secretaria / Secretaria-2026!\n"
                "presidente / Presidencia-2026!\n"
                "revisor / RevisorCEI-2026!\n"
                "monitor / MonitorCEI-2026!\n"
                "investigador / Investigador-2026!"
            )


if "user" not in st.session_state:
    set_request_context(None, "")
    login_screen()
    st.stop()

user = refresh_user(st.session_state["user"]["id"])
st.session_state["user"] = user
set_request_context(user["id"], user["role"])

ROLE_PAGES = {
    "Administrador": ["Dashboard", "Protocolos", "Evaluaciones", "Sesiones", "Seguridad", "Enmiendas", "Supervisión", "Miembros", "Base de conocimiento", "Mi seguridad", "Administración"],
    "Secretaría": ["Dashboard", "Protocolos", "Sesiones", "Seguridad", "Enmiendas", "Supervisión", "Miembros", "Base de conocimiento", "Mi seguridad"],
    "Presidencia": ["Dashboard", "Protocolos", "Evaluaciones", "Sesiones", "Seguridad", "Enmiendas", "Supervisión", "Miembros", "Base de conocimiento", "Mi seguridad"],
    "Revisor": ["Dashboard", "Protocolos", "Evaluaciones", "Sesiones", "Base de conocimiento", "Mi seguridad"],
    "Monitor": ["Dashboard", "Protocolos", "Seguridad", "Supervisión", "Base de conocimiento", "Mi seguridad"],
    "Investigador": ["Dashboard", "Protocolos", "Seguridad", "Enmiendas", "Base de conocimiento", "Mi seguridad"],
}

with st.sidebar:
    st.markdown("## ⚖️ CEI Nexus")
    st.caption(get_setting("committee_name", "Comité de Ética en Investigación"))
    st.markdown("---")
    st.markdown(f"**{user['full_name']}**")
    st.caption(f"{user['role']} · {user.get('discipline') or 'Sin disciplina'}")
    if user.get("mfa_enabled"):
        st.success("MFA activo", icon="🔐")
    elif st.session_state.get("mfa_enrollment_required"):
        st.warning("MFA obligatorio pendiente", icon="⚠️")
    pages = ROLE_PAGES.get(user["role"], ["Dashboard", "Mi seguridad"])
    if st.session_state.get("mfa_enrollment_required"):
        pages = ["Mi seguridad"]
    current_page = st.radio("Navegación", pages, label_visibility="collapsed")
    st.markdown("---")
    st.caption("La asistencia automatizada no reemplaza la deliberación ni la responsabilidad del CEI.")
    if st.button("Cerrar sesión", use_container_width=True):
        log_action(user["id"], "Cierre de sesión", "user", user["id"])
        set_request_context(None, "")
        st.session_state.clear()
        st.rerun()


def protocol_label(protocol: dict) -> str:
    return f"{protocol['code']} · {protocol['title'][:85]}"


def protocol_options() -> tuple[list[dict], dict[str, dict]]:
    rows = query("SELECT * FROM protocols ORDER BY created_at DESC")
    return rows, {protocol_label(p): p for p in rows}


def secure_store(
    *,
    data: bytes,
    namespace: str,
    filename: str,
    content_type: str,
    aad: dict,
    legal_hold: bool = False,
):
    years = int(get_setting("document_retention_years", "10"))
    return get_storage().put_encrypted(
        data=data,
        namespace=namespace,
        filename=filename,
        content_type=content_type or "application/octet-stream",
        aad=aad,
        retention_days=max(365, years * 365),
        legal_hold=legal_hold,
    )


def render_dashboard() -> None:
    page_header("Centro de control del Comité", "Oportunidad, calidad, seguridad, carga y cumplimiento del workflow institucional.", "Métricas en tiempo real")
    protocols = query("SELECT * FROM protocols ORDER BY created_at DESC")
    safety = query("SELECT * FROM safety_events")
    deviations = query("SELECT * FROM deviations")
    training = query("SELECT t.*, u.full_name FROM training t JOIN users u ON u.id=t.user_id ORDER BY expires_at")
    workflow = get_active_workflow()

    active = [p for p in protocols if p["status"] not in FINAL_STATES]
    observed = [p for p in protocols if p["status"] == "Observado"]
    tpo, tdf = [], []
    for p in protocols:
        if p.get("submitted_at") and p.get("first_observation_at"):
            tpo.append((date.fromisoformat(p["first_observation_at"]) - date.fromisoformat(p["submitted_at"])).days)
        if p.get("submitted_at") and p.get("final_decision_at"):
            tdf.append((date.fromisoformat(p["final_decision_at"]) - date.fromisoformat(p["submitted_at"])).days)

    target_sae = int(get_setting("sae_target_business_days", "2"))
    late_safety = [
        e for e in safety
        if business_days_between(date.fromisoformat(e["awareness_date"]), date.fromisoformat(e["reported_at"])) > target_sae
    ]
    overdue_devs = [
        d for d in deviations
        if d.get("due_date") and d["status"] != "Cerrado" and date.fromisoformat(d["due_date"]) < date.today()
    ]
    alert_days = int(get_setting("training_alert_days", "60"))
    expiring = [
        t for t in training
        if t.get("expires_at") and (date.fromisoformat(t["expires_at"]) - date.today()).days <= alert_days
    ]

    cols = st.columns(4)
    with cols[0]:
        kpi_card("Protocolos activos", str(len(active)), f"{len(protocols)} expedientes totales")
    with cols[1]:
        kpi_card("Primera observación", f"{sum(tpo)/len(tpo):.1f} d" if tpo else "—", f"Meta ≤ {get_setting('first_observation_target_days','9')} días")
    with cols[2]:
        kpi_card("Dictamen final", f"{sum(tdf)/len(tdf):.1f} d" if tdf else "—", f"Meta ≤ {get_setting('protocol_target_days','60')} días")
    with cols[3]:
        rate = len(observed) / len(protocols) * 100 if protocols else 0
        kpi_card("Observados", f"{rate:.0f}%", f"{len(observed)} expedientes")

    st.caption(f"Workflow activo: {workflow['name']} · versión {workflow['version']} · hash {workflow['_hash'][:12]}…")
    a1, a2, a3 = st.columns(3)
    a1.metric("EAS fuera de meta", len(late_safety), delta=f"Meta {target_sae} días hábiles", delta_color="inverse")
    a2.metric("CAPA/desvíos vencidos", len(overdue_devs), delta="Requieren seguimiento", delta_color="inverse")
    a3.metric("Capacitaciones por vencer", len(expiring), delta=f"Próximos {alert_days} días", delta_color="inverse")

    left, right = st.columns([1.4, 1])
    with left:
        if protocols:
            status_count = pd.DataFrame(protocols).groupby("status", as_index=False).size().sort_values("size", ascending=False)
            fig = px.bar(status_count, x="status", y="size", labels={"status": "Etapa", "size": "Protocolos"}, title="Cartera por etapa del POE")
            fig.update_layout(height=365, margin=dict(l=15, r=15, t=55, b=90), showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
    with right:
        workload = query(
            """SELECT u.full_name AS revisor, COUNT(p.id) AS protocolos
               FROM users u LEFT JOIN protocols p ON p.assigned_reviewer_id=u.id
               WHERE u.role IN ('Revisor','Presidencia')
               GROUP BY u.id, u.full_name ORDER BY protocolos DESC"""
        )
        if workload:
            fig = px.pie(pd.DataFrame(workload), names="revisor", values="protocolos", hole=.58, title="Carga por evaluador")
            fig.update_layout(height=365, margin=dict(l=10, r=10, t=55, b=20))
            st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Expedientes prioritarios")
    attention = [p for p in protocols if p["status"] in {"Observado", "En revisión", "Respuesta recibida", "Suspendido", "Subsanación documental"}]
    if attention:
        df = pd.DataFrame(attention)[["code", "title", "principal_investigator", "risk_level", "status", "stage_entered_at"]]
        df.columns = ["Código", "Título", "Investigador", "Riesgo", "Etapa", "Ingreso a etapa"]
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.success("No hay expedientes prioritarios pendientes.")


def render_protocols() -> None:
    page_header("Expedientes y documentos", "Workflow por POE, versionado documental y almacenamiento cifrado con retención.", "PostgreSQL + Object Storage")
    protocols, mapping = protocol_options()
    tabs = st.tabs(["Cartera", "Nuevo protocolo", "Workflow y metadatos", "Documentos seguros"])

    with tabs[0]:
        status_options = sorted({p["status"] for p in protocols})
        c1, c2 = st.columns(2)
        status_filter = c1.multiselect("Etapa", status_options)
        risk_filter = c2.multiselect("Riesgo", RISK_LEVELS)
        rows = [p for p in protocols if (not status_filter or p["status"] in status_filter) and (not risk_filter or p["risk_level"] in risk_filter)]
        if rows:
            df = pd.DataFrame(rows)[["code", "title", "principal_investigator", "institution", "study_type", "risk_level", "status", "submitted_at", "current_version", "workflow_version"]]
            df.columns = ["Código", "Título", "IP", "Institución", "Tipo", "Riesgo", "Etapa", "Ingreso", "Versión documental", "POE"]
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.download_button("Exportar cartera CSV", df_to_csv_bytes(df), "protocolos_cei.csv", "text/csv")
        else:
            st.info("No hay protocolos con esos filtros.")

    with tabs[1]:
        if user["role"] not in {"Administrador", "Secretaría", "Investigador", "Presidencia"}:
            st.warning("Su rol dispone de acceso de consulta.")
        else:
            workflow = get_active_workflow()
            reviewers = query("SELECT id, full_name FROM users WHERE active=true AND role IN ('Revisor','Presidencia') ORDER BY full_name")
            reviewer_map = {"Sin asignar": None, **{r["full_name"]: r["id"] for r in reviewers}}
            with st.form("new_protocol"):
                c1, c2 = st.columns(2)
                code = c1.text_input("Código interno*", value=f"CEI-{date.today().year}-")
                title = c2.text_input("Título completo*")
                c3, c4 = st.columns(2)
                pi = c3.text_input("Investigador principal*")
                sponsor = c4.text_input("Patrocinador / financiamiento")
                c5, c6 = st.columns(2)
                institution = c5.text_input("Institución / centro")
                study_type = c6.selectbox("Tipo de investigación*", STUDY_TYPES)
                c7, c8, c9 = st.columns(3)
                phase = c7.text_input("Fase", value="N/A")
                risk = c8.selectbox("Nivel de riesgo*", RISK_LEVELS, index=2)
                version = c9.text_input("Versión", value="1.0")
                vulnerable = st.text_input("Población vulnerable / salvaguardas")
                assigned_name = st.selectbox("Evaluador asignado", list(reviewer_map))
                notes = st.text_area("Notas de recepción")
                create = st.form_submit_button("Crear expediente", type="primary")
            if create:
                if not code.strip() or not title.strip() or not pi.strip():
                    st.error("Complete código, título e investigador principal.")
                elif one("SELECT id FROM protocols WHERE code=?", (code.strip(),)):
                    st.error("El código ya existe.")
                else:
                    now = iso_now()
                    initial = workflow["initial_stage"]
                    pid = execute(
                        """INSERT INTO protocols
                        (code, title, principal_investigator, sponsor, institution, phase, study_type,
                         risk_level, vulnerable_population, status, current_stage, stage_entered_at,
                         workflow_version, submitted_at, current_version, assigned_reviewer_id,
                         created_by, notes, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (code.strip(), title.strip(), pi.strip(), sponsor.strip(), institution.strip(), phase.strip(), study_type,
                         risk, vulnerable.strip(), initial, initial, now, str(workflow["version"]), date.today().isoformat(),
                         version.strip() or "1.0", reviewer_map[assigned_name], user["id"], notes.strip(), now, now),
                    )
                    log_action(user["id"], "Creó protocolo", "protocol", pid, {"code": code.strip(), "workflow": workflow["_hash"]})
                    st.success("Expediente creado en la etapa inicial del POE.")
                    st.rerun()

    with tabs[2]:
        if not mapping:
            st.info("No hay protocolos.")
        else:
            selected = st.selectbox("Expediente", list(mapping), key="workflow_protocol")
            p = mapping[selected]
            reviewers = query("SELECT id, full_name FROM users WHERE active=true AND role IN ('Revisor','Presidencia') ORDER BY full_name")
            reviewer_names = ["Sin asignar"] + [r["full_name"] for r in reviewers]
            current_reviewer = one("SELECT full_name FROM users WHERE id=?", (p.get("assigned_reviewer_id"),)) if p.get("assigned_reviewer_id") else None
            current_name = current_reviewer["full_name"] if current_reviewer else "Sin asignar"
            st.markdown(f"**Etapa actual:** {p['status']} · **POE:** {p.get('workflow_version') or 'sin versión'}")
            if user["role"] in {"Administrador", "Secretaría", "Presidencia"}:
                with st.form("metadata_update"):
                    c1, c2, c3 = st.columns(3)
                    risk = c1.selectbox("Riesgo", RISK_LEVELS, index=RISK_LEVELS.index(p["risk_level"]))
                    version = c2.text_input("Versión documental", value=p.get("current_version") or "1.0")
                    assigned_name = c3.selectbox("Evaluador", reviewer_names, index=reviewer_names.index(current_name) if current_name in reviewer_names else 0)
                    notes = st.text_area("Notas", value=p.get("notes") or "")
                    update = st.form_submit_button("Guardar metadatos")
                if update:
                    assigned_id = next((r["id"] for r in reviewers if r["full_name"] == assigned_name), None)
                    execute("UPDATE protocols SET risk_level=?, current_version=?, assigned_reviewer_id=?, notes=?, updated_at=? WHERE id=?", (risk, version.strip(), assigned_id, notes.strip(), iso_now(), p["id"]))
                    log_action(user["id"], "Actualizó metadatos del protocolo", "protocol", p["id"], {"risk": risk, "version": version})
                    st.success("Metadatos actualizados.")
                    st.rerun()
            else:
                st.caption(f"Riesgo: {p['risk_level']} · Versión documental: {p.get('current_version') or '—'} · Evaluador: {current_name}")

            transitions = available_transitions(p.get("current_stage") or p["status"], user["role"])
            st.markdown("#### Transición conforme al POE")
            if transitions:
                with st.form("workflow_transition"):
                    target = st.selectbox("Próxima etapa permitida", transitions)
                    reason = st.text_area("Fundamento / referencia de acta o comunicación*")
                    submit_transition = st.form_submit_button("Ejecutar transición", type="primary")
                if submit_transition:
                    if not reason.strip():
                        st.error("Documente el fundamento de la transición.")
                    else:
                        try:
                            transition_protocol(p["id"], target, user, reason)
                            if target in FINAL_STATES and not p.get("final_decision_at"):
                                execute("UPDATE protocols SET final_decision_at=? WHERE id=?", (date.today().isoformat(), p["id"]))
                            st.success(f"Expediente trasladado a: {target}.")
                            st.rerun()
                        except WorkflowError as exc:
                            st.error(str(exc))
            else:
                st.info("No hay transiciones habilitadas para su rol desde esta etapa.")

            history = query(
                """SELECT w.from_stage, w.to_stage, w.reason, w.created_at, u.full_name
                   FROM workflow_events w LEFT JOIN users u ON u.id=w.performed_by
                   WHERE w.protocol_id=? ORDER BY w.id DESC""",
                (p["id"],),
            )
            if history:
                hdf = pd.DataFrame(history)
                hdf.columns = ["Desde", "Hacia", "Fundamento", "Fecha", "Usuario"]
                st.dataframe(hdf, use_container_width=True, hide_index=True)

    with tabs[3]:
        if not mapping:
            st.info("No hay protocolos.")
        else:
            selected = st.selectbox("Expediente", list(mapping), key="document_protocol")
            p = mapping[selected]
            c1, c2, c3 = st.columns([1.2, .7, 1.2])
            category = c1.selectbox("Categoría", ["Protocolo", "Consentimiento informado", "Manual del investigador", "CV / capacitación", "Seguro", "Contrato / presupuesto", "Material de reclutamiento", "Enmienda", "Informe de seguridad", "Respuesta a observaciones", "Otro"])
            version = c2.text_input("Versión", value=p.get("current_version") or "1.0")
            uploaded = c3.file_uploader("Archivo", type=["pdf", "docx", "xlsx", "csv", "txt"], key="secure_protocol_document")
            if st.button("Cifrar e incorporar", type="primary", disabled=uploaded is None):
                try:
                    content = uploaded.getvalue()
                    stored = secure_store(
                        data=content,
                        namespace=f"protocols/{p['code']}",
                        filename=uploaded.name,
                        content_type=uploaded.type or "application/octet-stream",
                        aad={"record_type": "protocol_document", "protocol_id": p["id"], "category": category, "version": version},
                    )
                    execute("UPDATE documents SET is_current=false WHERE protocol_id=? AND category=? AND is_current=true", (p["id"], category))
                    did = execute(
                        """INSERT INTO documents
                        (protocol_id, category, version, filename, object_key, object_version,
                         plaintext_sha256, ciphertext_sha256, content_type, size_bytes,
                         encryption_key_id, retention_until, legal_hold, uploaded_at, uploaded_by, is_current)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, ?, true)""",
                        (p["id"], category, version.strip(), uploaded.name, stored.object_key, stored.version_id,
                         stored.plaintext_sha256, stored.ciphertext_sha256, stored.content_type, stored.size_bytes,
                         stored.encryption_key_id, stored.retention_until, iso_now(), user["id"]),
                    )
                    log_action(user["id"], "Incorporó documento cifrado", "document", did, {"protocol": p["code"], "sha256": stored.plaintext_sha256, "object_version": stored.version_id})
                    st.success("Documento cifrado, versionado y almacenado correctamente.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"No fue posible almacenar el documento: {exc}")

            docs = query(
                """SELECT d.*, u.full_name AS uploaded_by_name FROM documents d
                   LEFT JOIN users u ON u.id=d.uploaded_by
                   WHERE d.protocol_id=? ORDER BY d.uploaded_at DESC""",
                (p["id"],),
            )
            if docs:
                ddf = pd.DataFrame(docs)[["id", "category", "version", "filename", "plaintext_sha256", "size_bytes", "retention_until", "is_current", "uploaded_at", "uploaded_by_name"]]
                ddf.columns = ["ID", "Categoría", "Versión", "Archivo", "SHA-256", "Bytes", "Retención", "Vigente", "Carga", "Usuario"]
                st.dataframe(ddf, use_container_width=True, hide_index=True)
                selected_doc = st.selectbox("Documento para recuperar", docs, format_func=lambda d: f"#{d['id']} · {d['category']} · {d['filename']} · v{d.get('version') or ''}")
                if st.button("Verificar y preparar descarga"):
                    try:
                        data, aad = get_storage().get_decrypted(selected_doc["object_key"], selected_doc.get("object_version"))
                        st.session_state[f"doc_download_{selected_doc['id']}"] = data
                        st.success(f"Integridad verificada: {aad.get('plaintext_sha256', '')[:16]}…")
                    except Exception as exc:
                        st.error(f"La recuperación o verificación falló: {exc}")
                if st.session_state.get(f"doc_download_{selected_doc['id']}"):
                    st.download_button("Descargar documento descifrado", st.session_state[f"doc_download_{selected_doc['id']}"], selected_doc["filename"], selected_doc["content_type"])
            else:
                st.caption("Aún no hay documentos vinculados.")


def render_reviews() -> None:
    page_header("Evaluación ética y científica", "Checklist trazable, observaciones y dictamen PDF con firma digital PAdES.", "Asistencia al evaluador")
    _, mapping = protocol_options()
    if not mapping:
        st.info("No hay protocolos.")
        return
    selected = st.selectbox("Expediente", list(mapping))
    p = mapping[selected]
    st.markdown(f"<div class='cei-info'><b>{p['code']}</b> · {p['title']}<br>Riesgo: <b>{p['risk_level']}</b> · Etapa: <b>{p['status']}</b> · Versión: <b>{p['current_version']}</b></div>", unsafe_allow_html=True)
    tabs = st.tabs(["Nueva evaluación", "Analizador de consentimiento", "Historial, PDF y firma"])

    with tabs[0]:
        with st.form("review_form"):
            review_type = st.selectbox("Tipo de revisión", ["Inicial", "Expeditiva", "Continuada", "Enmienda", "Seguridad"])
            grouped: dict[str, list[dict]] = {}
            for item in REVIEW_CHECKLIST:
                grouped.setdefault(item["domain"], []).append(item)
            answers = []
            for domain, items in grouped.items():
                st.markdown(f"#### {domain}")
                for item in items:
                    c1, c2 = st.columns([1.15, 1])
                    answer = c1.selectbox(item["text"], ANSWER_OPTIONS, index=0, key=f"ans_{p['id']}_{item['key']}")
                    comment = c2.text_input(f"Comentario · {item['severity']}", key=f"com_{p['id']}_{item['key']}", placeholder="Fundamento, documento o cambio requerido")
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
                (p["id"], user["id"], review_type, iso_now(), iso_now(), summary["total_score"], recommendation, general_comments.strip(), iso_now()),
            )
            for item in answers:
                execute("""INSERT INTO review_items (review_id, domain, item_key, item_text, answer, severity, comment) VALUES (?, ?, ?, ?, ?, ?, ?)""", (rid, item["domain"], item["key"], item["text"], item["answer"], item["severity"], item["comment"].strip()))
            observations = generate_observations(answers)
            if observations and not p.get("first_observation_at"):
                execute("UPDATE protocols SET first_observation_at=?, updated_at=? WHERE id=?", (date.today().isoformat(), iso_now(), p["id"]))
            log_action(user["id"], "Completó evaluación", "review", rid, {"protocol": p["code"], "score": summary["total_score"], "recommendation": recommendation, "critical_open": len(summary["critical_open"])})
            st.success(f"Evaluación guardada. Puntaje orientativo: {summary['total_score']}%.")
            if summary["critical_open"]:
                st.error(f"Hallazgos críticos abiertos: {len(summary['critical_open'])}")
            st.write("**Sugerencia del motor de reglas:**", summary["suggested_recommendation"])
            with st.expander("Observaciones generadas"):
                for obs in observations:
                    st.write("•", obs)

    with tabs[1]:
        ci_file = st.file_uploader("Consentimiento en PDF", type=["pdf"], key="ci_analyzer_pdf")
        ci_text = st.text_area("O pegue el texto", height=220, placeholder="La revisión automática no reemplaza la lectura del evaluador.")
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
            m1.metric("Cobertura", f"{result['coverage']}%")
            m2.metric("Palabras", result["word_count"])
            m3.metric("Palabras/oración", result["avg_sentence_words"])
            m4.metric("Legibilidad", result["readability_flag"])
            cdf = pd.DataFrame(result["checks"])
            cdf["Estado"] = cdf["present"].map({True: "Detectado", False: "No detectado"})
            st.dataframe(cdf[["element", "Estado"]].rename(columns={"element": "Elemento"}), use_container_width=True, hide_index=True)
            if result["missing"]:
                st.warning("Elementos no detectados: " + "; ".join(result["missing"]))

    with tabs[2]:
        reviews = query(
            """SELECT r.*, u.full_name AS reviewer_name FROM reviews r
               JOIN users u ON u.id=r.reviewer_id WHERE r.protocol_id=? ORDER BY r.created_at DESC""",
            (p["id"],),
        )
        if not reviews:
            st.info("No hay evaluaciones registradas.")
        else:
            rdf = pd.DataFrame(reviews)[["id", "review_type", "reviewer_name", "completed_at", "total_score", "recommendation"]]
            rdf.columns = ["ID", "Tipo", "Revisor", "Fecha", "Puntaje", "Recomendación"]
            st.dataframe(rdf, use_container_width=True, hide_index=True)
            review_id = st.selectbox("Evaluación", [r["id"] for r in reviews])
            review = next(r for r in reviews if r["id"] == review_id)
            items = query("SELECT * FROM review_items WHERE review_id=? ORDER BY id", (review_id,))
            pdf = build_review_pdf(get_setting("committee_name"), p, review, items, review["reviewer_name"])
            st.download_button("Descargar informe PDF sin firma", pdf, f"{p['code']}_revision_{review_id}.pdf", "application/pdf")

            st.markdown("#### Firma digital del dictamen")
            signatures = query("SELECT * FROM digital_signatures WHERE review_id=? ORDER BY signed_at DESC", (review_id,))
            if signatures:
                sdf = pd.DataFrame(signatures)[["signed_at", "certificate_subject", "signed_sha256", "signature_profile", "trust_validation_status"]]
                sdf.columns = ["Fecha", "Certificado", "SHA-256 firmado", "Perfil", "Validación de confianza"]
                st.dataframe(sdf, use_container_width=True, hide_index=True)
                selected_signature = st.selectbox(
                    "Documento firmado archivado",
                    signatures,
                    format_func=lambda sig: f"#{sig['id']} · {sig['signed_at']} · {sig.get('certificate_subject') or 'Certificado'}",
                )
                if st.button("Recuperar y verificar PDF firmado", key=f"retrieve_signature_{review_id}"):
                    try:
                        signed_data, signed_aad = get_storage().get_decrypted(
                            selected_signature["signed_object_key"],
                            selected_signature.get("signed_object_version"),
                        )
                        import hashlib

                        actual_hash = hashlib.sha256(signed_data).hexdigest()
                        if actual_hash != selected_signature["signed_sha256"]:
                            raise ValueError("El hash del PDF recuperado no coincide con el registro de firma.")
                        st.session_state[f"archived_signed_pdf_{selected_signature['id']}"] = signed_data
                        st.success(f"Integridad verificada: {actual_hash[:20]}…")
                    except Exception as exc:
                        st.error(f"No fue posible recuperar el PDF firmado: {exc}")
                archived_key = f"archived_signed_pdf_{selected_signature['id']}"
                if st.session_state.get(archived_key):
                    st.download_button(
                        "Descargar PDF firmado archivado",
                        st.session_state[archived_key],
                        f"{p['code']}_revision_{review_id}_firmada_archivo.pdf",
                        "application/pdf",
                        key=f"download_archived_signature_{selected_signature['id']}",
                    )
            if not user.get("mfa_enabled"):
                st.warning("Active MFA en ‘Mi seguridad’ antes de firmar. La firma exige autenticación reforzada.")
            else:
                with st.form("digital_signature_form"):
                    p12 = st.file_uploader("Certificado personal PKCS#12 (.p12/.pfx)", type=["p12", "pfx"], key=f"p12_{review_id}")
                    c1, c2 = st.columns(2)
                    passphrase = c1.text_input("Contraseña del certificado", type="password")
                    otp = c2.text_input("Código MFA de confirmación", type="password")
                    reason = st.text_input("Motivo", value="Dictamen del Comité de Ética en Investigación")
                    location = st.text_input("Ubicación", value=get_setting("institution_location", "Argentina"))
                    sign_now = st.form_submit_button("Firmar y archivar", type="primary")
                if sign_now:
                    try:
                        secret = decrypt_totp_secret(user["mfa_secret_enc"])
                        if not verify_totp(secret, otp):
                            raise ValueError("El código MFA de confirmación es inválido.")
                        if p12 is None:
                            raise ValueError("Seleccione el certificado PKCS#12.")
                        signed = sign_pdf_with_pkcs12(
                            pdf_bytes=pdf,
                            pkcs12_bytes=p12.getvalue(),
                            passphrase=passphrase,
                            field_name=f"CEI_Review_{review_id}_{user['id']}",
                            reason=reason,
                            location=location,
                        )
                        stored = secure_store(
                            data=signed.pdf_bytes,
                            namespace=f"signed/{p['code']}",
                            filename=f"{p['code']}_revision_{review_id}_firmada.pdf",
                            content_type="application/pdf",
                            aad={"record_type": "digitally_signed_review", "protocol_id": p["id"], "review_id": review_id, "signer_user_id": user["id"]},
                            legal_hold=True,
                        )
                        sig_id = execute(
                            """INSERT INTO digital_signatures
                            (protocol_id, review_id, signer_user_id, unsigned_sha256, signed_sha256,
                             signed_object_key, signed_object_version, certificate_subject,
                             certificate_issuer, certificate_serial, certificate_fingerprint_sha256,
                             signature_profile, trust_validation_status, signed_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PAdES', ?, ?)""",
                            (p["id"], review_id, user["id"], signed.unsigned_sha256, signed.signed_sha256,
                             stored.object_key, stored.version_id, signed.certificate_subject, signed.certificate_issuer,
                             signed.certificate_serial, signed.certificate_fingerprint_sha256,
                             "Integridad firmada; validar confianza con la cadena institucional", iso_now()),
                        )
                        log_action(user["id"], "Firmó digitalmente un dictamen", "digital_signature", sig_id, {"protocol": p["code"], "review_id": review_id, "signed_sha256": signed.signed_sha256, "certificate_fingerprint": signed.certificate_fingerprint_sha256})
                        st.session_state[f"signed_pdf_{review_id}"] = signed.pdf_bytes
                        st.success("PDF firmado en perfil PAdES y archivado en almacenamiento cifrado con retención.")
                    except Exception as exc:
                        st.error(f"No fue posible firmar: {exc}")
                if st.session_state.get(f"signed_pdf_{review_id}"):
                    st.download_button("Descargar PDF firmado", st.session_state[f"signed_pdf_{review_id}"], f"{p['code']}_revision_{review_id}_firmada.pdf", "application/pdf", type="primary")
            st.caption("La validez jurídica depende del certificado, su cadena de confianza, vigencia, revocación y la normativa aplicable. Para producción se recomienda firma remota o HSM institucional.")


def render_meetings() -> None:
    page_header("Sesiones, quórum y deliberación", "Representatividad, conflictos de interés, recusaciones y actas.", "Gobernanza")
    members = query("""SELECT id, full_name, role, discipline, is_scientific, is_independent, is_community FROM users WHERE active=true AND role IN ('Presidencia','Revisor') ORDER BY full_name""")
    tabs = st.tabs(["Nueva sesión", "Historial"])
    with tabs[0]:
        if not members:
            st.warning("No hay miembros habilitados.")
            return
        with st.form("meeting_form"):
            c1, c2 = st.columns(2)
            title = c1.text_input("Título", value=f"Reunión ordinaria {date.today().strftime('%d/%m/%Y')}")
            meeting_date = c2.date_input("Fecha", value=date.today())
            notes = st.text_area("Agenda / notas")
            attendance_rows = []
            for member in members:
                a, b, c, d = st.columns([2.2, .7, .8, .8])
                a.markdown(f"**{member['full_name']}**  \n<small>{member.get('discipline') or ''} · {'científico' if member['is_scientific'] else 'no científico'}{' · independiente' if member['is_independent'] else ''}{' · comunidad' if member['is_community'] else ''}</small>", unsafe_allow_html=True)
                present = b.checkbox("Presente", key=f"pres_{member['id']}")
                conflict = c.checkbox("CoI", key=f"coi_{member['id']}")
                recused = d.checkbox("Recusado", key=f"rec_{member['id']}", disabled=not conflict)
                attendance_rows.append({"member_id": member["id"], "present": present, "conflict_declared": conflict, "recused": recused, "is_scientific": bool(member["is_scientific"]), "is_independent": bool(member["is_independent"]), "is_community": bool(member["is_community"])})
            save = st.form_submit_button("Guardar y verificar quórum", type="primary")
        if save:
            result = quorum_evaluation(len(members), attendance_rows, int(get_setting("quorum_min_absolute", "5")), get_setting("require_non_scientific", "1") == "1", get_setting("require_independent", "1") == "1", get_setting("require_community", "1") == "1")
            mid = execute("INSERT INTO meetings(title, meeting_date, status, notes, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)", (title.strip(), meeting_date.isoformat(), "Quórum válido" if result["valid"] else "Quórum no válido", notes.strip(), user["id"], iso_now()))
            for row in attendance_rows:
                execute("INSERT INTO attendance(meeting_id, member_id, present, conflict_declared, recused) VALUES (?, ?, ?, ?, ?)", (mid, row["member_id"], row["present"], row["conflict_declared"], row["recused"]))
            log_action(user["id"], "Registró sesión", "meeting", mid, result)
            st.success(f"Sesión registrada: {'quórum válido' if result['valid'] else 'quórum no válido'}.") if result["valid"] else st.error("La sesión no cumple los requisitos configurados de quórum.")
            for condition, ok in result["conditions"].items():
                st.write("✅" if ok else "❌", condition)
    with tabs[1]:
        meetings = query("""SELECT m.*, u.full_name AS created_by_name FROM meetings m LEFT JOIN users u ON u.id=m.created_by ORDER BY m.meeting_date DESC""")
        if meetings:
            mdf = pd.DataFrame(meetings)[["id", "meeting_date", "title", "status", "created_by_name"]]
            mdf.columns = ["ID", "Fecha", "Sesión", "Estado", "Registró"]
            st.dataframe(mdf, use_container_width=True, hide_index=True)
            mid = st.selectbox("Asistencia", [m["id"] for m in meetings])
            attendance = query("""SELECT u.full_name, u.discipline, a.present, a.conflict_declared, a.recused, a.vote FROM attendance a JOIN users u ON u.id=a.member_id WHERE a.meeting_id=? ORDER BY u.full_name""", (mid,))
            if attendance:
                adf = pd.DataFrame(attendance)
                adf.columns = ["Miembro", "Disciplina", "Presente", "Conflicto", "Recusado", "Voto"]
                st.dataframe(adf, use_container_width=True, hide_index=True)
        else:
            st.info("No hay sesiones.")


def render_safety() -> None:
    page_header("Seguridad de participantes", "Eventos serios, plazos de reporte, desvíos y CAPA.", "Vigilancia continua")
    _, mapping = protocol_options()
    if not mapping:
        st.info("No hay protocolos.")
        return
    tabs = st.tabs(["EAS / RAMSI", "Desvíos", "Tablero"])
    with tabs[0]:
        p = mapping[st.selectbox("Protocolo", list(mapping), key="safety_protocol")]
        with st.form("new_safety_event"):
            c1, c2, c3 = st.columns(3)
            event_type = c1.selectbox("Tipo", ["EAS", "RAMSI / SUSAR", "Evento de especial interés", "Otro"])
            participant_code = c2.text_input("Código del participante*")
            event_date = c3.date_input("Fecha del evento", value=date.today())
            c4, c5, c6 = st.columns(3)
            awareness_date = c4.date_input("Conocimiento", value=date.today())
            reported_at = c5.date_input("Reporte al CEI", value=date.today())
            status = c6.selectbox("Estado", ["Notificado", "Bajo revisión", "Observado", "En seguimiento", "Cerrado"])
            c7, c8, c9 = st.columns(3)
            seriousness = c7.selectbox("Seriedad", ["Fallecimiento", "Riesgo de vida", "Hospitalización", "Discapacidad", "Anomalía congénita", "Evento médicamente importante"])
            expectedness = c8.selectbox("Esperabilidad", ["Esperado", "Inesperado", "No determinado"])
            relatedness = c9.selectbox("Relación", ["No relacionada", "Improbable", "Posible", "Probable", "Definida", "No determinada"])
            description = st.text_area("Descripción clínica y evolución*")
            followup_due = st.date_input("Próximo seguimiento", value=date.today() + timedelta(days=30))
            save = st.form_submit_button("Registrar evento", type="primary")
        if save:
            if not participant_code.strip() or not description.strip():
                st.error("Complete código y descripción.")
            else:
                eid = execute("""INSERT INTO safety_events(protocol_id, event_type, participant_code, event_date, awareness_date, reported_at, seriousness, expectedness, relatedness, description, status, followup_due, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (p["id"], event_type, participant_code.strip(), event_date.isoformat(), awareness_date.isoformat(), reported_at.isoformat(), seriousness, expectedness, relatedness, description.strip(), status, followup_due.isoformat(), user["id"], iso_now()))
                delay = business_days_between(awareness_date, reported_at)
                log_action(user["id"], "Registró evento de seguridad", "safety_event", eid, {"delay_business_days": delay})
                target = int(get_setting("sae_target_business_days", "2"))
                st.warning(f"Evento registrado: {delay} días hábiles, por encima de la meta {target}.") if delay > target else st.success(f"Evento registrado: {delay} días hábiles.")
    with tabs[1]:
        p = mapping[st.selectbox("Protocolo", list(mapping), key="deviation_protocol")]
        with st.form("new_deviation"):
            c1, c2, c3 = st.columns(3)
            participant = c1.text_input("Código de participante")
            deviation_date = c2.date_input("Fecha", value=date.today())
            deviation_type = c3.selectbox("Tipo", ["Consentimiento", "Elegibilidad", "Dosis/medicación", "Cadena de frío", "Procedimiento", "Visita/ventana", "Datos", "Otro"])
            c4, c5, c6 = st.columns(3)
            severity = c4.selectbox("Clasificación", ["Menor", "Mayor", "Crítico / violación"])
            safety_impact = c5.checkbox("Impacto en seguridad")
            data_impact = c6.checkbox("Impacto en datos")
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
                did = execute("""INSERT INTO deviations(protocol_id, participant_code, deviation_date, deviation_type, severity, safety_impact, data_integrity_impact, description, corrective_action, preventive_action, status, due_date, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (p["id"], participant.strip(), deviation_date.isoformat(), deviation_type, severity, safety_impact, data_impact, description.strip(), corrective.strip(), preventive.strip(), status, due.isoformat(), user["id"], iso_now()))
                log_action(user["id"], "Registró desvío", "deviation", did, {"severity": severity})
                st.success("Desvío registrado.")
    with tabs[2]:
        events = query("""SELECT s.*, p.code FROM safety_events s JOIN protocols p ON p.id=s.protocol_id ORDER BY s.reported_at DESC""")
        if events:
            target = int(get_setting("sae_target_business_days", "2"))
            rows = []
            for event in events:
                delay = business_days_between(date.fromisoformat(event["awareness_date"]), date.fromisoformat(event["reported_at"]))
                rows.append({"Protocolo": event["code"], "Tipo": event["event_type"], "Participante": event["participant_code"], "Evento": event["event_date"], "Reporte": event["reported_at"], "Demora hábil": delay, "Dentro de meta": "Sí" if delay <= target else "No", "Estado": event["status"]})
            edf = pd.DataFrame(rows)
            st.dataframe(edf, use_container_width=True, hide_index=True)
            st.download_button("Exportar seguridad CSV", df_to_csv_bytes(edf), "seguridad_cei.csv", "text/csv")
        else:
            st.info("No hay eventos.")


def render_amendments() -> None:
    page_header("Enmiendas", "Clasificación por impacto, aprobación previa y trazabilidad.", "Control de cambios")
    _, mapping = protocol_options()
    if not mapping:
        st.info("No hay protocolos.")
        return
    p = mapping[st.selectbox("Protocolo", list(mapping))]
    with st.form("new_amendment"):
        c1, c2, c3 = st.columns(3)
        code = c1.text_input("Código", value=f"ENM-{date.today().year}-")
        submitted = c2.date_input("Presentación", value=date.today())
        classification = c3.selectbox("Clasificación", ["Sustancial", "No sustancial", "Urgente por seguridad", "A determinar"])
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
            aid = execute("""INSERT INTO amendments(protocol_id, amendment_code, submitted_at, classification, safety_impact, scientific_impact, operational_impact, summary, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (p["id"], code.strip(), submitted.isoformat(), classification, safety, scientific, operational, summary.strip(), status, user["id"], iso_now()))
            log_action(user["id"], "Registró enmienda", "amendment", aid, {"classification": classification})
            st.success("Enmienda registrada.")
    rows = query("""SELECT a.*, p.code FROM amendments a JOIN protocols p ON p.id=a.protocol_id ORDER BY a.submitted_at DESC""")
    if rows:
        df = pd.DataFrame(rows)[["code", "amendment_code", "submitted_at", "classification", "safety_impact", "scientific_impact", "operational_impact", "status", "summary"]]
        df.columns = ["Protocolo", "Enmienda", "Ingreso", "Clasificación", "Seguridad", "Científico", "Operativo", "Estado", "Resumen"]
        st.dataframe(df, use_container_width=True, hide_index=True)


def render_supervision() -> None:
    page_header("Supervisión, hallazgos y CAPA", "Hallazgos objetivos, cuantificados y seguidos hasta el levantamiento.", "Garantía de calidad")
    _, mapping = protocol_options()
    if not mapping:
        st.info("No hay protocolos.")
        return
    p = mapping[st.selectbox("Protocolo", list(mapping))]
    with st.form("finding_form"):
        c1, c2, c3 = st.columns(3)
        visit_date = c1.date_input("Fecha", value=date.today())
        visit_type = c2.selectbox("Visita", ["Programada", "Por causa", "Seguimiento de EAS", "Cierre", "Auditoría interna"])
        category = c3.selectbox("Categoría", ["Consentimiento informado", "Protocolo", "Seguridad", "Producto de investigación", "Datos fuente/FRC", "Equipo/capacitación", "Farmacia", "Archivo", "Otro"])
        c4, c5, c6 = st.columns(3)
        severity = c4.selectbox("Severidad", ["Menor", "Mayor", "Crítica"])
        numerator = c5.number_input("Con hallazgo", min_value=0, step=1)
        denominator = c6.number_input("Revisados", min_value=0, step=1)
        description = st.text_area("Hallazgo objetivo*")
        evidence = st.text_input("Evidencia / anexo")
        capa = st.text_area("CAPA requerida")
        c7, c8 = st.columns(2)
        due = c7.date_input("Fecha límite", value=date.today() + timedelta(days=30))
        status = c8.selectbox("Estado", ["Abierto", "Observado", "Respuesta recibida", "Verificación pendiente", "Levantado"])
        save = st.form_submit_button("Registrar hallazgo", type="primary")
    if save:
        if not description.strip():
            st.error("Describa el hallazgo.")
        elif denominator and numerator > denominator:
            st.error("El numerador no puede superar el denominador.")
        else:
            fid = execute("""INSERT INTO findings(protocol_id, visit_date, visit_type, category, severity, numerator, denominator, description, evidence_reference, capa, due_date, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (p["id"], visit_date.isoformat(), visit_type, category, severity, int(numerator), int(denominator), description.strip(), evidence.strip(), capa.strip(), due.isoformat(), status, user["id"], iso_now()))
            log_action(user["id"], "Registró hallazgo", "finding", fid, {"severity": severity})
            st.success("Hallazgo registrado.")
    findings = query("""SELECT f.*, p.code FROM findings f JOIN protocols p ON p.id=f.protocol_id ORDER BY f.visit_date DESC""")
    if findings:
        rows = []
        for finding in findings:
            rate = round((finding.get("numerator") or 0) / finding["denominator"] * 100, 1) if finding.get("denominator") else None
            rows.append({"Protocolo": finding["code"], "Visita": finding["visit_date"], "Tipo": finding["visit_type"], "Categoría": finding["category"], "Severidad": finding["severity"], "Hallazgo": f"{finding.get('numerator') or 0}/{finding.get('denominator') or 0}", "Tasa": f"{rate}%" if rate is not None else "—", "Estado": finding["status"], "Vence": finding["due_date"], "Descripción": finding["description"]})
        fdf = pd.DataFrame(rows)
        st.dataframe(fdf, use_container_width=True, hide_index=True)
        st.download_button("Exportar hallazgos CSV", df_to_csv_bytes(fdf), "hallazgos_cei.csv", "text/csv")


def render_members() -> None:
    page_header("Miembros y capacitación", "Composición, independencia y vigencia formativa.", "Competencia institucional")
    members = query("""SELECT id, username, full_name, email, role, discipline, is_scientific, is_independent, is_community, active, mfa_enabled, last_login FROM users ORDER BY role, full_name""")
    tabs = st.tabs(["Composición", "Registrar capacitación", "Vencimientos"])
    with tabs[0]:
        if members:
            df = pd.DataFrame(members)[["full_name", "role", "discipline", "is_scientific", "is_independent", "is_community", "mfa_enabled", "active", "last_login"]]
            df.columns = ["Miembro", "Rol", "Disciplina", "Científico", "Independiente", "Comunidad", "MFA", "Activo", "Último acceso"]
            st.dataframe(df, use_container_width=True, hide_index=True)
    with tabs[1]:
        eligible = [m for m in members if m["role"] in {"Administrador", "Secretaría", "Presidencia", "Revisor", "Monitor"}]
        member_map = {m["full_name"]: m for m in eligible}
        with st.form("training_form"):
            name = st.selectbox("Miembro", list(member_map))
            course = st.text_input("Curso*", value="Buenas Prácticas Clínicas ICH E6(R3)")
            provider = st.text_input("Proveedor")
            c1, c2 = st.columns(2)
            issued = c1.date_input("Emisión", value=date.today())
            expires = c2.date_input("Vencimiento", value=date.today() + timedelta(days=730))
            certificate = st.text_input("Referencia")
            save = st.form_submit_button("Registrar", type="primary")
        if save:
            tid = execute("INSERT INTO training(user_id, course_name, provider, issued_at, expires_at, certificate_reference, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (member_map[name]["id"], course.strip(), provider.strip(), issued.isoformat(), expires.isoformat(), certificate.strip(), iso_now()))
            log_action(user["id"], "Registró capacitación", "training", tid, {"member": name})
            st.success("Capacitación registrada.")
    with tabs[2]:
        training = query("""SELECT t.*, u.full_name, u.role FROM training t JOIN users u ON u.id=t.user_id ORDER BY t.expires_at""")
        if training:
            rows = []
            for item in training:
                days = (date.fromisoformat(item["expires_at"]) - date.today()).days if item.get("expires_at") else None
                rows.append({"Miembro": item["full_name"], "Rol": item["role"], "Curso": item["course_name"], "Proveedor": item["provider"], "Emisión": item["issued_at"], "Vencimiento": item["expires_at"], "Días": days, "Certificado": item["certificate_reference"]})
            tdf = pd.DataFrame(rows)
            st.dataframe(tdf, use_container_width=True, hide_index=True)
            st.download_button("Exportar capacitación CSV", df_to_csv_bytes(tdf), "capacitacion_cei.csv", "text/csv")


def render_kb() -> None:
    page_header("Base de conocimiento", "Fuentes versionadas, documentos institucionales y normativa aplicable.", "Consulta regulatoria")
    sources = load_sources()
    q = st.text_input("Buscar", placeholder="consentimiento, EAS, quórum, datos, enmienda")
    results = search_sources(q, sources, local_guide_text()) if q.strip() else sources
    st.caption(f"{len(results)} fuentes. Verifique vigencia, jurisdicción y POE aplicable.")
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
                    st.download_button("Descargar documento local", local_path.read_bytes(), local_path.name, "application/pdf", key=f"kb_{source['title']}")

    institutional = query("SELECT * FROM documents WHERE protocol_id IS NULL AND category='Base de conocimiento' ORDER BY uploaded_at DESC")
    if institutional:
        st.markdown("#### Documentos institucionales cifrados")
        idf = pd.DataFrame(institutional)[["id", "filename", "version", "plaintext_sha256", "retention_until", "uploaded_at"]]
        idf.columns = ["ID", "Documento", "Versión", "SHA-256", "Retención", "Carga"]
        st.dataframe(idf, use_container_width=True, hide_index=True)
    if user["role"] in {"Administrador", "Secretaría", "Presidencia"}:
        st.markdown("#### Incorporar fuente institucional")
        kb_file = st.file_uploader("PDF", type=["pdf"], key="kb_secure_upload")
        kb_title = st.text_input("Título / versión")
        if st.button("Cifrar e incorporar", disabled=kb_file is None or not kb_title.strip()):
            try:
                stored = secure_store(data=kb_file.getvalue(), namespace="knowledge-base", filename=kb_file.name, content_type="application/pdf", aad={"record_type": "knowledge_base", "title": kb_title})
                did = execute("""INSERT INTO documents(protocol_id, category, version, filename, object_key, object_version, plaintext_sha256, ciphertext_sha256, content_type, size_bytes, encryption_key_id, retention_until, legal_hold, uploaded_at, uploaded_by, is_current) VALUES (NULL, 'Base de conocimiento', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, ?, true)""", (kb_title.strip(), kb_file.name, stored.object_key, stored.version_id, stored.plaintext_sha256, stored.ciphertext_sha256, stored.content_type, stored.size_bytes, stored.encryption_key_id, stored.retention_until, iso_now(), user["id"]))
                log_action(user["id"], "Incorporó fuente institucional cifrada", "document", did, {"title": kb_title, "sha256": stored.plaintext_sha256})
                st.success("Fuente incorporada al repositorio seguro.")
                st.rerun()
            except Exception as exc:
                st.error(str(exc))


def render_my_security() -> None:
    page_header("Mi seguridad", "Autenticación multifactor, recuperación y cambio de contraseña.", "Protección de identidad")
    current = refresh_user(user["id"])
    tabs = st.tabs(["MFA", "Contraseña", "Sesión"])
    with tabs[0]:
        if st.session_state.get("new_recovery_codes"):
            st.warning("Guarde estos códigos ahora. No volverán a mostrarse.")
            st.code("\n".join(st.session_state["new_recovery_codes"]))
            if st.button("Confirmo que guardé los códigos", key="confirm_recovery_codes"):
                st.session_state.pop("new_recovery_codes", None)
                st.rerun()
        if current.get("mfa_enabled"):
            st.success("La autenticación multifactor está activa.")
            with st.form("regenerate_codes"):
                otp = st.text_input("Código MFA para generar nuevos códigos de recuperación", type="password")
                regenerate = st.form_submit_button("Generar nuevos códigos")
            if regenerate:
                try:
                    secret = decrypt_totp_secret(current["mfa_secret_enc"])
                    if not verify_totp(secret, otp):
                        raise ValueError("Código MFA inválido.")
                    codes = generate_recovery_codes()
                    execute("UPDATE users SET recovery_codes=?::jsonb WHERE id=?", (json.dumps(hash_recovery_codes(codes)), current["id"]))
                    log_action(current["id"], "Regeneró códigos de recuperación", "user", current["id"], {})
                    st.warning("Guarde estos códigos ahora. No volverán a mostrarse.")
                    st.code("\n".join(codes))
                except Exception as exc:
                    st.error(str(exc))
        else:
            st.warning("MFA no está configurado.")
            if "mfa_setup_secret" not in st.session_state:
                st.session_state["mfa_setup_secret"] = generate_totp_secret()
            secret = st.session_state["mfa_setup_secret"]
            issuer = get_setting("committee_name", "CEI Nexus")
            uri = totp_provisioning_uri(secret, current["username"], issuer)
            st.image(totp_qr_png(uri), width=220)
            st.code(secret)
            st.caption("Escanee el QR con una aplicación TOTP. Luego ingrese el primer código para activar.")
            with st.form("enable_mfa"):
                code = st.text_input("Código de 6 dígitos", type="password")
                enable = st.form_submit_button("Activar MFA", type="primary")
            if enable:
                try:
                    if not verify_totp(secret, code):
                        raise ValueError("Código TOTP inválido.")
                    codes = generate_recovery_codes()
                    execute("UPDATE users SET mfa_secret_enc=?, mfa_enabled=true, recovery_codes=?::jsonb WHERE id=?", (encrypt_totp_secret(secret), json.dumps(hash_recovery_codes(codes)), current["id"]))
                    log_action(current["id"], "Activó MFA", "user", current["id"], {})
                    st.session_state["mfa_enrollment_required"] = False
                    st.session_state.pop("mfa_setup_secret", None)
                    st.session_state["new_recovery_codes"] = codes
                    st.rerun()
                except Exception as exc:
                    st.error(str(exc))
    with tabs[1]:
        with st.form("change_password"):
            current_password = st.text_input("Contraseña actual", type="password")
            new_password = st.text_input("Nueva contraseña (mínimo 12 caracteres)", type="password")
            confirm = st.text_input("Repetir nueva contraseña", type="password")
            otp = st.text_input("Código MFA, si está activo", type="password")
            change = st.form_submit_button("Cambiar contraseña", type="primary")
        if change:
            try:
                if not verify_password(current_password, current["password_hash"]):
                    raise ValueError("La contraseña actual no es correcta.")
                if new_password != confirm:
                    raise ValueError("Las nuevas contraseñas no coinciden.")
                if current.get("mfa_enabled") and not verify_totp(decrypt_totp_secret(current["mfa_secret_enc"]), otp):
                    raise ValueError("Código MFA inválido.")
                encoded = hash_password(new_password)
                execute("UPDATE users SET password_hash=?, password_changed_at=?, failed_login_count=0, locked_until=NULL WHERE id=?", (encoded, iso_now(), current["id"]))
                log_action(current["id"], "Cambió contraseña", "user", current["id"], {})
                st.success("Contraseña actualizada.")
            except Exception as exc:
                st.error(str(exc))
    with tabs[2]:
        st.write(f"**Último acceso:** {current.get('last_login') or 'Sin registro'}")
        st.write(f"**MFA:** {'Activo' if current.get('mfa_enabled') else 'No configurado'}")
        st.write(f"**Rol:** {current['role']}")
        if st.session_state.get("mfa_enrollment_required"):
            st.warning("Su rol requiere MFA. Hasta activarlo, el acceso queda limitado a esta pantalla.")


def render_admin() -> None:
    page_header("Administración, POE y auditoría", "Configuración institucional, workflow versionado y cadena inmutable.", "Acceso restringido")
    tabs = st.tabs(["Parámetros", "POE y workflow", "Auditoría inmutable", "Diagnóstico"])
    with tabs[0]:
        with st.form("settings_form"):
            committee_name = st.text_input("Nombre del comité", value=get_setting("committee_name"))
            c1, c2, c3 = st.columns(3)
            quorum = c1.number_input("Mínimo de quórum", min_value=1, value=int(get_setting("quorum_min_absolute", "5")))
            sae_days = c2.number_input("Meta EAS (días hábiles)", min_value=0, value=int(get_setting("sae_target_business_days", "2")))
            protocol_days = c3.number_input("Meta dictamen (días)", min_value=1, value=int(get_setting("protocol_target_days", "60")))
            c4, c5, c6 = st.columns(3)
            first_obs = c4.number_input("Meta primera observación", min_value=1, value=int(get_setting("first_observation_target_days", "9")))
            training_days = c5.number_input("Alerta capacitación", min_value=1, value=int(get_setting("training_alert_days", "60")))
            retention = c6.number_input("Retención documental (años)", min_value=1, value=int(get_setting("document_retention_years", "10")))
            enforce_roles = st.text_input("Roles con MFA obligatorio (separados por coma)", value=get_setting("enforce_mfa_roles", "Administrador,Presidencia,Secretaría"))
            c7, c8 = st.columns(2)
            max_failures = c7.number_input("Intentos fallidos antes del bloqueo", min_value=3, value=int(get_setting("login_max_failures", "5")))
            lock_minutes = c8.number_input("Minutos de bloqueo", min_value=5, value=int(get_setting("login_lock_minutes", "15")))
            req_non = st.checkbox("Exigir miembro no científico", value=get_setting("require_non_scientific", "1") == "1")
            req_ind = st.checkbox("Exigir miembro independiente", value=get_setting("require_independent", "1") == "1")
            req_com = st.checkbox("Exigir representante comunitario", value=get_setting("require_community", "1") == "1")
            save = st.form_submit_button("Guardar parámetros", type="primary")
        if save:
            values = {"committee_name": committee_name.strip(), "quorum_min_absolute": str(int(quorum)), "sae_target_business_days": str(int(sae_days)), "protocol_target_days": str(int(protocol_days)), "first_observation_target_days": str(int(first_obs)), "training_alert_days": str(int(training_days)), "document_retention_years": str(int(retention)), "enforce_mfa_roles": enforce_roles.strip(), "login_max_failures": str(int(max_failures)), "login_lock_minutes": str(int(lock_minutes)), "require_non_scientific": "1" if req_non else "0", "require_independent": "1" if req_ind else "0", "require_community": "1" if req_com else "0"}
            for key, value in values.items():
                set_setting(key, value)
            log_action(user["id"], "Actualizó parámetros", "settings", "", values)
            st.success("Parámetros actualizados.")
    with tabs[1]:
        active = get_active_workflow()
        st.markdown(f"**Activo:** {active['name']} · v{active['version']} · `{active['_hash']}`")
        stages = []
        for stage, definition in active["stages"].items():
            stages.append({"Etapa": stage, "SLA días": definition.get("sla_days"), "Transiciones": ", ".join(definition.get("transitions", {}).keys())})
        st.dataframe(pd.DataFrame(stages), use_container_width=True, hide_index=True)
        st.markdown("#### Cargar nueva versión de POE")
        workflow_file = st.file_uploader("YAML aprobado por el comité", type=["yaml", "yml"], key="poe_yaml")
        activate = st.checkbox("Activar inmediatamente después de validar")
        if st.button("Validar e instalar", disabled=workflow_file is None):
            try:
                definition = load_workflow_yaml(workflow_file.getvalue())
                wid = install_workflow(definition, approved_by=user["id"], activate=activate)
                log_action(user["id"], "Instaló definición de POE", "workflow_definition", wid, {"code": definition["code"], "version": definition["version"], "hash": workflow_hash(definition), "active": activate})
                st.success(f"POE válido e instalado. ID {wid}.")
                st.rerun()
            except Exception as exc:
                st.error(str(exc))
        st.info("La plantilla incluida no puede considerarse el POE real hasta que el comité apruebe su mapeo, responsables, plazos, documentos obligatorios y excepciones.")
    with tabs[2]:
        verification = verify_audit_chain()
        if verification.get("valid"):
            st.success(f"Cadena válida: {verification.get('checked_entries', 0)} eventos. Hash actual: {verification.get('current_hash','')[:20]}…")
        else:
            st.error(f"Cadena inconsistente. Primer ID afectado: {verification.get('bad_id')}")
        if st.button("Crear ancla WORM en almacenamiento seguro", type="primary", disabled=not verification.get("valid")):
            try:
                result = create_audit_anchor(user["id"])
                st.success("La cadena fue sellada en almacenamiento con retención y legal hold." if not result.get("already_exists") else "Ya existía un ancla para el último evento.")
            except Exception as exc:
                st.error(str(exc))
        anchors = list_audit_anchors()
        if anchors:
            adf = pd.DataFrame(anchors)[["id", "audit_log_id", "event_count", "chain_hash", "created_at", "created_by_name"]]
            adf.columns = ["ID", "Último evento", "Eventos", "Hash", "Fecha", "Creó"]
            st.dataframe(adf, use_container_width=True, hide_index=True)
        logs = query("""SELECT a.created_at, a.event_uuid, u.full_name, u.role, a.action, a.entity_type, a.entity_id, a.previous_hash, a.entry_hash, a.detail_json FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 1000""")
        if logs:
            ldf = pd.DataFrame(logs)
            st.dataframe(ldf, use_container_width=True, hide_index=True)
            st.download_button("Exportar auditoría CSV", df_to_csv_bytes(ldf), "auditoria_cei.csv", "text/csv")
    with tabs[3]:
        checks = {}
        try:
            checks["PostgreSQL"] = bool(one("SELECT version() AS version"))
        except Exception:
            checks["PostgreSQL"] = False
        try:
            get_storage().ensure_bucket()
            checks["Almacenamiento S3/MinIO"] = True
        except Exception:
            checks["Almacenamiento S3/MinIO"] = False
        checks["Guía local"] = LOCAL_GUIDE.exists()
        checks["Workflow activo"] = bool(get_active_workflow())
        checks["Cadena de auditoría"] = bool(verify_audit_chain().get("valid"))
        checks["MFA administrador"] = bool(user.get("mfa_enabled"))
        for label, ok in checks.items():
            st.write("✅" if ok else "❌", label)
        st.caption("Para firma institucional de máxima seguridad se recomienda HSM o firma remota; el archivo PKCS#12 cargado en esta versión se usa solo en memoria y no se conserva.")


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
    "Mi seguridad": render_my_security,
    "Administración": render_admin,
}

PAGE_RENDERERS[current_page]()
