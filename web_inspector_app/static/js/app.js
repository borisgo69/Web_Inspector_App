const form = document.getElementById("inspect-form");
const targetInput = document.getElementById("target");
const skipNmapInput = document.getElementById("skip-nmap");
const downloadReportButton = document.getElementById("download-report");
const statusBox = document.getElementById("status-box");
const metricsGrid = document.getElementById("metrics-grid");
const siteProfile = document.getElementById("site-profile");
const headersPanel = document.getElementById("headers-panel");
const nmapPanel = document.getElementById("nmap-panel");
const tlsPanel = document.getElementById("tls-panel");
const historyList = document.getElementById("history-list");
const commandUsed = document.getElementById("command-used");
var lastReport = null;

const SECURITY_HEADER_HELP = {
    "content-security-policy": "Ayuda a reducir ataques XSS limitando los recursos que puede cargar la pagina.",
    "strict-transport-security": "Fuerza el uso de HTTPS en futuras visitas.",
    "x-frame-options": "Ayuda a evitar que la pagina se cargue dentro de marcos maliciosos.",
    "x-content-type-options": "Evita que el navegador interprete archivos con un tipo distinto al declarado.",
    "referrer-policy": "Controla cuanta informacion de origen se envia al abrir enlaces externos."
};

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function asCode(value) {
    return `<code>${escapeHtml(value || "N/D")}</code>`;
}

function setStatus(message, isError = false) {
    statusBox.textContent = message;
    statusBox.classList.toggle("is-error", isError);
}

function createDetailItem(label, value, isHtml = false) {
    return `
        <div class="detail-item">
            <strong>${escapeHtml(label)}</strong>
            <div>${isHtml ? value : escapeHtml(value)}</div>
        </div>
    `;
}

function createTagList(items) {
    return items.map((item) => `<span class="tag">${escapeHtml(item)}</span>`).join("");
}

function getHeaderHelp(headerName) {
    return SECURITY_HEADER_HELP[String(headerName || "").toLowerCase()] || "";
}

function getObservationHelp(observation) {
    const normalized = String(observation || "").toLowerCase();
    const match = Object.keys(SECURITY_HEADER_HELP).find((headerName) => normalized.includes(headerName));
    return match ? SECURITY_HEADER_HELP[match] : "";
}

function withHelp(content, helpText) {
    const help = helpText ? `<p class="help-text">${escapeHtml(helpText)}</p>` : "";
    return `${content}${help}`;
}

function renderObservation(observation) {
    const help = getObservationHelp(observation);

    return `
        <div class="observation-item">
            <span class="tag">${escapeHtml(observation)}</span>
            ${help ? `<p class="help-text">${escapeHtml(help)}</p>` : ""}
        </div>
    `;
}

function updateDownloadButton() {
    if (downloadReportButton) {
        downloadReportButton.disabled = !lastReport;
    }
}

function extractHostFromInput(target) {
    const raw = target.trim();
    if (!raw) {
        return "";
    }

    if (!raw.includes("://")) {
        const pathless = raw.split("/")[0];
        if (pathless.includes(":") && pathless.split(":").length > 2) {
            return pathless.replace(/^\[/, "").replace(/\]$/, "");
        }
    }

    try {
        return new URL(raw.includes("://") ? raw : `http://${raw}`).hostname;
    } catch {
        return raw.split("/")[0].split(":")[0];
    }
}

function isValidIpv4(host) {
    const parts = host.split(".");
    return parts.length === 4 && parts.every((part) => {
        if (!/^\d+$/.test(part)) {
            return false;
        }

        const number = Number(part);
        return number >= 0 && number <= 255;
    });
}

function isValidDomain(host) {
    const labels = host.split(".");
    if (labels.length < 2) {
        return false;
    }

    return labels.every((label) => {
        if (!label || label.length > 63) {
            return false;
        }
        if (label.startsWith("-") || label.endsWith("-")) {
            return false;
        }
        return /^[a-z0-9-]+$/i.test(label);
    });
}

function isValidTargetFormat(target) {
    const host = extractHostFromInput(target);

    if (!host) {
        return false;
    }

    if (isValidIpv4(host)) {
        return true;
    }

    if (host.includes(":")) {
        return true;
    }

    if (host.includes(".") && /^[0-9.]+$/.test(host)) {
        return false;
    }

    return isValidDomain(host);
}

function getRiskClass(level) {
    if (level === "Bajo") {
        return "metric--success";
    }
    if (level === "Medio") {
        return "metric--warning";
    }
    if (level === "Alto") {
        return "metric--danger";
    }
    return "";
}

function renderMetrics(data) {
    const nmapExecuted = data.nmap.executed !== false;
    const openPorts = data.nmap.open_ports?.length ?? 0;
    const openPortsValue = nmapExecuted ? openPorts : "Omitido";
    const statusCode = Number(data.web.status_code);
    const statusClass = statusCode >= 200 && statusCode < 400 ? "metric--success" : "metric--danger";
    const portClass = nmapExecuted ? (openPorts > 0 ? "metric--success" : "metric--danger") : "";
    const risk = data.risk || {};
    const riskLevel = risk.level || "Sin datos";
    const riskPoints = Number.isFinite(Number(risk.points)) ? `${risk.points} puntos` : "";
    const riskClass = getRiskClass(riskLevel);

    metricsGrid.innerHTML = `
        <article class="metric ${statusClass}">
            <span class="metric__label">Estado HTTP</span>
            <strong class="metric__value">${escapeHtml(data.web.status_code)}</strong>
        </article>
        <article class="metric">
            <span class="metric__label">Respuesta</span>
            <strong class="metric__value">${escapeHtml(data.web.response_time_ms)} ms</strong>
        </article>
        <article class="metric">
            <span class="metric__label">Formularios</span>
            <strong class="metric__value">${escapeHtml(data.web.forms)}</strong>
        </article>
        <article class="metric ${portClass}">
            <span class="metric__label">Puertos abiertos</span>
            <strong class="metric__value">${escapeHtml(openPortsValue)}</strong>
        </article>
        <article class="metric ${riskClass}">
            <span class="metric__label">Riesgo</span>
            <strong class="metric__value">${escapeHtml(riskLevel)}</strong>
            ${riskPoints ? `<span class="metric__note">${escapeHtml(riskPoints)}</span>` : ""}
        </article>
    `;
}

function renderSiteProfile(web) {
    const ips = createTagList(web.ip_addresses || []);
    siteProfile.classList.remove("empty-state");
    siteProfile.innerHTML = `
        ${createDetailItem("Host", asCode(web.host), true)}
        ${createDetailItem("URL final", asCode(web.final_url), true)}
        ${createDetailItem("Titulo", web.title || "No encontrado")}
        ${createDetailItem("IP(s)", ips ? `<div class="tag-list">${ips}</div>` : "Sin datos", Boolean(ips))}
        ${createDetailItem("Meta generator", web.meta_generator || "No detectado")}
        ${createDetailItem("robots.txt", asCode(web.robots_url), true)}
    `;
}

function renderHeaders(web) {
    const headers = Object.entries(web.interesting_headers || {})
        .map(([key, value]) => createDetailItem(key, withHelp(asCode(value), getHeaderHelp(key)), true))
        .join("");

    const observations = (web.observations || []).map(renderObservation).join("");
    headersPanel.classList.remove("empty-state");
    headersPanel.innerHTML = `
        ${headers || createDetailItem("Cabeceras", "No se han encontrado cabeceras destacadas.")}
        ${createDetailItem("Observaciones", observations ? `<div class="observation-list">${observations}</div>` : "Sin observaciones", Boolean(observations))}
    `;
}

function getStateText(state) {
    const labels = {
        open: "Abierto",
        closed: "Cerrado",
        filtered: "Filtrado",
        unknown: "Desconocido"
    };
    return labels[state] || state;
}

function getStateClass(state) {
    if (state === "open") {
        return "open";
    }
    if (state === "closed") {
        return "closed";
    }
    return "filtered";
}

function renderPortRow(port) {
    const description = [port.service, port.product, port.version].filter(Boolean).join(" ");
    const stateClass = getStateClass(port.state);

    return `
        <div class="port-row port-row--${stateClass}">
            <span class="port-row__name">${escapeHtml(port.protocol)}/${escapeHtml(port.port)}</span>
            <span class="port-row__service">${escapeHtml(description || "Servicio no identificado")}</span>
            <span class="state-pill state-pill--${stateClass}">${escapeHtml(getStateText(port.state))}</span>
        </div>
    `;
}

function updateCommand(command) {
    commandUsed.innerHTML = `Comando: ${asCode(command || "pendiente")}`;
}

function renderNmap(nmap) {
    updateCommand(nmap.command || "no ejecutado");
    nmapPanel.classList.remove("empty-state");

    if (nmap.executed === false) {
        nmapPanel.innerHTML = createDetailItem("Estado", nmap.message || "Escaneo nmap no ejecutado.");
        return;
    }

    if (!nmap.available) {
        nmapPanel.innerHTML = createDetailItem("Estado", nmap.message || "Nmap no disponible.");
        return;
    }

    const scannedPorts = nmap.scanned_ports?.length
        ? nmap.scanned_ports
        : (nmap.open_ports || []).map((port) => ({ ...port, state: "open" }));

    const portsHtml = scannedPorts.length
        ? `<div class="ports-list">${scannedPorts.map(renderPortRow).join("")}</div>`
        : createDetailItem(
              "Puertos",
              '<span class="state-pill state-pill--closed">Cerrado</span> No hay puertos abiertos en este perfil.',
              true
          );

    nmapPanel.innerHTML = `
        ${createDetailItem("Resumen", nmap.message || "Sin resumen")}
        ${portsHtml}
    `;
}

function renderTlsAndLinks(web) {
    const tlsHtml = web.tls
        ? Object.entries(web.tls)
              .map(([key, value]) => createDetailItem(key, value || "Sin dato"))
              .join("")
        : createDetailItem("TLS", "No aplica o no se han podido extraer datos TLS.");

    const linkStats = `
        ${createDetailItem("Enlaces internos", String(web.internal_links))}
        ${createDetailItem("Enlaces externos", String(web.external_links))}
        ${createDetailItem("Scripts", String(web.scripts))}
        ${createDetailItem("Inputs password", String(web.password_inputs))}
        ${createDetailItem("Tamano HTML", `${web.content_length} caracteres`)}
    `;

    tlsPanel.classList.remove("empty-state");
    tlsPanel.innerHTML = `${tlsHtml}${linkStats}`;
}

function formatDate(dateValue) {
    if (!dateValue) {
        return "Fecha no disponible";
    }

    return new Date(dateValue).toLocaleString("es-ES", {
        dateStyle: "short",
        timeStyle: "short"
    });
}

function renderHistory(history) {
    if (!history || history.length === 0) {
        historyList.classList.add("empty-state");
        historyList.textContent = "Sin escaneos guardados.";
        return;
    }

    historyList.classList.remove("empty-state");
    historyList.innerHTML = history
        .map((entry) => {
            const openPorts = Number(entry.open_ports || 0);
            const stateClass = openPorts > 0 ? "open" : "closed";

            return `
                <article class="history-item">
                    <div class="history-item__top">
                        <span class="history-item__target">${escapeHtml(entry.host || entry.target)}</span>
                        <span class="state-pill state-pill--${stateClass}">${openPorts} abiertos</span>
                    </div>
                    <div class="history-item__meta">
                        <span>${escapeHtml(formatDate(entry.generated_at))}</span>
                        <span>HTTP ${escapeHtml(entry.status_code || "N/D")}</span>
                        <span>${escapeHtml(entry.response_time_ms || "N/D")} ms</span>
                    </div>
                </article>
            `;
        })
        .join("");
}

function renderReport(data) {
    lastReport = data;
    updateDownloadButton();
    renderMetrics(data);
    renderSiteProfile(data.web);
    renderHeaders(data.web);
    renderNmap(data.nmap);
    renderTlsAndLinks(data.web);
    renderHistory(data.history);
}

async function inspectTarget(target, skipNmap) {
    const response = await fetch("/api/inspect", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ target, skip_nmap: skipNmap })
    });

    const data = await response.json();
    if (!response.ok || !data.ok) {
        throw new Error(data.error || "No se pudo completar la inspeccion.");
    }
    return data;
}

async function loadHistory() {
    try {
        const response = await fetch("/api/history");
        const data = await response.json();

        if (response.ok && data.ok) {
            renderHistory(data.history);
        }
    } catch {
        historyList.textContent = "No se ha podido cargar el historial.";
    }
}

if (downloadReportButton) {
    downloadReportButton.addEventListener("click", () => {
        if (!lastReport) {
            return;
        }

        const blob = new Blob([JSON.stringify(lastReport, null, 2)], {
            type: "application/json"
        });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = "web-inspector-report.json";
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 0);
    });
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const target = targetInput.value.trim();

    if (!target) {
        setStatus("Escribe una IP, URL o dominio para continuar.", true);
        return;
    }

    if (!isValidTargetFormat(target)) {
        setStatus("Introduce una IP, dominio o URL validos.", true);
        return;
    }

    const submitButton = form.querySelector('button[type="submit"]');
    const originalButtonText = submitButton.textContent;
    const skipNmap = Boolean(skipNmapInput?.checked);
    submitButton.disabled = true;
    submitButton.textContent = "Analizando...";
    submitButton.classList.add("is-loading");
    setStatus(`Analizando ${target}...`);

    try {
        const data = await inspectTarget(target, skipNmap);
        renderReport(data);
        setStatus(`Analisis completado para ${data.web.final_url}`);
    } catch (error) {
        setStatus(error.message, true);
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = originalButtonText;
        submitButton.classList.remove("is-loading");
    }
});

updateDownloadButton();
loadHistory();
