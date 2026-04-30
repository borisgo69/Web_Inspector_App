const form = document.getElementById("inspect-form");
const targetInput = document.getElementById("target");
const statusBox = document.getElementById("status-box");
const metricsGrid = document.getElementById("metrics-grid");
const siteProfile = document.getElementById("site-profile");
const headersPanel = document.getElementById("headers-panel");
const nmapPanel = document.getElementById("nmap-panel");
const tlsPanel = document.getElementById("tls-panel");

function setStatus(message, isError = false) {
    statusBox.textContent = message;
    statusBox.style.color = isError ? "#9b1c1c" : "";
    statusBox.style.borderColor = isError ? "rgba(155, 28, 28, 0.35)" : "";
}

function createDetailItem(label, value) {
    return `
        <div class="detail-item">
            <strong>${label}</strong>
            <div>${value}</div>
        </div>
    `;
}

function renderMetrics(data) {
    const openPorts = data.nmap.open_ports?.length ?? 0;
    metricsGrid.innerHTML = `
        <article class="metric">
            <span class="metric__label">Estado</span>
            <strong class="metric__value">${data.web.status_code}</strong>
        </article>
        <article class="metric">
            <span class="metric__label">Respuesta</span>
            <strong class="metric__value">${data.web.response_time_ms} ms</strong>
        </article>
        <article class="metric">
            <span class="metric__label">Formularios</span>
            <strong class="metric__value">${data.web.forms}</strong>
        </article>
        <article class="metric">
            <span class="metric__label">Puertos abiertos</span>
            <strong class="metric__value">${openPorts}</strong>
        </article>
    `;
}

function renderSiteProfile(web) {
    const ips = (web.ip_addresses || []).map((ip) => `<span class="tag">${ip}</span>`).join("");
    siteProfile.innerHTML = `
        ${createDetailItem("Host", `<code>${web.host}</code>`)}
        ${createDetailItem("URL final", `<code>${web.final_url}</code>`)}
        ${createDetailItem("Titulo", web.title || "No encontrado")}
        ${createDetailItem("IP(s)", ips ? `<div class="tag-list">${ips}</div>` : "Sin datos")}
        ${createDetailItem("Meta generator", web.meta_generator || "No detectado")}
        ${createDetailItem("robots.txt", `<code>${web.robots_url}</code>`)}
    `;
}

function renderHeaders(web) {
    const headers = Object.entries(web.interesting_headers || {})
        .map(([key, value]) => createDetailItem(key, `<code>${value}</code>`))
        .join("");

    const observations = (web.observations || [])
        .map((item) => `<span class="tag">${item}</span>`)
        .join("");

    headersPanel.innerHTML = `
        ${headers || createDetailItem("Cabeceras", "No se han encontrado cabeceras destacadas.")}
        ${createDetailItem("Observaciones", observations ? `<div class="tag-list">${observations}</div>` : "Sin observaciones")}
    `;
}

function renderNmap(nmap) {
    if (!nmap.available) {
        nmapPanel.innerHTML = createDetailItem("Estado", nmap.message);
        return;
    }

    const ports = (nmap.open_ports || [])
        .map((port) => {
            const description = [port.service, port.product, port.version].filter(Boolean).join(" ");
            return createDetailItem(
                `${port.protocol}/${port.port}`,
                description || "Servicio no identificado"
            );
        })
        .join("");

    nmapPanel.innerHTML = `
        ${createDetailItem("Comando", `<code>${nmap.command || "N/D"}</code>`)}
        ${createDetailItem("Resumen", nmap.message || "Sin resumen")}
        ${ports || createDetailItem("Puertos", "No hay puertos abiertos en este perfil o nmap no devolvio resultados.")}
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

    tlsPanel.innerHTML = `${tlsHtml}${linkStats}`;
}

async function inspectTarget(target) {
    const response = await fetch("/api/inspect", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ target })
    });

    const data = await response.json();
    if (!response.ok || !data.ok) {
        throw new Error(data.error || "No se pudo completar la inspeccion.");
    }
    return data;
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const target = targetInput.value.trim();

    if (!target) {
        setStatus("Escribe una URL o dominio para continuar.", true);
        return;
    }

    const submitButton = form.querySelector("button");
    submitButton.disabled = true;
    setStatus(`Inspeccionando ${target}...`);

    try {
        const data = await inspectTarget(target);
        renderMetrics(data);
        renderSiteProfile(data.web);
        renderHeaders(data.web);
        renderNmap(data.nmap);
        renderTlsAndLinks(data.web);
        setStatus(`Inspeccion completada para ${data.web.final_url}`);
    } catch (error) {
        setStatus(error.message, true);
    } finally {
        submitButton.disabled = false;
    }
});
