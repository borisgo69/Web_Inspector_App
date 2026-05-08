const $ = (selector) => document.querySelector(selector);

const form = $("#inspect-form");
const targetInput = $("#target");
const statusBox = $("#status-box");
const panels = {
    metrics: $("#metrics-grid"),
    siteProfile: $("#site-profile"),
    headers: $("#headers-panel"),
    nmap: $("#nmap-panel"),
    tls: $("#tls-panel")
};

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

function createTagList(items) {
    const tags = (items || []).map((item) => `<span class="tag">${item}</span>`).join("");
    return tags ? `<div class="tag-list">${tags}</div>` : "";
}

function renderMetrics({ web, nmap }) {
    const metrics = [
        ["Estado", web.status_code],
        ["Respuesta", `${web.response_time_ms} ms`],
        ["Formularios", web.forms],
        ["Puertos abiertos", nmap.open_ports?.length ?? 0]
    ];

    panels.metrics.innerHTML = metrics
        .map(([label, value]) => `
            <article class="metric">
                <span class="metric__label">${label}</span>
                <strong class="metric__value">${value}</strong>
            </article>
        `)
        .join("");
}

function renderSiteProfile(web) {
    const ips = createTagList(web.ip_addresses);
    panels.siteProfile.innerHTML = `
        ${createDetailItem("Host", `<code>${web.host}</code>`)}
        ${createDetailItem("URL final", `<code>${web.final_url}</code>`)}
        ${createDetailItem("Titulo", web.title || "No encontrado")}
        ${createDetailItem("IP(s)", ips || "Sin datos")}
        ${createDetailItem("Meta generator", web.meta_generator || "No detectado")}
        ${createDetailItem("robots.txt", `<code>${web.robots_url}</code>`)}
    `;
}

function renderHeaders(web) {
    const headers = Object.entries(web.interesting_headers || {})
        .map(([key, value]) => createDetailItem(key, `<code>${value}</code>`))
        .join("");
    const observations = createTagList(web.observations);

    panels.headers.innerHTML = `
        ${headers || createDetailItem("Cabeceras", "No se han encontrado cabeceras destacadas.")}
        ${createDetailItem("Observaciones", observations || "Sin observaciones")}
    `;
}

function renderNmap(nmap) {
    if (!nmap.available) {
        panels.nmap.innerHTML = createDetailItem("Estado", nmap.message);
        return;
    }

    const ports = (nmap.open_ports || [])
        .map((port) => {
            const description = [port.service, port.product, port.version].filter(Boolean).join(" ");
            return createDetailItem(`${port.protocol}/${port.port}`, description || "Servicio no identificado");
        })
        .join("");

    panels.nmap.innerHTML = `
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

    const linkStats = [
        ["Enlaces internos", String(web.internal_links)],
        ["Enlaces externos", String(web.external_links)],
        ["Scripts", String(web.scripts)],
        ["Inputs password", String(web.password_inputs)],
        ["Tamano HTML", `${web.content_length} caracteres`]
    ];

    panels.tls.innerHTML = `${tlsHtml}${linkStats.map(([label, value]) => createDetailItem(label, value)).join("")}`;
}

function renderReport(data) {
    renderMetrics(data);
    renderSiteProfile(data.web);
    renderHeaders(data.web);
    renderNmap(data.nmap);
    renderTlsAndLinks(data.web);
}

async function inspectTarget(target) {
    const response = await fetch("/api/inspect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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
        renderReport(data);
        setStatus(`Inspeccion completada para ${data.web.final_url}`);
    } catch (error) {
        setStatus(error.message, true);
    } finally {
        submitButton.disabled = false;
    }
});
