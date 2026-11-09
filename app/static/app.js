async function api(path, opts = {}) {
    const res = await fetch(path, {
        headers: { "Content-Type": "application/json" },
        ...opts,
    });
    if (!res.ok) {
        const text = await res.text();
        throw new Error(`${res.status}: ${text}`);
    }
    return res.json();
}

// === Главная страница ===
async function loadTargets() {
    const tbody = document.querySelector("#targets-table tbody");
    if (!tbody) return;
    const targets = await api("/api/targets");
    tbody.innerHTML = targets.map(t => `
        <tr>
            <td>${t.id}</td>
            <td>${t.host}</td>
            <td>${t.ip || "—"}</td>
            <td>${new Date(t.created_at).toLocaleString()}</td>
            <td><a class="button" href="/scans/new?host=${encodeURIComponent(t.host)}">Скан</a></td>
        </tr>`).join("");
}

async function loadScans() {
    const tbody = document.querySelector("#scans-table tbody");
    if (!tbody) return;
    const scans = await api("/api/scans?limit=20");
    if (!scans.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#999">Пока нет сканов</td></tr>';
        return;
    }
    tbody.innerHTML = scans.map(s => `
        <tr>
            <td>${s.id}</td>
            <td>${s.target_host}</td>
            <td>${(s.scan_types || []).join(", ")}</td>
            <td><span class="status-${s.status}">${s.status}</span></td>
            <td>
                <a class="button" href="/scans/${s.id}">Детали</a>
                <a class="button" href="/reports/${s.id}.html" target="_blank">Отчёт</a>
            </td>
        </tr>`).join("");
}

document.querySelector("#scan-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const host = form.host.value.trim();
    const types = [...form.querySelectorAll("input[name=type]:checked")].map(c => c.value);
    if (!host) return;
    const btn = form.querySelector("button");
    const msg = document.querySelector("#form-msg");
    btn.disabled = true; msg.textContent = "Создаю скан…";
    try {
        const scan = await api("/api/scans", {
            method: "POST",
            body: JSON.stringify({ host, scan_types: types.length ? types : ["tcp"] }),
        });
        msg.textContent = `Скан #${scan.id} запущен`;
        setTimeout(() => location.href = `/scans/${scan.id}`, 500);
    } catch (err) {
        msg.textContent = "Ошибка: " + err.message;
        btn.disabled = false;
    }
});

// === Страница скана ===
async function pollScan() {
    if (!window.SCAN_ID) return;
    const s = await api(`/api/scans/${window.SCAN_ID}/status`);
    document.querySelector("#status").textContent = s.status;
    document.querySelector("#error").textContent = s.error || "—";
    document.querySelector("#findings-count").textContent = s.findings_count;
    document.querySelector("#urls-count").textContent = s.urls_count;

    if (s.status === "done") {
        const link = document.querySelector("#report-link");
        link.href = `/reports/${window.SCAN_ID}.html`;
        link.style.display = "inline-block";
        await loadFindings();
        return; // перестаём поллить
    }
    if (s.status === "failed") return;
    setTimeout(pollScan, 2000);
}

async function loadFindings() {
    const tbody = document.querySelector("#findings-table tbody");
    if (!tbody) return;
    const items = await api(`/api/findings?scan_id=${window.SCAN_ID}`);
    tbody.innerHTML = items.map(f => `
        <tr>
            <td>${f.type}</td>
            <td class="sev-${f.severity || "info"}">${f.severity || "—"}</td>
            <td>${f.title}</td>
        </tr>`).join("");
}

document.addEventListener("DOMContentLoaded", () => {
    if (document.querySelector("#targets-table")) { loadTargets(); loadScans(); }
    if (window.SCAN_ID) { pollScan(); }
});