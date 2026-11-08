/**
 * ==============================================================================
 * Telegram Uptime Monitor: Frontend Logic (app.js)
 * ==============================================================================
 * Автор: V1PER (viper86rus-arch)
 * GitHub: https://github.com/viper86rus-arch/Telegram_Uptime_Monitor
 * Лицензия: MIT License (2026)
 * ==============================================================================
 */

(function () {
  "use strict";

  // Инициализация Telegram WebApp SDK
  const tg = window.Telegram?.WebApp;
  if (tg) {
    tg.ready();
    tg.expand();
  }

  // Извлечение initData или fallback для тестирования в браузере
  const urlParams = new URLSearchParams(window.location.search);
  const testUserId = urlParams.get("test_user_id") || "707755583";
  const initData = tg?.initData || "";

  // Состояние приложения
  let userSites = [];
  let currentSite = null;

  // DOM Элементы
  const limitBadge = document.getElementById("limitBadge");
  const statUpCount = document.getElementById("statUpCount");
  const statDownCount = document.getElementById("statDownCount");
  const sitesList = document.getElementById("sitesList");
  const btnRefresh = document.getElementById("btnRefresh");

  // Модалка добавления
  const addModal = document.getElementById("addModal");
  const btnOpenAddModal = document.getElementById("btnOpenAddModal");
  const btnCloseAddModal = document.getElementById("btnCloseAddModal");
  const btnCancelAdd = document.getElementById("btnCancelAdd");
  const addSiteForm = document.getElementById("addSiteForm");
  const urlInput = document.getElementById("urlInput");
  const addErrorBox = document.getElementById("addErrorBox");
  const btnSubmitAdd = document.getElementById("btnSubmitAdd");

  // Модалка истории
  const historyModal = document.getElementById("historyModal");
  const btnCloseHistoryModal = document.getElementById("btnCloseHistoryModal");
  const historySiteUrl = document.getElementById("historySiteUrl");
  const historyStatusBadge = document.getElementById("historyStatusBadge");
  const historyLatency = document.getElementById("historyLatency");
  const historyStatusCode = document.getElementById("historyStatusCode");
  const historyFails = document.getElementById("historyFails");
  const historyList = document.getElementById("historyList");
  const btnCheckNow = document.getElementById("btnCheckNow");
  const btnDeleteSite = document.getElementById("btnDeleteSite");

  // ============================================================================
  // 1. СЕТЕВОЙ КЛИЕНТ API
  // ============================================================================

  async function apiRequest(endpoint, options = {}) {
    options.headers = options.headers || {};
    options.headers["Content-Type"] = "application/json";

    if (initData) {
      options.headers["Authorization"] = `tma ${initData}`;
      options.headers["X-Telegram-Init-Data"] = initData;
    } else {
      // Локальный режим разработчика вне Telegram
      const sep = endpoint.includes("?") ? "&" : "?";
      endpoint = `${endpoint}${sep}test_user_id=${testUserId}`;
    }

    try {
      const resp = await fetch(endpoint, options);
      const data = await resp.json();
      return { ok: resp.ok, status: resp.status, data };
    } catch (e) {
      return { ok: false, status: 0, data: { error: `Ошибка связи с сервером: ${e.message}` } };
    }
  }

  // ============================================================================
  // 2. ЗАГРУЗКА И ОТОБРАЖЕНИЕ САЙТОВ
  // ============================================================================

  async function loadSites() {
    sitesList.innerHTML = `
      <div class="empty-state">
        <div class="spinner"></div>
        <p>Синхронизация сайтов...</p>
      </div>
    `;

    const res = await apiRequest("/api/sites");
    if (!res.ok) {
      sitesList.innerHTML = `
        <div class="empty-state">
          <p style="color: var(--danger-color);">⚠️ ${res.data?.error || "Не удалось загрузить сайты"}</p>
          <button class="btn btn-sm btn-outline" style="margin-top: 8px;" onclick="window.location.reload()">Повторить</button>
        </div>
      `;
      return;
    }

    userSites = res.data.sites || [];
    renderSites(userSites);
    updateStats(userSites);
  }

  function updateStats(sites) {
    const up = sites.filter((s) => s.status === "UP").length;
    const down = sites.filter((s) => s.status === "DOWN").length;

    statUpCount.textContent = up;
    statDownCount.textContent = down;
    limitBadge.textContent = `${sites.length} / 5 URL`;

    // Если достигнут лимит 5 URL по ТЗ, блокируем кнопку добавления
    if (sites.length >= 5) {
      btnOpenAddModal.disabled = true;
      btnOpenAddModal.style.opacity = "0.6";
      btnOpenAddModal.title = "Достигнут максимальный лимит (5 сайтов)";
    } else {
      btnOpenAddModal.disabled = false;
      btnOpenAddModal.style.opacity = "1";
      btnOpenAddModal.title = "";
    }
  }

  function renderSites(sites) {
    if (sites.length === 0) {
      sitesList.innerHTML = `
        <div class="empty-state">
          <span style="font-size: 2rem;">🌐</span>
          <p><b>Список сайтов пуст</b></p>
          <p style="font-size: 0.75rem;">Добавьте свой первый веб-ресурс для круглосуточного мониторинга каждые 5 минут.</p>
        </div>
      `;
      return;
    }

    sitesList.innerHTML = "";
    sites.forEach((site) => {
      const card = document.createElement("div");
      card.className = "site-card";

      let badgeClass = "badge-pending";
      let badgeText = "ОЖИДАНИЕ";
      if (site.status === "UP") {
        badgeClass = "badge-up";
        badgeText = "ДОСТУПЕН";
      } else if (site.status === "DOWN") {
        badgeClass = "badge-down";
        badgeText = "СБОЙ";
      }

      const latency = site.last_response_time_ms ? `${site.last_response_time_ms} мс` : "-- мс";
      const code = site.last_status_code ? `HTTP ${site.last_status_code}` : (site.status === "DOWN" ? "Ошибка" : "--");
      const timeAgo = formatTimeAgo(site.last_checked_at);

      card.innerHTML = `
        <div class="site-card-top">
          <div class="site-url-wrap">
            <span class="site-url" title="${escapeHtml(site.url)}">${escapeHtml(site.url)}</span>
          </div>
          <span class="status-badge ${badgeClass}">${badgeText}</span>
        </div>
        <div class="site-card-bottom">
          <span>⚡ ${latency} • ${code}</span>
          <span>🕒 ${timeAgo}</span>
        </div>
      `;

      card.addEventListener("click", () => openHistoryModal(site));
      sitesList.appendChild(card);
    });
  }

  // ============================================================================
  // 3. ДОБАВЛЕНИЕ САЙТА
  // ============================================================================

  btnOpenAddModal.addEventListener("click", () => {
    if (userSites.length >= 5) {
      alert("Достигнут лимит: максимум 5 сайтов на аккаунт по ТЗ.");
      return;
    }
    urlInput.value = "";
    addErrorBox.style.display = "none";
    addModal.classList.add("active");
    setTimeout(() => urlInput.focus(), 150);
  });

  function closeAddModal() {
    addModal.classList.remove("active");
  }

  btnCloseAddModal.addEventListener("click", closeAddModal);
  btnCancelAdd.addEventListener("click", closeAddModal);

  addSiteForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    addErrorBox.style.display = "none";

    let url = urlInput.value.trim();
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = "https://" + url;
    }

    btnSubmitAdd.disabled = true;
    btnSubmitAdd.style.opacity = "0.7";

    const res = await apiRequest("/api/sites", {
      method: "POST",
      body: JSON.stringify({ url }),
    });

    btnSubmitAdd.disabled = false;
    btnSubmitAdd.style.opacity = "1";

    if (!res.ok) {
      addErrorBox.textContent = res.data?.error || "Ошибка при добавлении сайта.";
      addErrorBox.style.display = "block";
      tg?.HapticFeedback?.notificationOccurred("error");
      return;
    }

    tg?.HapticFeedback?.notificationOccurred("success");
    closeAddModal();
    await loadSites();
  });

  // ============================================================================
  // 4. ДЕТАЛИ И ИСТОРИЯ ПОСЛЕДНИХ 20 ПРОВЕРОК
  // ============================================================================

  async function openHistoryModal(site) {
    currentSite = site;
    historySiteUrl.textContent = site.url;

    updateHistoryHeader(site);
    historyList.innerHTML = `<div class="empty-state"><div class="spinner"></div><p>Загрузка истории...</p></div>`;
    historyModal.classList.add("active");

    await loadSiteHistory(site.id);
  }

  function updateHistoryHeader(site) {
    if (site.status === "UP") {
      historyStatusBadge.className = "status-badge badge-up";
      historyStatusBadge.textContent = "UP (ДОСТУПЕН)";
    } else if (site.status === "DOWN") {
      historyStatusBadge.className = "status-badge badge-down";
      historyStatusBadge.textContent = "DOWN (СБОЙ)";
    } else {
      historyStatusBadge.className = "status-badge badge-pending";
      historyStatusBadge.textContent = "PENDING";
    }

    historyLatency.textContent = site.last_response_time_ms ? `${site.last_response_time_ms} мс` : "-- мс";
    historyStatusCode.textContent = site.last_status_code ? `HTTP ${site.last_status_code}` : "--";
    historyFails.textContent = `${site.consecutive_fails || 0} / 2 сбоя`;
  }

  async function loadSiteHistory(siteId) {
    const res = await apiRequest(`/api/sites/${siteId}/history`);
    if (!res.ok) {
      historyList.innerHTML = `<div class="empty-text" style="color: var(--danger-color);">Не удалось загрузить историю проверок.</div>`;
      return;
    }

    const history = res.data.history || [];
    if (history.length === 0) {
      historyList.innerHTML = `<div class="empty-text">История ещё формируется. Проверки выполняются каждые 5 минут.</div>`;
      return;
    }

    historyList.innerHTML = "";
    history.forEach((h) => {
      const row = document.createElement("div");
      row.className = `history-row ${h.is_success ? "success" : "fail"}`;

      const date = new Date(h.checked_at * 1000);
      const timeStr = date.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      const statusIcon = h.is_success ? "🟢" : "🔴";
      const codeStr = h.status_code ? `HTTP ${h.status_code}` : (h.error_message || "Сбой");

      row.innerHTML = `
        <div class="history-left">
          <span>${statusIcon}</span>
          <span class="history-time">${timeStr}</span>
          <span class="history-code">${escapeHtml(codeStr)}</span>
        </div>
        <div>
          <b>${h.response_time_ms} мс</b>
        </div>
      `;
      historyList.appendChild(row);
    });
  }

  function closeHistoryModal() {
    historyModal.classList.remove("active");
    currentSite = null;
  }

  btnCloseHistoryModal.addEventListener("click", closeHistoryModal);

  // Мгновенная проверка по кнопке
  btnCheckNow.addEventListener("click", async () => {
    if (!currentSite) return;
    btnCheckNow.disabled = true;
    btnCheckNow.textContent = "⏳ Проверка...";

    const res = await apiRequest(`/api/sites/${currentSite.id}/check`, { method: "POST" });
    btnCheckNow.disabled = false;
    btnCheckNow.textContent = "⚡ Проверить сейчас";

    if (res.ok && res.data.site) {
      currentSite = res.data.site;
      updateHistoryHeader(currentSite);
      await loadSiteHistory(currentSite.id);
      await loadSites();
      tg?.HapticFeedback?.notificationOccurred("success");
    } else {
      alert("Ошибка при проверке: " + (res.data?.error || "Сбой связи"));
    }
  });

  // Удаление сайта
  btnDeleteSite.addEventListener("click", async () => {
    if (!currentSite) return;
    const confirmed = confirm(`Вы уверены, что хотите удалить сайт ${currentSite.url} из мониторинга?`);
    if (!confirmed) return;

    btnDeleteSite.disabled = true;
    const res = await apiRequest(`/api/sites/${currentSite.id}`, { method: "DELETE" });
    btnDeleteSite.disabled = false;

    if (res.ok) {
      tg?.HapticFeedback?.notificationOccurred("warning");
      closeHistoryModal();
      await loadSites();
    } else {
      alert("Ошибка удаления: " + (res.data?.error || "Сбой"));
    }
  });

  // Кнопка быстрого обновления
  btnRefresh.addEventListener("click", () => {
    tg?.HapticFeedback?.impactOccurred("light");
    loadSites();
  });

  // ============================================================================
  // ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
  // ============================================================================

  function formatTimeAgo(timestamp) {
    if (!timestamp) return "Ещё не проверялся";
    const diff = Math.floor(Date.now() / 1000 - timestamp);
    if (diff < 30) return "Только что";
    if (diff < 60) return `${diff} сек назад`;
    const mins = Math.floor(diff / 60);
    if (mins < 60) return `${mins} мин назад`;
    const hours = Math.floor(mins / 60);
    return `${hours} ч назад`;
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // Запуск при загрузке страницы
  loadSites();
})();
