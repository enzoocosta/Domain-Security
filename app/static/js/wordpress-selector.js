(function () {
  var panelsRoot = document.getElementById("wordpress-profile-panels");
  var profileGrid =
    document.getElementById("secao-escolha") ||
    document.querySelector("[data-profile-grid]");
  var commonBlock = document.getElementById("bloco-comum");
  var technicalBlock = document.getElementById("bloco-tecnico");
  var options = Array.prototype.slice.call(
    document.querySelectorAll("[data-profile-option]")
  );
  var resetButtons = Array.prototype.slice.call(
    document.querySelectorAll("[data-profile-reset]")
  );

  if (!panelsRoot || !options.length) {
    return;
  }

  var commonForm = document.querySelector("[data-wp-common-form]");
  var commonResults = document.querySelector("[data-wp-common-results]");
  var commonLoading = document.querySelector("[data-wp-common-loading]");
  var commonProgressLabel = document.querySelector("[data-wp-common-progress-label]");
  var commonProgressBar = document.querySelector("[data-wp-common-progress-bar]");
  var commonAlert = document.querySelector("[data-wp-common-alert]");
  var commonContent = document.querySelector("[data-wp-common-content]");
  var commonSite = document.querySelector("[data-wp-common-site]");
  var commonCardList = document.querySelector("[data-wp-common-card-list]");
  var commonSummary = document.querySelector("[data-wp-common-summary]");

  var techForm = document.querySelector("[data-wp-tech-form]");
  var techResults = document.querySelector("[data-wp-tech-results]");
  var techLoading = document.querySelector("[data-wp-tech-loading]");
  var techPhaseLabel = document.querySelector("[data-wp-tech-phase-label]");
  var techProgressLabel = document.querySelector("[data-wp-tech-progress-label]");
  var techProgressBar = document.querySelector("[data-wp-tech-progress-bar]");
  var techAlert = document.querySelector("[data-wp-tech-alert]");
  var techContent = document.querySelector("[data-wp-tech-content]");
  var techSite = document.querySelector("[data-wp-tech-site-label]");
  var techSummaryLine = document.querySelector("[data-wp-tech-summary-line]");
  var techOverview = document.querySelector("[data-wp-tech-overview]");
  var techTopVulnerabilities = document.querySelector("[data-wp-tech-top-vulnerabilities]");
  var techLoader = document.querySelector("[data-wp-tech-loader]");
  var techStepList = document.querySelector("[data-wp-tech-step-list]");
  var techCompleteTitle = document.querySelector("[data-wp-tech-complete-title]");
  var techCompleteCopy = document.querySelector("[data-wp-tech-complete-copy]");
  var techCompleteItems = document.querySelector("[data-wp-tech-complete-items]");
  var techCompleteVulnerabilities = document.querySelector(
    "[data-wp-tech-complete-vulnerabilities]"
  );
  var techCompleteScore = document.querySelector("[data-wp-tech-complete-score]");
  var exportPdfButton = document.querySelector("[data-wp-export-pdf]");
  var copyJsonButton = document.querySelector("[data-wp-copy-json]");
  var clientReportButton = document.querySelector("[data-wp-generate-client-report]");
  var openTechnicalReportButton = document.querySelector(
    "[data-wp-open-technical-report]"
  );

  var backdrop = document.querySelector("[data-wp-modal-backdrop]");
  var modalTitle = document.querySelector("[data-wp-modal-title]");
  var modalLead = document.querySelector("[data-wp-modal-lead]");
  var modalSteps = document.querySelector("[data-wp-modal-steps]");
  var closeButtons = Array.prototype.slice.call(
    document.querySelectorAll("[data-wp-modal-close]")
  );

  var lastAnalysis = null;
  var currentProfile = null;
  var PROFILE_STORAGE_KEY = "dsc-wordpress-profile";
  var TECHNICAL_REPORT_STORAGE_KEY = "dsc-wordpress-technical-report";

  function getPanels() {
    return Array.prototype.slice.call(
      document.querySelectorAll("[data-profile-panel]")
    );
  }

  function animateElement(element, className) {
    if (!element) {
      return;
    }
    element.classList.remove(className);
    window.requestAnimationFrame(function () {
      element.classList.add(className);
    });
  }

  function showElement(element) {
    if (!element) {
      return;
    }
    element.hidden = false;
    element.style.display = "";
  }

  function hideElement(element) {
    if (!element) {
      return;
    }
    element.hidden = true;
    element.style.display = "none";
  }

  function setPanelVisibility(profile) {
    if (profile === "common" || profile === "technical") {
      panelsRoot.setAttribute("data-active-profile", profile);
    } else {
      panelsRoot.removeAttribute("data-active-profile");
    }

    if (profile === "common") {
      hideElement(profileGrid);
      hideElement(technicalBlock);
      showElement(commonBlock);
      showElement(panelsRoot);
      panelsRoot.setAttribute("aria-hidden", "false");
      return;
    }

    if (profile === "technical") {
      hideElement(profileGrid);
      hideElement(commonBlock);
      showElement(technicalBlock);
      showElement(panelsRoot);
      panelsRoot.setAttribute("aria-hidden", "false");
      return;
    }

    showElement(profileGrid);
    hideElement(commonBlock);
    hideElement(technicalBlock);
    hideElement(panelsRoot);
    panelsRoot.setAttribute("aria-hidden", "true");
  }

  function resetProfileSelection() {
    currentProfile = null;
    try {
      window.localStorage.removeItem(PROFILE_STORAGE_KEY);
    } catch (error) {
      // Ignore storage failures; the visible state is still reset.
    }
    options.forEach(function (option) {
      option.hidden = false;
      option.style.display = "";
      option.setAttribute("aria-pressed", "false");
    });

    setPanelVisibility(null);
  }

  function setActiveProfile(profile) {
    if (profile !== "common" && profile !== "technical") {
      resetProfileSelection();
      return;
    }

    currentProfile = profile;
    options.forEach(function (option) {
      var isSelected = option.getAttribute("data-profile-target") === profile;
      option.setAttribute("aria-pressed", String(isSelected));
    });

    setPanelVisibility(profile);
    try {
      window.localStorage.setItem(PROFILE_STORAGE_KEY, profile);
    } catch (error) {
      // Ignore storage failures; the selected profile remains active in this session.
    }
    animateElement(panelsRoot, "is-visible");
  }

  function normalizeDomain(value) {
    return String(value || "").trim();
  }

  function escapeHtml(value) {
    return String(value || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function formatSeverityLabel(severity) {
    return {
      critical: "Critical",
      high: "High",
      medium: "Medium",
      low: "Low",
    }[severity] || "Info";
  }

  function severityRank(severity) {
    return {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
    }[severity] || 0;
  }

  function cvssSeverity(cvssScore, severity) {
    var score = Number(cvssScore);
    if (!Number.isNaN(score)) {
      if (score >= 9) {
        return "critical";
      }
      if (score >= 7) {
        return "high";
      }
      if (score >= 4) {
        return "medium";
      }
      return "low";
    }
    return severity || "low";
  }

  function formatTipo(tipo) {
    return {
      core: "Core",
      plugin: "Plugin",
      tema: "Tema",
    }[tipo] || tipo;
  }

  function formatClassificacao(classificacao) {
    return {
      seguro: {
        tone: "good",
        signal: "SEGURO",
        title: "Seguro",
        text: "Nao encontramos falhas conhecidas nos itens identificados.",
      },
      atencao: {
        tone: "warning",
        signal: "ATENCAO",
        title: "Atencao",
        text: "Existem pontos que merecem correcao ou revisao.",
      },
      em_risco: {
        tone: "danger",
        signal: "RISCO",
        title: "Em risco",
        text: "Encontramos falhas relevantes e o site precisa de tratamento tecnico.",
      },
    }[classificacao] || {
      tone: "warning",
      signal: "ANALISE",
      title: "Analise concluida",
      text: "",
    };
  }

  function positiveSignals(data) {
    var detection = data && data.detection ? data.detection : null;
    if (!detection || !detection.signals) {
      return [];
    }
    return detection.signals.filter(function (signal) {
      return signal.detected;
    });
  }

  function positiveSignalNames(data) {
    return positiveSignals(data).map(function (signal) {
      return signal.name;
    });
  }

  function persistTechnicalReport(data) {
    if (!data || !window.localStorage) {
      return;
    }

    try {
      window.localStorage.setItem(
        TECHNICAL_REPORT_STORAGE_KEY,
        JSON.stringify({
          savedAt: new Date().toISOString(),
          analysis: data,
        })
      );
    } catch (error) {
      return;
    }
  }

  function openTechnicalReport(options) {
    if (!lastAnalysis) {
      return;
    }

    persistTechnicalReport(lastAnalysis);
    var url = "/wordpress/relatorio-tecnico";
    if (options && options.print) {
      url += "?print=1";
    }
    window.location.href = url;
  }

  function setAlert(element, tone, text) {
    if (!element) {
      return;
    }
    if (!text) {
      element.hidden = true;
      element.className = "wp-scan-alert";
      element.textContent = "";
      return;
    }
    element.hidden = false;
    element.className = "wp-scan-alert wp-scan-alert--" + tone;
    element.textContent = text;
  }

  function summaryMetrics(summary) {
    return [
      ["Itens analisados", summary.totalItemsAnalisados],
      ["Criticas", summary.vulnerabilidadesPorSeveridade.critical || 0],
      ["Altas", summary.vulnerabilidadesPorSeveridade.high || 0],
      ["Score", summary.scoreGeral],
    ];
  }

  function commonCopyForItem(item) {
    if (item.status === "seguro") {
      return {
        icon: "OK",
        tone: "good",
        title:
          item.tipo === "core"
            ? "Parte principal do WordPress sem falhas conhecidas"
            : item.tipo === "plugin"
              ? "Plugin sem falhas conhecidas"
              : "Tema sem falhas conhecidas",
        text:
          item.tipo === "core"
            ? "A parte principal do seu site nao mostrou falhas conhecidas nesta verificacao publica."
            : "Este componente nao mostrou falhas conhecidas na base consultada. Ainda assim, vale manter tudo atualizado.",
      };
    }

    if (item.status === "nao_detectado") {
      return {
        icon: "!",
        tone: "warning",
        title: "Nao conseguimos confirmar todos os detalhes",
        text:
          item.tipo === "core"
            ? "Nao conseguimos identificar a versao do WordPress. Isso pode ser bom, porque esconder a versao ajuda na seguranca."
            : "Encontramos sinais deste componente, mas nao deu para confirmar a versao exata. Peca para o tecnico revisar manualmente.",
      };
    }

    return {
      icon: item.status === "critico" ? "X" : "!",
      tone: item.status === "critico" ? "danger" : "warning",
      title:
        item.tipo === "core"
          ? "WordPress desatualizado com risco conhecido"
          : item.tipo === "plugin"
            ? "Plugin desatualizado com risco de invasao"
            : "Tema com falha conhecida",
      text:
        "Este componente do seu site tem uma falha conhecida. O melhor caminho e pedir para o responsavel tecnico atualizar ou substituir essa parte.",
    };
  }

  function helpContentForItem(item) {
    var title =
      item.tipo === "core"
        ? "Como cuidar da parte principal do WordPress"
        : item.tipo === "plugin"
          ? "Como cuidar melhor desse plugin"
          : "Como revisar o tema do site";

    return {
      title: title,
      lead:
        "Voce nao precisa resolver isso sozinho. O melhor caminho e repassar um pedido claro para quem cuida do site.",
      steps: [
        "Envie o nome do item encontrado para o tecnico ou agencia responsavel.",
        "Peca para revisar atualizacao, compatibilidade e copia de seguranca antes de qualquer mudanca.",
        "Se o componente estiver velho ou sem manutencao, pergunte se existe uma alternativa mais segura.",
        "Depois da correcao, rode esta verificacao novamente para confirmar.",
      ],
    };
  }

  function openModal(itemPayload) {
    if (!backdrop || !modalTitle || !modalLead || !modalSteps) {
      return;
    }

    var item = null;
    try {
      item = JSON.parse(itemPayload);
    } catch (error) {
      return;
    }

    var help = helpContentForItem(item);
    modalTitle.textContent = help.title;
    modalLead.textContent = help.lead;
    modalSteps.innerHTML = help.steps
      .map(function (step) {
        return "<li>" + escapeHtml(step) + "</li>";
      })
      .join("");
    backdrop.hidden = false;
  }

  function closeModal() {
    if (backdrop) {
      backdrop.hidden = true;
    }
  }

  function wireModalTriggers(root) {
    if (!root) {
      return;
    }

    Array.prototype.slice
      .call(root.querySelectorAll("[data-help-item]"))
      .forEach(function (button) {
        button.addEventListener("click", function () {
          openModal(button.getAttribute("data-help-item"));
        });
      });
  }

  function renderSummary(root, summary, actions) {
    if (!root) {
      return;
    }

    var state = formatClassificacao(summary.classificacao);
    root.className = "wp-summary wp-summary--" + state.tone;
    root.innerHTML =
      '<div class="wp-summary__header">' +
      '<span class="wp-summary__signal">' + state.signal + "</span>" +
      "<div>" +
      "<h4>" + state.title + "</h4>" +
      "<p>" + state.text + "</p>" +
      "</div>" +
      "</div>" +
      '<div class="wp-summary__metrics">' +
      summaryMetrics(summary)
        .map(function (metric) {
          return (
            '<article class="wp-summary__metric">' +
            "<span>" + metric[0] + "</span>" +
            "<strong>" + metric[1] + "</strong>" +
            "</article>"
          );
        })
        .join("") +
      "</div>" +
      '<div class="wp-summary__actions">' + actions + "</div>";
  }

  function renderCommon(data) {
    lastAnalysis = data;
    showElement(commonResults);
    hideElement(commonLoading);
    showElement(commonContent);
    setAlert(commonAlert, "info", "");

    commonSite.textContent = "Resumo publico para " + data.scannedUrl;

    if (!data.siteConfirmed) {
      setAlert(
        commonAlert,
        "warning",
        "Nao foi possivel confirmar que este site utiliza WordPress. Verifique a URL e tente novamente."
      );
      hideElement(commonContent);
      return;
    }

    if (data.detection && data.detection.versionHidden) {
      setAlert(
        commonAlert,
        "success",
        "Seu site usa WordPress e esta com a versao escondida. Isso e otimo. E como nao colocar o modelo da fechadura na porta de casa."
      );
    } else if (data.warnings.length) {
      setAlert(commonAlert, "info", data.warnings.join(" "));
    }

    var cardsMarkup = data.items
      .map(function (item) {
        var copy = commonCopyForItem(item);
        var itemPayload = escapeHtml(JSON.stringify(item));
        return (
          '<article class="wp-result-card wp-result-card--' +
          copy.tone +
          '">' +
          '<div class="wp-result-card__header">' +
          '<span class="wp-result-card__icon">' + copy.icon + "</span>" +
          "<div>" +
          "<h4>" + escapeHtml(copy.title) + "</h4>" +
          '<p class="wp-result-card__status">' + escapeHtml(item.nome) + "</p>" +
          "</div>" +
          "</div>" +
          '<p class="wp-result-card__copy">' + escapeHtml(copy.text) + "</p>" +
          '<div class="wp-result-card__actions">' +
          '<button type="button" class="button button--secondary button--small" data-help-item="' + itemPayload + '">O que fazer?</button>' +
          "</div>" +
          "</article>"
        );
      })
      .join("");

    if (data.detection && data.detection.versionHidden) {
      cardsMarkup =
        '<article class="wp-result-card wp-result-card--good">' +
        '<div class="wp-result-card__header">' +
        '<span class="wp-result-card__icon">OK</span>' +
        "<div>" +
        "<h4>Versao do WordPress escondida</h4>" +
        '<p class="wp-result-card__status">Boa pratica de seguranca</p>' +
        "</div>" +
        "</div>" +
        '<p class="wp-result-card__copy">Detectamos WordPress por outros sinais, mas a versao nao esta exposta publicamente. Isso reduz pistas para pessoas mal-intencionadas.</p>' +
        "</article>" +
        cardsMarkup;
    }

    commonCardList.innerHTML = cardsMarkup;

    renderSummary(
      commonSummary,
      data.summary,
      '<button type="button" class="button button--secondary button--small" data-export-report="common">Exportar relatorio PDF</button>' +
        '<button type="button" class="button button--ghost button--small" data-reset-analysis="common">Verificar outro site</button>'
    );

    wireModalTriggers(commonCardList);
    animateElement(commonContent, "is-visible");
  }

  function renderTechnicalOverview(summary) {
    techOverview.innerHTML = [
      ["Itens analisados", summary.totalItemsAnalisados],
      ["Criticas", summary.vulnerabilidadesPorSeveridade.critical || 0],
      ["Altas", summary.vulnerabilidadesPorSeveridade.high || 0],
      ["Score de seguranca", summary.scoreGeral],
    ]
      .map(function (metric) {
        return (
          '<article class="wp-tech-metric">' +
          '<span class="wp-tech-metric__label">' + metric[0] + "</span>" +
          '<strong class="wp-tech-metric__value">' + metric[1] + "</strong>" +
          "</article>"
        );
      })
      .join("");
  }

  function technicalCompletionContent(data) {
    var summary = data && data.summary ? data.summary : {};
    var totalItems = summary.totalItemsAnalisados || 0;
    var totalVulnerabilities = summary.totalVulnerabilidades || 0;
    var score = summary.scoreGeral || 0;

    if (data && data.siteConfirmed === false) {
      return {
        title: "Analise encerrada com ressalvas",
        copy:
          "A captura terminou, mas o alvo nao confirmou WordPress com seguranca. Revisando sinais coletados antes de exibir o alerta final.",
        items: totalItems + " itens verificados",
        vulnerabilities: totalVulnerabilities + " achados correlacionados",
        score: "Score " + score,
      };
    }

    if (totalVulnerabilities > 0) {
      return {
        title: "Mapa tecnico consolidado",
        copy:
          "Cruzando componentes detectados com a base de vulnerabilidades e montando a prioridade tecnica da resposta.",
        items: totalItems + " itens mapeados",
        vulnerabilities: totalVulnerabilities + " vulnerabilidades",
        score: "Score " + score,
      };
    }

    return {
      title: "Superficie validada com sucesso",
      copy:
        "Nenhuma vulnerabilidade conhecida entrou na fila critica. Finalizando os indicadores para exibir o resultado tecnico completo.",
      items: totalItems + " itens mapeados",
      vulnerabilities: totalVulnerabilities + " vulnerabilidades",
      score: "Score " + score,
    };
  }

  function renderTechnicalStepList(steps, activeIndex) {
    if (!techStepList) {
      return;
    }

    var safeSteps = steps && steps.length ? steps : ["Iniciando analise..."];
    var currentIndex = Math.max(0, Math.min(activeIndex || 0, safeSteps.length - 1));

    techStepList.innerHTML = safeSteps
      .map(function (step, index) {
        var state = "pending";
        var stateLabel = "Na fila";

        if (index < currentIndex) {
          state = "done";
          stateLabel = "Concluida";
        } else if (index === currentIndex) {
          state = "active";
          stateLabel = "Em execucao";
        }

        return (
          '<article class="wp-tech-loader__step wp-tech-loader__step--' +
          state +
          '">' +
          '<span class="wp-tech-loader__step-index">' +
          escapeHtml(String(index + 1).padStart(2, "0")) +
          "</span>" +
          '<div class="wp-tech-loader__step-copy">' +
          "<strong>" +
          escapeHtml(step) +
          "</strong>" +
          "<span>" +
          stateLabel +
          "</span>" +
          "</div>" +
          '<span class="wp-tech-loader__step-signal" aria-hidden="true"></span>' +
          "</article>"
        );
      })
      .join("");
  }

  function setTechnicalLoadingState(state, data) {
    if (!techLoader) {
      return;
    }

    techLoader.setAttribute("data-state", state);

    if (state === "loading") {
      var loadingSteps = data && data.steps ? data.steps : [];
      renderTechnicalStepList(loadingSteps, data && data.activeIndex ? data.activeIndex : 0);
      if (techPhaseLabel) {
        techPhaseLabel.textContent = "Analise tecnica em andamento";
      }
      return;
    }

    if (state === "complete") {
      var completion = technicalCompletionContent(data || {});
      if (techPhaseLabel) {
        techPhaseLabel.textContent = "Analise tecnica concluida";
      }
      if (techCompleteTitle) {
        techCompleteTitle.textContent = completion.title;
      }
      if (techCompleteCopy) {
        techCompleteCopy.textContent = completion.copy;
      }
      if (techCompleteItems) {
        techCompleteItems.textContent = completion.items;
      }
      if (techCompleteVulnerabilities) {
        techCompleteVulnerabilities.textContent = completion.vulnerabilities;
      }
      if (techCompleteScore) {
        techCompleteScore.textContent = completion.score;
      }
    }
  }

  function topVulnerabilityRows(data) {
    var rows = [];

    data.items.forEach(function (item) {
      item.vulnerabilidades.forEach(function (vulnerability) {
        rows.push({
          item: item,
          vulnerability: vulnerability,
        });
      });
    });

    rows.sort(function (left, right) {
      var severityDelta =
        severityRank(right.vulnerability.severidade) -
        severityRank(left.vulnerability.severidade);

      if (severityDelta !== 0) {
        return severityDelta;
      }

      return (right.vulnerability.cvssScore || 0) - (left.vulnerability.cvssScore || 0);
    });

    return rows.slice(0, 5);
  }

  function renderTopVulnerabilities(data) {
    if (!techTopVulnerabilities) {
      return;
    }

    var rows = topVulnerabilityRows(data);

    if (!rows.length) {
      techTopVulnerabilities.innerHTML =
        '<article class="wp-tech-vulnerability-empty">' +
        '<strong>Nenhuma vulnerabilidade conhecida encontrada</strong>' +
        '<p>Os componentes identificados nao apresentaram CVEs conhecidas na base consultada. Mantenha monitoramento e atualizacoes recorrentes.</p>' +
        "</article>";
      return;
    }

    techTopVulnerabilities.innerHTML = rows
      .map(function (row) {
        var item = row.item;
        var vulnerability = row.vulnerability;
        var severity = cvssSeverity(vulnerability.cvssScore, vulnerability.severidade);
        var cve = vulnerability.cve || vulnerability.id || "N/D";
        var fixedVersion = vulnerability.corrigidoNaVersao || "N/D";
        var detectedVersion = item.versaoDetectada || "N/D";
        return (
          '<article class="wp-tech-vuln-card wp-tech-vuln-card--' + escapeHtml(severity) + '">' +
          '<div class="wp-tech-vuln-card__header">' +
          "<div>" +
          '<p class="wp-tech-vuln-card__item">' + escapeHtml(formatTipo(item.tipo)) + " afetado</p>" +
          "<h5>" + escapeHtml(item.nome) + "</h5>" +
          "</div>" +
          '<span class="wp-tech-vuln-card__badge wp-tech-vuln-card__badge--' + escapeHtml(severity) + '">' +
          escapeHtml(formatSeverityLabel(vulnerability.severidade)) +
          "</span>" +
          "</div>" +
          '<p class="wp-tech-vuln-card__title">' + escapeHtml(vulnerability.titulo) + "</p>" +
          '<div class="wp-tech-vuln-card__facts">' +
          '<span><strong>CVE</strong>' + escapeHtml(cve) + "</span>" +
          '<span><strong>CVSS</strong><mark class="wp-tech-cvss wp-tech-cvss--' + escapeHtml(severity) + '">' + escapeHtml(vulnerability.cvssScore != null ? String(vulnerability.cvssScore) : "N/D") + "</mark></span>" +
          '<span><strong>Severidade</strong>' + escapeHtml(formatSeverityLabel(vulnerability.severidade)) + "</span>" +
          '<span><strong>Versao afetada</strong>' + escapeHtml(detectedVersion) + "</span>" +
          '<span><strong>Versao corrigida</strong>' + escapeHtml(fixedVersion) + "</span>" +
          '<span><strong>Status</strong><em class="wp-tech-status wp-tech-status--' + statusTone(item.status) + '">' + escapeHtml(item.status === "critico" ? "CRITICO" : "SEGURO") + "</em></span>" +
          "</div>" +
          "</article>"
        );
      })
      .join("");
  }

  function renderTechnical(data) {
    lastAnalysis = data;
    persistTechnicalReport(data);
    showElement(techResults);
    hideElement(techLoading);
    showElement(techContent);
    setAlert(techAlert, "info", "");

    techSite.textContent = data.scannedUrl;
    var signalNames = positiveSignalNames(data);
    techSummaryLine.textContent =
      "Deteccao: " +
      (data.detection ? data.detection.confidence : "n/d") +
      " | Itens analisados: " +
      data.summary.totalItemsAnalisados +
      " | Vulnerabilidades: " +
      data.summary.totalVulnerabilidades +
      " | Cache: " +
      (data.cacheHit ? "sim" : "nao");

    if (!data.siteConfirmed) {
      setAlert(
        techAlert,
        "warning",
        "Nao foi possivel confirmar que este site utiliza WordPress. Verifique a URL e tente novamente."
      );
      hideElement(techContent);
      return;
    }

    if (data.detection && data.detection.versionHidden) {
      setAlert(
        techAlert,
        "info",
        "WordPress detectado via " +
          signalNames.join(", ") +
          ". Versao nao exposta publicamente. Boa pratica de hardening aplicada."
      );
    } else if (data.warnings.length) {
      setAlert(techAlert, "info", data.warnings.join(" "));
    }

    renderTechnicalOverview(data.summary);
    renderTopVulnerabilities(data);
    animateElement(techContent, "is-visible");
  }

  function statusTone(status) {
    return {
      seguro: "good",
      atencao: "warning",
      critico: "danger",
      nao_detectado: "info",
    }[status] || "info";
  }

  function startProgress(steps, labelElement, barElement, options) {
    var safeSteps = steps.length ? steps : ["Iniciando analise..."];
    var index = 0;
    var progress = 8;
    var onUpdate = options && typeof options.onUpdate === "function"
      ? options.onUpdate
      : null;
    var onStop = options && typeof options.onStop === "function"
      ? options.onStop
      : null;

    if (labelElement) {
      labelElement.textContent = safeSteps[0];
    }
    if (barElement) {
      barElement.style.width = "12%";
    }
    if (onUpdate) {
      onUpdate({
        steps: safeSteps,
        activeIndex: 0,
        label: safeSteps[0],
        progress: 12,
      });
    }

    var intervalId = window.setInterval(function () {
      index = Math.min(index + 1, safeSteps.length - 1);
      progress = Math.min(progress + 18, 88);
      if (labelElement) {
        labelElement.textContent = safeSteps[index];
      }
      if (barElement) {
        barElement.style.width = progress + "%";
      }
      if (onUpdate) {
        onUpdate({
          steps: safeSteps,
          activeIndex: index,
          label: safeSteps[index],
          progress: progress,
        });
      }
    }, 650);

    return function stopProgress(finalLabel) {
      window.clearInterval(intervalId);
      if (labelElement && finalLabel) {
        labelElement.textContent = finalLabel;
      }
      if (barElement) {
        barElement.style.width = "100%";
      }
      if (onStop) {
        onStop({
          steps: safeSteps,
          activeIndex: safeSteps.length - 1,
          label: finalLabel || safeSteps[safeSteps.length - 1],
          progress: 100,
        });
      }
    };
  }

  function fetchAnalysis(url, options) {
    return window.fetch("/api/v1/wordpress/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: url,
        options: options,
      }),
    }).then(function (response) {
      return response.json().then(function (payload) {
        if (!response.ok) {
          throw new Error(payload.detail || "Nao foi possivel concluir a analise.");
        }
        return payload;
      });
    });
  }

  function buildExportDocument(data, mode) {
    var rows = []
      .concat.apply(
        [],
        data.items.map(function (item) {
          if (!item.vulnerabilidades.length) {
            return [
              {
                item: item,
                vulnerability: null,
              },
            ];
          }

          return item.vulnerabilidades.map(function (vulnerability) {
            return {
              item: item,
              vulnerability: vulnerability,
            };
          });
        })
      )
      .map(function (row) {
        var item = row.item;
        var vulnerability = row.vulnerability;
        return (
          "<tr>" +
          "<td>" + escapeHtml(item.nome) + "</td>" +
          "<td>" + escapeHtml(formatTipo(item.tipo)) + "</td>" +
          "<td>" + escapeHtml(item.versaoDetectada || "N/D") + "</td>" +
          "<td>" + escapeHtml(item.status.toUpperCase()) + "</td>" +
          "<td>" + escapeHtml(vulnerability ? vulnerability.titulo : "Nenhuma vulnerabilidade conhecida encontrada") + "</td>" +
          "<td>" + escapeHtml(vulnerability && vulnerability.cve ? vulnerability.cve : "N/D") + "</td>" +
          "<td>" + escapeHtml(vulnerability && vulnerability.cvssScore !== null ? String(vulnerability.cvssScore) : "N/D") + "</td>" +
          "</tr>"
        );
      })
      .join("");

    return (
      "<html><head><title>Relatorio WordPress</title><style>" +
      "body{font-family:Arial,sans-serif;padding:24px;color:#111}table{width:100%;border-collapse:collapse;margin-top:16px}td,th{border:1px solid #ddd;padding:8px;text-align:left}th{background:#f5f5f5}" +
      "</style></head><body>" +
      "<h1>Relatorio WordPress</h1>" +
      "<p>Modo: " + escapeHtml(mode) + "</p>" +
      "<p>Site: " + escapeHtml(data.scannedUrl) + "</p>" +
      "<p>Score: " + escapeHtml(String(data.summary.scoreGeral)) + "</p>" +
      "<table><thead><tr><th>Item</th><th>Tipo</th><th>Versao</th><th>Status</th><th>Vulnerabilidade</th><th>CVE</th><th>CVSS</th></tr></thead><tbody>" +
      rows +
      "</tbody></table></body></html>"
    );
  }

  function exportReport(mode) {
    if (!lastAnalysis) {
      return;
    }
    if (mode === "technical") {
      openTechnicalReport({ print: true });
      return;
    }
    var popup = window.open("", "_blank", "noopener,noreferrer");
    if (!popup) {
      return;
    }
    popup.document.write(buildExportDocument(lastAnalysis, mode));
    popup.document.close();
    popup.focus();
    popup.print();
  }

  function resetAnalysis(mode) {
    if (mode === "common") {
      hideElement(commonResults);
      hideElement(commonLoading);
      hideElement(commonAlert);
      hideElement(commonContent);
      if (commonForm) {
        commonForm.elements.site.value = "";
        commonForm.elements.site.focus();
      }
      return;
    }

    hideElement(techResults);
    hideElement(techLoading);
    hideElement(techAlert);
    hideElement(techContent);
    if (techForm) {
      techForm.elements.site.value = "";
      techForm.elements.site.focus();
    }
  }

  function bindSummaryActions(root) {
    if (!root) {
      return;
    }

    Array.prototype.slice
      .call(root.querySelectorAll("[data-export-report]"))
      .forEach(function (button) {
        button.addEventListener("click", function () {
          exportReport(button.getAttribute("data-export-report"));
        });
      });

    Array.prototype.slice
      .call(root.querySelectorAll("[data-reset-analysis]"))
      .forEach(function (button) {
        button.addEventListener("click", function () {
          resetAnalysis(button.getAttribute("data-reset-analysis"));
        });
      });
  }

  function analyzeForCommon(event) {
    event.preventDefault();
    var site = normalizeDomain(commonForm.elements.site.value);
    if (!site) {
      commonForm.elements.site.focus();
      return;
    }

    showElement(commonResults);
    showElement(commonLoading);
    hideElement(commonContent);
    hideElement(commonAlert);

    var stopProgress = startProgress(
      [
        "Carregando pagina principal...",
        "Verificando versao do WordPress...",
        "Analisando plugins...",
        "Analisando tema...",
        "Consultando base de vulnerabilidades...",
      ],
      commonProgressLabel,
      commonProgressBar
    );

    fetchAnalysis(site, {
      detect_core: true,
      detect_plugins: true,
      detect_themes: true,
    })
      .then(function (payload) {
        stopProgress("Analise concluida.");
        window.setTimeout(function () {
          renderCommon(payload);
          bindSummaryActions(commonSummary);
        }, 180);
      })
      .catch(function (error) {
        stopProgress("Falha na analise.");
        hideElement(commonLoading);
        setAlert(commonAlert, "warning", error.message);
      });
  }

  function analyzeForTechnical(event) {
    event.preventDefault();
    var site = normalizeDomain(techForm.elements.site.value);
    var steps = [
      "Carregando pagina principal...",
      "Verificando versao do WordPress...",
      "Analisando plugins...",
      "Analisando tema...",
      "Consultando WPVulnerability...",
    ];

    if (!site) {
      techForm.elements.site.focus();
      return;
    }

    showElement(techResults);
    showElement(techLoading);
    hideElement(techContent);
    hideElement(techAlert);
    setTechnicalLoadingState("loading", {
      steps: steps,
      activeIndex: 0,
    });

    var stopProgress = startProgress(steps, techProgressLabel, techProgressBar, {
      onUpdate: function (progressState) {
        setTechnicalLoadingState("loading", progressState);
      },
    });

    fetchAnalysis(site, {
      detect_core: techForm.elements.detect_core.checked,
      detect_plugins: techForm.elements.detect_plugins.checked,
      detect_themes: techForm.elements.detect_themes.checked,
    })
      .then(function (payload) {
        stopProgress("Analise concluida.");
        setTechnicalLoadingState("complete", payload);
        window.setTimeout(function () {
          renderTechnical(payload);
        }, 1100);
      })
      .catch(function (error) {
        stopProgress("Falha na analise.");
        hideElement(techLoading);
        if (techPhaseLabel) {
          techPhaseLabel.textContent = "Analise interrompida";
        }
        setAlert(techAlert, "warning", error.message);
      });
  }

  if (commonForm) {
    commonForm.addEventListener("submit", analyzeForCommon);
  }

  if (techForm) {
    techForm.addEventListener("submit", analyzeForTechnical);
  }

  if (exportPdfButton) {
    exportPdfButton.addEventListener("click", function () {
      exportReport("technical");
    });
  }

  if (copyJsonButton) {
    copyJsonButton.addEventListener("click", function () {
      if (!lastAnalysis || !navigator.clipboard) {
        return;
      }
      navigator.clipboard.writeText(JSON.stringify(lastAnalysis, null, 2));
    });
  }

  if (openTechnicalReportButton) {
    openTechnicalReportButton.addEventListener("click", function () {
      openTechnicalReport();
    });
  }

  if (clientReportButton) {
    clientReportButton.addEventListener("click", function () {
      if (!lastAnalysis) {
        return;
      }
      setActiveProfile("common");
      if (commonForm) {
        commonForm.elements.site.value = lastAnalysis.targetUrl;
      }
      renderCommon(lastAnalysis);
      bindSummaryActions(commonSummary);
    });
  }

  options.forEach(function (option) {
    option.addEventListener("click", function () {
      setActiveProfile(option.getAttribute("data-profile-target"));
    });
  });

  resetButtons.forEach(function (button) {
    button.addEventListener("click", function () {
      resetProfileSelection();
    });
  });

  closeButtons.forEach(function (button) {
    button.addEventListener("click", closeModal);
  });

  if (backdrop) {
    backdrop.addEventListener("click", function (event) {
      if (event.target === backdrop) {
        closeModal();
      }
    });
  }

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      closeModal();
    }
  });

  setPanelVisibility(null);

  try {
    var storedProfile = window.localStorage.getItem(PROFILE_STORAGE_KEY);
    if (storedProfile === "common" || storedProfile === "technical") {
      setActiveProfile(storedProfile);
    }
  } catch (error) {
    return;
  }
})();
