(function () {
  var root = document.querySelector("[data-wp-tech-report-page]");

  if (!root) {
    return;
  }

  var STORAGE_KEY = "dsc-wordpress-technical-report";
  var emptyState = document.querySelector("[data-wp-tech-report-empty]");
  var reportBody = document.querySelector("[data-wp-tech-report-body]");
  var siteLabel = document.querySelector("[data-wp-tech-report-site]");
  var metaLine = document.querySelector("[data-wp-tech-report-meta]");
  var metricsRoot = document.querySelector("[data-wp-tech-report-metrics]");
  var scoreLabel = document.querySelector("[data-wp-tech-report-score-label]");
  var scoreBar = document.querySelector("[data-wp-tech-report-score-bar]");
  var riskMapRoot = document.querySelector("[data-wp-tech-report-risk-map]");
  var vulnerabilityGroupsRoot = document.querySelector("[data-wp-tech-report-vulnerability-groups]");
  var signalsRoot = document.querySelector("[data-wp-tech-report-signals]");
  var safeItemsRoot = document.querySelector("[data-wp-tech-report-safe-items]");
  var recommendationsRoot = document.querySelector("[data-wp-tech-report-recommendations]");
  var itemsRoot = document.querySelector("[data-wp-tech-report-items]");
  var referencesRoot = document.querySelector("[data-wp-tech-report-references]");
  var printButton = document.querySelector("[data-wp-tech-report-print]");
  var copyJsonButton = document.querySelector("[data-wp-tech-report-copy-json]");

  function escapeHtml(value) {
    return String(value || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function formatTipo(tipo) {
    return {
      core: "Core",
      plugin: "Plugin",
      tema: "Tema",
    }[tipo] || tipo || "N/D";
  }

  function severityRank(severity) {
    return {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
    }[severity] || 0;
  }

  function severityLabel(severity) {
    return {
      critical: "CRITICO",
      high: "ALTO",
      medium: "MEDIO",
      low: "BAIXO",
    }[severity] || "INFO";
  }

  function severityTitle(severity) {
    return {
      critical: "Criticas",
      high: "Altas",
      medium: "Medias",
      low: "Baixas",
    }[severity] || "Informativas";
  }

  function scoreTone(score) {
    if (score >= 80) {
      return "good";
    }
    if (score >= 50) {
      return "warning";
    }
    return "danger";
  }

  function formatDateTime(value) {
    if (!value) {
      return "N/D";
    }

    var parsed = new Date(value);
    if (isNaN(parsed.getTime())) {
      return "N/D";
    }

    try {
      return new Intl.DateTimeFormat("pt-BR", {
        dateStyle: "short",
        timeStyle: "short",
      }).format(parsed);
    } catch (error) {
      return parsed.toISOString();
    }
  }

  function readStoredReport() {
    if (!window.localStorage) {
      return null;
    }

    try {
      var raw = window.localStorage.getItem(STORAGE_KEY);
      if (!raw) {
        return null;
      }

      var parsed = JSON.parse(raw);
      if (!parsed || !parsed.analysis) {
        return null;
      }

      return parsed;
    } catch (error) {
      return null;
    }
  }

  function flattenVulnerabilities(data) {
    var rows = [];

    (data.items || []).forEach(function (item) {
      (item.vulnerabilidades || []).forEach(function (vulnerability) {
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

    return rows;
  }

  function collectReferences(data) {
    var seen = {};
    var references = [
      {
        label: "WPScan DB",
        url: "https://wpscan.com/wordpresses",
      },
      {
        label: "OWASP WordPress Security Testing Guide",
        url: "https://owasp.org/www-project-web-security-testing-guide/stable/6-Appendix/F-Leveraging_Dev_Tools/README",
      },
      {
        label: "WordPress Hardening Codex",
        url: "https://wordpress.org/documentation/article/hardening-wordpress/",
      },
    ];

    references.forEach(function (reference) {
      seen[reference.url] = true;
    });

    function pushReference(label, url) {
      if (!url || seen[url]) {
        return;
      }
      seen[url] = true;
      references.push({
        label: label,
        url: url,
      });
    }

    (data.items || []).forEach(function (item) {
      pushReference(item.nome + " - referencia", item.referencia);
      (item.vulnerabilidades || []).forEach(function (vulnerability) {
        pushReference(vulnerability.titulo, vulnerability.referencia);
      });
    });

    return references;
  }

  function renderSummary(payload, savedAt) {
    var summary = payload.summary || {};
    var bySeverity = summary.vulnerabilidadesPorSeveridade || {};
    var score = Number(summary.scoreGeral || 0);
    var scoreClass = scoreTone(score);

    siteLabel.textContent = payload.scannedUrl || payload.targetUrl || "URL analisada";
    metaLine.textContent = "Analise gerada em " + formatDateTime(savedAt);

    metricsRoot.innerHTML = [
      ["Total de itens analisados", summary.totalItemsAnalisados || 0],
      ["Total de vulnerabilidades", summary.totalVulnerabilidades || 0],
      ["Criticas", bySeverity.critical || 0],
      ["Altas", bySeverity.high || 0],
      ["Medias", bySeverity.medium || 0],
      ["Baixas", bySeverity.low || 0],
      ["Score geral", score + "/100"],
    ]
      .map(function (metric) {
        return (
          '<article class="wp-tech-report-metric">' +
          '<span class="wp-tech-report-metric__label">' + escapeHtml(metric[0]) + "</span>" +
          '<strong class="wp-tech-report-metric__value">' + escapeHtml(String(metric[1])) + "</strong>" +
          "</article>"
        );
      })
      .join("");

    scoreLabel.textContent = score + "/100";
    scoreBar.style.width = Math.max(0, Math.min(score, 100)) + "%";
    scoreBar.className = "wp-tech-report-score__fill wp-tech-report-score__fill--" + scoreClass;
  }

  function renderRiskMap(payload) {
    var summary = payload.summary || {};
    var bySeverity = summary.vulnerabilidadesPorSeveridade || {};
    var max = Math.max(
      bySeverity.critical || 0,
      bySeverity.high || 0,
      bySeverity.medium || 0,
      bySeverity.low || 0,
      1
    );

    riskMapRoot.innerHTML = ["critical", "high", "medium", "low"]
      .map(function (severity) {
        var count = bySeverity[severity] || 0;
        var width = Math.max(4, Math.round((count / max) * 100));
        return (
          '<article class="wp-tech-report-risk wp-tech-report-risk--' + severity + '">' +
          '<div class="wp-tech-report-risk__top">' +
          "<strong>" + severityTitle(severity) + "</strong>" +
          "<span>" + escapeHtml(String(count)) + "</span>" +
          "</div>" +
          '<div class="wp-tech-report-risk__bar"><span style="width: ' + width + '%"></span></div>' +
          "</article>"
        );
      })
      .join("");
  }

  function renderSignals(payload) {
    var signals = ((payload.detection || {}).signals || []).slice();

    if (!signals.length) {
      signalsRoot.innerHTML =
        '<article class="wp-tech-report-empty-card">Nenhum sinal tecnico foi registrado.</article>';
      return;
    }

    signals.sort(function (left, right) {
      return left.layer - right.layer;
    });

    signalsRoot.innerHTML = signals
      .map(function (signal) {
        return (
          '<article class="wp-tech-report-signal wp-tech-report-signal--' +
          (signal.detected ? "detected" : "clear") +
          '">' +
          '<div class="wp-tech-report-signal__top">' +
          '<strong>' + escapeHtml(signal.name) + "</strong>" +
          '<span class="badge badge--' + (signal.detected ? "good" : "info") + '">' +
          (signal.detected ? "Detectado" : "Nao detectado") +
          "</span>" +
          "</div>" +
          '<p class="wp-tech-report-signal__meta">Camada ' + escapeHtml(String(signal.layer)) + "</p>" +
          '<p class="wp-tech-report-signal__value">' + escapeHtml(signal.value || "Sem detalhe adicional") + "</p>" +
          "</article>"
        );
      })
      .join("");
  }

  function safeItems(payload) {
    return (payload.items || []).filter(function (item) {
      return item.status === "seguro" || !(item.vulnerabilidades || []).length;
    });
  }

  function renderVulnerabilityGroups(payload) {
    var rows = flattenVulnerabilities(payload);

    if (!rows.length) {
      vulnerabilityGroupsRoot.innerHTML =
        '<article class="wp-tech-report-empty-card">Nenhuma vulnerabilidade conhecida foi encontrada nos itens identificados.</article>';
      return;
    }

    vulnerabilityGroupsRoot.innerHTML = ["critical", "high", "medium", "low"]
      .map(function (severity) {
        var severityRows = rows.filter(function (row) {
          return row.vulnerability.severidade === severity;
        });

        if (!severityRows.length) {
          return "";
        }

        return (
          '<section class="wp-tech-report-vuln-group">' +
          '<div class="wp-tech-report-vuln-group__heading">' +
          "<h3>" + severityTitle(severity) + "</h3>" +
          '<span class="wp-tech-report-vuln-count">' + escapeHtml(String(severityRows.length)) + "</span>" +
          "</div>" +
          severityRows
            .map(function (row, index) {
              var item = row.item;
              var vulnerability = row.vulnerability;
              var cve = vulnerability.cve || vulnerability.id || "N/D";
              var fixedVersion = vulnerability.corrigidoNaVersao || "N/D";
              var installedVersion = item.versaoDetectada || "N/D";
              var description =
                vulnerability.descricao ||
                vulnerability.description ||
                vulnerability.titulo ||
                "Descricao tecnica nao fornecida pela base consultada.";
              var attackVector =
                vulnerability.vetorAtaque ||
                vulnerability.attackVector ||
                vulnerability.vector ||
                "Nao informado no JSON retornado.";
              var recommendation =
                fixedVersion !== "N/D"
                  ? "Atualize " + item.nome + " para a versao " + fixedVersion + " ou superior, validando compatibilidade e backup antes da mudanca."
                  : "Atualize ou substitua o componente apos validar compatibilidade, backup e janela de manutencao.";

              return (
                '<details class="wp-tech-report-vuln-detail wp-tech-report-vuln-detail--' +
                severity +
                '"' +
                (severity === "critical" && index === 0 ? " open" : "") +
                ">" +
                '<summary class="wp-tech-report-vuln-detail__summary">' +
                '<span class="wp-tech-report-vuln-icon"></span>' +
                "<strong>" + escapeHtml(item.nome) + "</strong>" +
                '<span class="wp-tech-report-vuln-badge wp-tech-report-vuln-badge--' + severity + '">' + severityLabel(severity) + "</span>" +
                '<span class="wp-tech-report-vuln-cvss">CVSS ' + escapeHtml(vulnerability.cvssScore != null ? String(vulnerability.cvssScore) : "N/D") + "</span>" +
                "</summary>" +
                '<div class="wp-tech-report-vuln-detail__body">' +
                '<dl class="wp-tech-report-vuln-facts">' +
                '<div><dt>CVE</dt><dd><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + encodeURIComponent(cve) + '" target="_blank" rel="noreferrer">' + escapeHtml(cve) + "</a></dd></div>" +
                "<div><dt>Tipo</dt><dd>" + escapeHtml(formatTipo(item.tipo)) + "</dd></div>" +
                "<div><dt>Versao instalada</dt><dd>" + escapeHtml(installedVersion) + "</dd></div>" +
                "<div><dt>Corrigido em</dt><dd>" + escapeHtml(fixedVersion) + "</dd></div>" +
                "</dl>" +
                '<div class="wp-tech-report-vuln-copy">' +
                "<h4>Descricao tecnica</h4><p>" + escapeHtml(description) + "</p>" +
                "<h4>Vetor de ataque</h4><p>" + escapeHtml(attackVector) + "</p>" +
                "<h4>Recomendacao de correcao</h4><p>" + escapeHtml(recommendation) + "</p>" +
                "</div>" +
                "</div>" +
                "</details>"
              );
            })
            .join("") +
          "</section>"
        );
      })
      .join("");
  }

  function renderSafeItems(payload) {
    var safeRows = safeItems(payload);

    if (!safeRows.length) {
      safeItemsRoot.innerHTML =
        '<article class="wp-tech-report-empty-card">Nenhum item entrou na faixa de componentes seguros nesta analise.</article>';
      return;
    }

    safeItemsRoot.innerHTML = safeRows
      .map(function (item) {
        return (
          '<article class="wp-tech-report-safe-card">' +
          '<div class="wp-tech-report-safe-card__header">' +
          "<div>" +
          '<p class="wp-tech-report-safe-card__slug">' + escapeHtml(item.slug || "N/D") + "</p>" +
          "<h3>" + escapeHtml(item.nome) + "</h3>" +
          "</div>" +
          '<div class="wp-tech-report-safe-card__badges">' +
          '<span class="badge badge--info">' + escapeHtml(formatTipo(item.tipo)) + "</span>" +
          '<span class="badge badge--good">SEGURO</span>' +
          "</div>" +
          "</div>" +
          '<div class="wp-tech-report-safe-card__facts">' +
          '<span><strong>Versao detectada:</strong> ' + escapeHtml(item.versaoDetectada || "N/D") + "</span>" +
          '<span><strong>Falhas conhecidas:</strong> 0</span>' +
          '<span><strong>Acao:</strong> Manter atualizacoes, backup e monitoramento recorrente.</span>' +
          "</div>" +
          "</article>"
        );
      })
      .join("");
  }

  function renderRecommendations(payload) {
    var rows = flattenVulnerabilities(payload);

    if (!rows.length) {
      recommendationsRoot.innerHTML =
        '<article class="wp-tech-report-recommendation">' +
        "<strong>Manter postura atual de seguranca</strong>" +
        "<p>Nao foram encontradas vulnerabilidades conhecidas. Preserve a rotina de atualizacao, backup validado e monitoramento continuo.</p>" +
        "</article>";
      return;
    }

    recommendationsRoot.innerHTML = rows
      .slice(0, 6)
      .map(function (row, index) {
        var item = row.item;
        var vulnerability = row.vulnerability;
        var severity = vulnerability.severidade || "low";
        var fixedVersion = vulnerability.corrigidoNaVersao || "versao corrigida nao informada";
        var cve = vulnerability.cve || vulnerability.id || "N/D";
        return (
          '<article class="wp-tech-report-recommendation wp-tech-report-recommendation--' + severity + '">' +
          '<div class="wp-tech-report-recommendation__header">' +
          '<span class="wp-tech-report-recommendation__index">P' + escapeHtml(String(index + 1)) + "</span>" +
          "<div>" +
          "<strong>" + escapeHtml(item.nome) + "</strong>" +
          "<p>Priorize a correcao de " + escapeHtml(cve) + " no componente " + escapeHtml(item.nome) + ".</p>" +
          "</div>" +
          '<span class="wp-tech-report-vuln-badge wp-tech-report-vuln-badge--' + severity + '">' + severityLabel(severity) + "</span>" +
          "</div>" +
          '<p class="wp-tech-report-recommendation__body">Atualize para ' + escapeHtml(fixedVersion) + ' ou superior, valide compatibilidade com o ambiente e execute backup antes da mudanca. Se nao houver patch disponivel, isole ou substitua o componente.</p>' +
          "</article>"
        );
      })
      .join("");
  }

  function renderItems(payload) {
    var items = payload.items || [];

    if (!items.length) {
      itemsRoot.innerHTML =
        '<article class="wp-tech-report-empty-card">Nenhum componente foi retornado pela analise.</article>';
      return;
    }

    itemsRoot.innerHTML = items
      .map(function (item) {
        return (
          '<article class="wp-tech-report-item">' +
          '<div class="wp-tech-report-item__header">' +
          "<div>" +
          '<p class="wp-tech-report-item__slug">' + escapeHtml(item.slug) + "</p>" +
          "<h3>" + escapeHtml(item.nome) + "</h3>" +
          "</div>" +
          '<div class="wp-tech-report-item__badges">' +
          '<span class="badge badge--info">' + escapeHtml(formatTipo(item.tipo)) + "</span>" +
          '<span class="badge badge--' + (item.status === "critico" ? "danger" : item.status === "seguro" ? "good" : "warning") + '">' +
          escapeHtml(String(item.status || "N/D").toUpperCase()) +
          "</span>" +
          "</div>" +
          "</div>" +
          '<div class="wp-tech-report-item__facts">' +
          '<span><strong>Versao:</strong> ' + escapeHtml(item.versaoDetectada || "N/D") + "</span>" +
          '<span><strong>Falhas:</strong> ' + escapeHtml(String((item.vulnerabilidades || []).length)) + "</span>" +
          '<span><strong>Referencia:</strong> ' +
          (item.referencia
            ? '<a href="' + escapeHtml(item.referencia) + '" target="_blank" rel="noreferrer">Abrir referencia</a>'
            : '<span class="text-muted">N/D</span>') +
          "</span>" +
          "</div>" +
          "</article>"
        );
      })
      .join("");
  }

  function renderReferences(payload) {
    referencesRoot.innerHTML = collectReferences(payload)
      .map(function (reference) {
        return (
          '<a class="wp-tech-report-reference" href="' +
          escapeHtml(reference.url) +
          '" target="_blank" rel="noreferrer">' +
          "<strong>" + escapeHtml(reference.label) + "</strong>" +
          '<span>' + escapeHtml(reference.url) + "</span>" +
          "</a>"
        );
      })
      .join("");
  }

  function showEmptyState() {
    if (emptyState) {
      emptyState.hidden = false;
    }
    if (reportBody) {
      reportBody.hidden = true;
    }
  }

  function showReport() {
    if (emptyState) {
      emptyState.hidden = true;
    }
    if (reportBody) {
      reportBody.hidden = false;
    }
  }

  function renderReport(record) {
    renderSummary(record.analysis, record.savedAt);
    renderRiskMap(record.analysis);
    renderVulnerabilityGroups(record.analysis);
    renderSignals(record.analysis);
    renderSafeItems(record.analysis);
    renderRecommendations(record.analysis);
    renderItems(record.analysis);
    renderReferences(record.analysis);
    showReport();
  }

  function shouldAutoPrint() {
    return new URLSearchParams(window.location.search).get("print") === "1";
  }

  var record = readStoredReport();

  if (!record) {
    showEmptyState();
  } else {
    renderReport(record);
  }

  if (printButton) {
    printButton.addEventListener("click", function () {
      window.print();
    });
  }

  if (copyJsonButton) {
    copyJsonButton.addEventListener("click", function () {
      if (!record || !record.analysis || !navigator.clipboard) {
        return;
      }
      navigator.clipboard.writeText(JSON.stringify(record.analysis, null, 2));
    });
  }

  if (record && shouldAutoPrint()) {
    window.setTimeout(function () {
      window.print();
    }, 180);
  }
})();
