/**
 * @fileoverview Montagem do corpo do relatório enviado à equipe de segurança.
 *
 * As URLs aparecem neutralizadas (defanged). Antes o e-mail para o SOC era o
 * único canal que mostrava as URLs vivas — e o Gmail transforma URL em texto
 * puro em link clicável, entregando ao analista um link de phishing ativo.
 */

/**
 * Monta as versões texto e HTML do relatório.
 *
 * @param {Object} emailData Dados do e-mail suspeito.
 * @param {string} reportType Um valor de REPORT_TYPES.
 * @param {Object} [options] Opções.
 * @param {string} [options.timeZone] Fuso do usuário, vindo do evento.
 * @returns {{plainBody: string, htmlBody: string}} Corpos do relatório.
 */
function createReportBody(emailData, reportType, options) {
  const opts = options || {};
  const timeZone = opts.timeZone || getScriptTimeZone();
  const reporter = getReporterEmail() || "desconhecido";
  const isInvestigation = reportType === REPORT_TYPES.INVESTIGATION;

  const ioc = emailData.iocReport || {};
  const risk = ioc.riskAnalysis || { score: 0, classification: "UNKNOWN", reasons: [] };
  const riskColor = getRiskColor(risk.classification);

  // Um único instante, usado nas duas representações.
  const now = new Date();
  const reportTimeUtc = formatUtc(now);
  const reportTimeLocal = formatInTimeZone(now, timeZone);
  const emailDate = formatUtc(emailData.date);

  const auth = ioc.authenticationResults || {};
  const authSummary =
    `SPF: ${auth.spf || "N/A"}, DKIM: ${auth.dkim || "N/A"}, DMARC: ${auth.dmarc || "N/A"}`;

  const flagLabels = (ioc.suspiciousFlags || []).map(function (flag) {
    return FLAG_LABELS[flag] || flag;
  });
  const flagsText = flagLabels.length ? flagLabels.join("; ") : "Nenhuma flag automática";

  const attachments = ioc.attachments || [];
  const urls = ioc.urlDetails || [];
  const ai = emailData.aiAnalysis;
  const searchLink = buildRfc822SearchLink(emailData.messageId);

  const title = isInvestigation ? "SOLICITAÇÃO DE INVESTIGAÇÃO" : "REPORTE DE PHISHING";

  // ---------------------------------------------------------------- texto --
  const plainLines = [
    title,
    `Relatado em: ${reportTimeLocal} (${timeZone})`,
    `             ${reportTimeUtc}`,
    `Repórter: ${reporter}`,
    "",
    "ANÁLISE DE RISCO (SOC)",
    `• Score: ${risk.score}/100`,
    `• Classificação: ${risk.classification}`,
    `• Motivos: ${
      (risk.reasons || []).length
        ? risk.reasons.join("; ")
        : "Nenhum fator de risco identificado."
    }`,
  ];

  if ((risk.mitigations || []).length) {
    plainLines.push(`• Mitigações: ${risk.mitigations.join("; ")}`);
  }

  plainLines.push(
    "",
    "DETALHES DO E-MAIL SUSPEITO",
    `• De: ${emailData.from}`,
    `• Nome exibido: ${ioc.fromDisplayName || "(nenhum)"}`,
    `• Para: ${emailData.to}`
  );
  if (emailData.replyTo) plainLines.push(`• Responder para: ${emailData.replyTo}`);
  plainLines.push(
    `• Assunto: ${emailData.subject}`,
    `• Data do e-mail: ${emailDate}`
  );
  if (emailData.messageId) plainLines.push(`• Message-ID: ${emailData.messageId}`);
  if (emailData.userAgent) plainLines.push(`• User-Agent: ${emailData.userAgent}`);

  plainLines.push(
    "",
    "INDICADORES TÉCNICOS",
    `• SHA-256 do .eml: ${ioc.raw_sha256 || "N/A"}`,
    `• Domínio do From: ${getDomainFromEmail(emailData.from)}`,
    `• Return-Path: ${emailData.returnPath || "N/A"} (${getDomainFromEmail(
      emailData.returnPath
    )})`,
    `• IP de origem: ${ioc.originatingIP || "Não identificado"}`,
    `• IPs públicos na cadeia: ${
      (ioc.receivedIPs || []).length ? ioc.receivedIPs.join(", ") : "Nenhum"
    }`,
    `• Saltos (Received): ${ioc.hopCount || 0}`,
    `• Autenticação: ${authSummary}`,
    `• Lista de distribuição: ${ioc.isMailingList ? "sim" : "não"}`,
    `• Flags: ${flagsText}`
  );

  if (urls.length) {
    plainLines.push("", `URLS (${urls.length}) — neutralizadas`);
    urls.slice(0, 20).forEach(function (entry) {
      const wrapped =
        entry.wrappers && entry.wrappers.length
          ? ` [desembrulhado de ${entry.wrappers.join(" → ")}]`
          : "";
      plainLines.push(`• ${defangUrl(entry.url)}${wrapped}`);
    });
    if (urls.length > 20) plainLines.push(`• ...e mais ${urls.length - 20}`);
  }

  if (attachments.length) {
    plainLines.push("", `ANEXOS (${attachments.length})`);
    attachments.forEach(function (attachment) {
      plainLines.push(
        `• ${attachment.name} (${attachment.type || "?"}, ${formatBytes(attachment.size)})`
      );
      if (attachment.sha256) plainLines.push(`  SHA-256: ${attachment.sha256}`);
    });
  } else {
    plainLines.push("", "ANEXOS: nenhum");
  }

  if (ai && ai.text) {
    plainLines.push(
      "",
      "ANÁLISE IA (GEMINI)",
      "-------------------------------------------------------------",
      ai.text,
      "-------------------------------------------------------------"
    );
  }

  if (searchLink) plainLines.push("", `Link Gmail (busca por Message-ID): ${searchLink}`);

  plainLines.push(
    "",
    "E-mail original anexado como .eml, com todos os cabeçalhos preservados.",
    "Relatório JSON de IoCs anexado, pronto para ingestão em SIEM."
  );

  if (isInvestigation) {
    plainLines.push("", "⚠️ AÇÃO NECESSÁRIA: o usuário solicitou investigação e aguarda resposta.");
  }

  // ------------------------------------------------------------------ HTML --
  const htmlBody = `
<div style="font-family:Arial,sans-serif;max-width:680px;">
  <h2 style="color:${isInvestigation ? "#b06000" : "#d93025"};margin:0 0 12px;">${title}</h2>

  <div style="background:#f5f5f5;padding:10px;margin:12px 0;font-size:13px;">
    <strong>Relatado em:</strong><br>
    <span style="margin-left:10px;">Local (${escapeHtml(timeZone)}): ${escapeHtml(
    reportTimeLocal
  )}</span><br>
    <span style="margin-left:10px;">UTC: ${escapeHtml(reportTimeUtc)}</span><br>
    <strong>Repórter:</strong> ${escapeHtml(reporter)}
  </div>

  ${
    isInvestigation
      ? `<div style="background:#fff3cd;border-left:4px solid #fbbc04;padding:12px;margin:16px 0;">
           <strong>⚠️ AÇÃO NECESSÁRIA:</strong> o usuário solicitou uma investigação e aguarda resposta.
         </div>`
      : ""
  }

  <div style="border:2px solid ${riskColor};border-radius:8px;overflow:hidden;margin:16px 0;">
    <div style="background:${riskColor};color:#fff;padding:8px 12px;font-weight:bold;">ANÁLISE DE RISCO</div>
    <div style="padding:12px;background:#fff;">
      <div style="font-size:24px;font-weight:bold;color:${riskColor};">
        ${risk.score} <span style="font-size:14px;color:#555;font-weight:normal;">/ 100</span>
      </div>
      <div style="font-size:16px;font-weight:bold;margin-bottom:8px;">${escapeHtml(
        risk.classification
      )}</div>
      ${
        (risk.reasons || []).length
          ? `<ul style="margin:0;padding-left:20px;color:#333;">${risk.reasons
              .map(function (reason) {
                return `<li>${escapeHtml(reason)}</li>`;
              })
              .join("")}</ul>`
          : `<span style="color:#188038;">Nenhum fator de risco identificado automaticamente.</span>`
      }
      ${
        (risk.mitigations || []).length
          ? `<p style="margin:8px 0 0;font-size:12px;color:#666;"><em>Mitigações: ${escapeHtml(
              risk.mitigations.join("; ")
            )}</em></p>`
          : ""
      }
    </div>
  </div>

  ${renderAiHtmlBlock(ai)}

  <h3 style="margin:20px 0 8px;">Detalhes do e-mail suspeito</h3>
  <table style="border-collapse:collapse;width:100%;font-size:13px;">
    ${renderRow("De", escapeHtml(emailData.from), true)}
    ${renderRow("Nome exibido", escapeHtml(ioc.fromDisplayName || "(nenhum)"), false)}
    ${renderRow("Para", escapeHtml(emailData.to), true)}
    ${
      emailData.replyTo
        ? renderRow(
            "Responder para",
            `<strong style="color:#d93025;">${escapeHtml(emailData.replyTo)}</strong>`,
            false
          )
        : ""
    }
    ${renderRow("Assunto", escapeHtml(emailData.subject), true)}
    ${renderRow("Data do e-mail", escapeHtml(emailDate), false)}
    ${
      emailData.messageId
        ? renderRow(
            "Message-ID",
            `<code style="font-size:12px;">${escapeHtml(emailData.messageId)}</code>`,
            true
          )
        : ""
    }
    ${renderRow(
      "SHA-256 do .eml",
      `<code style="font-size:11px;word-break:break-all;">${escapeHtml(
        ioc.raw_sha256 || "N/A"
      )}</code>`,
      false
    )}
  </table>

  <h3 style="margin:20px 0 8px;">Indicators of Compromise</h3>
  <table style="border-collapse:collapse;width:100%;font-size:13px;">
    ${renderRow(
      "IP de origem",
      ioc.originatingIP
        ? `<code>${escapeHtml(ioc.originatingIP)}</code>`
        : "Não identificado",
      true
    )}
    ${renderRow(
      "IPs públicos",
      (ioc.receivedIPs || []).length
        ? `<code>${escapeHtml(ioc.receivedIPs.join(", "))}</code>`
        : "Nenhum identificado",
      false
    )}
    ${renderRow("Consultar reputação", renderReputationHtml(ioc.originatingIP, ioc.receivedIPs), true)}
    ${renderRow("Autenticação", escapeHtml(authSummary), false)}
    ${renderRow(
      "Spoofing check",
      `From: ${escapeHtml(getDomainFromEmail(emailData.from))}<br>` +
        `Return-Path: ${escapeHtml(getDomainFromEmail(emailData.returnPath))}<br>` +
        `Lista de distribuição: ${ioc.isMailingList ? "sim" : "não"}`,
      true
    )}
    ${renderRow(
      "Flags",
      flagLabels.length
        ? `<ul style="margin:0;padding-left:18px;color:#d93025;">${flagLabels
            .map(function (label) {
              return `<li>${escapeHtml(label)}</li>`;
            })
            .join("")}</ul>`
        : "Nenhuma flag automática",
      false
    )}
    ${urls.length ? renderRow(`URLs (${urls.length})`, renderUrlsHtml(urls), true) : ""}
    ${
      (ioc.anchorMismatches || []).length
        ? renderRow("Links disfarçados", renderAnchorMismatchHtml(ioc.anchorMismatches), false)
        : ""
    }
    ${renderRow("Anexos", renderAttachmentsHtml(attachments), true)}
    ${
      searchLink
        ? renderRow(
            "Gmail",
            `<a href="${sanitizeHref(searchLink)}">Abrir busca por Message-ID</a>`,
            false
          )
        : ""
    }
  </table>

  <p style="margin-top:20px;padding:10px;background:#e8f5e9;border-left:4px solid #34a853;font-size:13px;">
    <strong>Anexos deste relatório:</strong><br>
    1. E-mail original (.eml) com cabeçalhos completos — analise em
       <a href="https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx">MXToolbox EmailHeaders</a>.<br>
    2. Relatório de IoCs (.json) pronto para ingestão.
  </p>

  <p style="font-size:11px;color:#777;">
    As URLs acima estão neutralizadas (<code>hxxp</code> e <code>[.]</code>) para evitar cliques acidentais.
  </p>
</div>`;

  return { plainBody: plainLines.join("\n"), htmlBody: htmlBody };
}

/**
 * Renderiza uma linha da tabela do relatório.
 *
 * @param {string} label Rótulo da linha.
 * @param {string} value Conteúdo já escapado.
 * @param {boolean} shaded Se deve receber fundo cinza.
 * @returns {string} O HTML da linha.
 */
function renderRow(label, value, shaded) {
  return (
    `<tr${shaded ? ' style="background:#f5f5f5;"' : ""}>` +
    `<td style="padding:8px;border:1px solid #ddd;width:180px;vertical-align:top;"><strong>${escapeHtml(
      label
    )}</strong></td>` +
    `<td style="padding:8px;border:1px solid #ddd;word-break:break-word;">${value}</td>` +
    "</tr>"
  );
}

/**
 * Renderiza a lista de URLs neutralizadas.
 *
 * @param {Array<Object>} urls Detalhes das URLs.
 * @returns {string} O HTML da lista.
 */
function renderUrlsHtml(urls) {
  const items = urls.slice(0, 20).map(function (entry) {
    const badges = [];
    if (entry.wrappers && entry.wrappers.length) {
      badges.push(`desembrulhado de ${escapeHtml(entry.wrappers.join(" → "))}`);
    }
    if (entry.isShortener) badges.push("encurtador");
    if (entry.isIpLiteral) badges.push("IP literal");
    if (entry.isPunycode) badges.push("punycode");

    return (
      `<li><code style="font-size:11px;">${escapeHtml(defangUrl(entry.url))}</code>` +
      (badges.length
        ? ` <span style="color:#d93025;font-size:11px;">(${badges.join(", ")})</span>`
        : "") +
      "</li>"
    );
  });

  const extra = urls.length > 20 ? `<li>...e mais ${urls.length - 20}</li>` : "";
  return `<ul style="margin:0;padding-left:18px;">${items.join("")}${extra}</ul>`;
}

/**
 * Renderiza divergências entre texto do link e href.
 *
 * @param {Array<Object>} mismatches Divergências encontradas.
 * @returns {string} O HTML da lista.
 */
function renderAnchorMismatchHtml(mismatches) {
  const items = mismatches.slice(0, 5).map(function (mismatch) {
    return (
      `<li>Texto <em>“${escapeHtml(mismatch.text)}”</em> aponta para ` +
      `<code>${escapeHtml(defangUrl(mismatch.href))}</code></li>`
    );
  });
  return `<ul style="margin:0;padding-left:18px;color:#d93025;">${items.join("")}</ul>`;
}

/**
 * Renderiza a lista de anexos com hashes.
 *
 * @param {Array<Object>} attachments Anexos.
 * @returns {string} O HTML da lista.
 */
function renderAttachmentsHtml(attachments) {
  if (!attachments.length) return "Nenhum";

  const items = attachments.map(function (attachment) {
    const hash = attachment.sha256
      ? `<br><span style="font-size:11px;color:#555;">SHA-256: <code>${escapeHtml(
          attachment.sha256
        )}</code> · <a href="https://www.virustotal.com/gui/file/${encodeURIComponent(
          attachment.sha256
        )}">VirusTotal</a></span>`
      : "";
    return (
      `<li><code>${escapeHtml(attachment.name)}</code> ` +
      `<span style="font-size:11px;color:#555;">(${escapeHtml(
        attachment.type || "?"
      )}, ${formatBytes(attachment.size)})</span>${hash}</li>`
    );
  });
  return `<ul style="margin:0;padding-left:18px;">${items.join("")}</ul>`;
}

/**
 * Renderiza os links de reputação, priorizando o IP de origem.
 *
 * @param {string} originatingIp IP do primeiro salto.
 * @param {string[]} allIps Todos os IPs públicos.
 * @returns {string} O HTML dos links.
 */
function renderReputationHtml(originatingIp, allIps) {
  const ips = [];
  if (originatingIp) ips.push(originatingIp);
  (allIps || []).forEach(function (ip) {
    if (ips.indexOf(ip) === -1 && ips.length < 5) ips.push(ip);
  });

  if (!ips.length) return "Nenhum IP público para consultar.";

  return ips
    .map(function (ip, index) {
      const encoded = encodeURIComponent(ip);
      const label = index === 0 && originatingIp === ip ? " (origem)" : "";
      return (
        `<div style="margin-bottom:6px;"><strong>${escapeHtml(ip)}</strong>${label}: ` +
        `<a href="https://www.virustotal.com/gui/ip-address/${encoded}">VirusTotal</a> | ` +
        `<a href="https://www.shodan.io/host/${encoded}">Shodan</a> | ` +
        `<a href="https://www.abuseipdb.com/check/${encoded}">AbuseIPDB</a> | ` +
        `<a href="https://talosintelligence.com/reputation_center/lookup?search=${encoded}">Talos</a></div>`
      );
    })
    .join("");
}

/**
 * Renderiza o bloco da análise de IA.
 *
 * @param {Object} ai Resultado da análise.
 * @returns {string} O HTML do bloco, ou string vazia.
 */
function renderAiHtmlBlock(ai) {
  if (!ai || !ai.text) return "";

  const structured = ai.structured;
  const heading = structured
    ? `✨ ANÁLISE IA — ${escapeHtml(structured.veredito)} (confiança ${
        structured.confianca
      }%)`
    : "✨ ANÁLISE IA (GEMINI)";

  // O texto é escapado antes de qualquer conversão, então nada que o modelo
  // (ou o e-mail analisado, via ele) produza vira HTML ativo.
  const body = escapeHtml(ai.text)
    .replace(/\n/g, "<br>")
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");

  const injectionWarning =
    structured && structured.tentativa_de_manipulacao
      ? `<div style="background:#fce8e6;border-left:4px solid #d93025;padding:8px;margin-bottom:8px;font-size:12px;">
           <strong>Atenção:</strong> o conteúdo analisado continha texto tentando manipular o
           analisador automatizado — indicador forte de malícia.
         </div>`
      : "";

  return `
  <div style="border:2px solid #8e24aa;border-radius:8px;overflow:hidden;margin:16px 0;">
    <div style="background:#8e24aa;color:#fff;padding:8px 12px;font-weight:bold;">${heading}</div>
    <div style="padding:12px;background:#fff;font-size:13px;line-height:1.5;color:#333;">
      ${injectionWarning}${body}
    </div>
  </div>`;
}

/**
 * Gera o nome do arquivo .eml anexado.
 *
 * @param {string} subject Assunto do e-mail.
 * @param {Date} date Data do e-mail.
 * @returns {string} O nome do arquivo.
 */
function generateEmlFilename(subject, date) {
  // coerceDate evita que um header Date malformado derrube o relatório.
  const safeDate = coerceDate(date);
  const timestamp = Utilities.formatDate(safeDate, "UTC", "yyyy-MM-dd_HH-mm-ss");

  const cleanedSubject = String(subject || "")
    .replace(/[^a-zA-Z0-9\s]/g, "")
    .substring(0, 30)
    .trim()
    .replace(/\s+/g, "_");

  return `phishing_report_${timestamp}${cleanedSubject ? "_" + cleanedSubject : ""}.eml`;
}
