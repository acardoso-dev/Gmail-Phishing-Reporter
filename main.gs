/**
 * @fileoverview Main logic for the Gmail Phishing Reporter add-on.
 * This script builds the add-on interface and handles the logic for
 * forwarding suspicious emails to the security team.
 *
 * gr-cyber.dev - Add-on do Gmail para Reporte de Phishing
 */

/**
 * Entry point for the add-on. Builds the add-on interface in Gmail.
 * This function is called when the add-on is loaded.
 *
 * @param {Object} e The event object from Gmail.
 * @returns {Card[]} An array of cards to display in the add-on.
 */
function buildAddOn(e) {
  try {
    let emailData = null;

    // Tenta obter o ID da mensagem se estiver disponível no evento
    if (e && e.messageMetadata && e.messageMetadata.messageId) {
      try {
        emailData = getEmailData(e.messageMetadata.messageId);
      } catch (err) {
        console.warn(
          "Não foi possível carregar dados do e-mail no buildAddOn:",
          err
        );
      }
    } else if (e && e.gmail && e.gmail.messageId) {
      try {
        emailData = getEmailData(e.gmail.messageId);
      } catch (err) {
        console.warn(
          "Não foi possível carregar dados do e-mail no buildAddOn (gmail scope):",
          err
        );
      }
    }

    const card = CardService.newCardBuilder()
      .setHeader(
        CardService.newCardHeader()
          .setTitle("Reporte de Phishing")
          .setImageUrl(CONFIG.LOGO_URL)
      )
      .addSection(createMainSection(emailData))
      .build();

    return [card];
  } catch (error) {
    console.error("Erro ao construir o add-on:", error);
    return [
      createErrorViewCard(
        "Falha ao carregar o add-on. Por favor, tente novamente."
      ),
    ];
  }
}

/**
 * Creates the main section of the add-on with action buttons.
 *
 * @param {Object} emailData The data of the current email (optional).
 * @returns {CardSection} The main card section with buttons.
 */
function createMainSection(emailData) {
  const section = CardService.newCardSection();
  if (emailData) {
    section.addWidget(
      CardService.newTextParagraph().setText(
        `<b>De:</b> ${emailData.from}\n<b>Assunto:</b> ${emailData.subject}`
      )
    );
  }

  // Risk Analysis Widget (UI)
  if (emailData && emailData.iocReport && emailData.iocReport.riskAnalysis) {
    const risk = emailData.iocReport.riskAnalysis;
    const scoreText = `<b>ANÁLISE DE RISCO:</b> ${risk.score}/100`;
    let riskColor = "#555555";
    if (risk.classification.includes("CONFIRMED")) riskColor = "#990000";
    else if (risk.classification.includes("LIKELY")) riskColor = "#d93025";
    else if (risk.classification === "SUSPICIOUS") riskColor = "#f29900";
    else if (risk.classification === "BENIGN") riskColor = "#188038";

    const classText = `<b>Classificação:</b> <font color="${riskColor}">${risk.classification}</font>`;

    section.addWidget(CardService.newDivider());
    section.addWidget(
      CardService.newTextParagraph().setText(`${scoreText}\n${classText}`)
    );

    // Show top reasons (max 3)
    if (risk.reasons && risk.reasons.length > 0) {
      const topReasons = risk.reasons.slice(0, 3).join("\n- ");
      section.addWidget(
        CardService.newTextParagraph().setText(
          `<b>Motivos:</b>\n- ${topReasons}`
        )
      );
    }
  }

  // Authentication Checklist Widget
  if (emailData && emailData.iocReport && emailData.iocReport.authenticationResults) {
    const auth = emailData.iocReport.authenticationResults;
    const spfText = getAuthStatusIcon(auth.spf);
    const dkimText = getAuthStatusIcon(auth.dkim);
    const dmarcText = getAuthStatusIcon(auth.dmarc);

    const authText = `<b>Segurança do Remetente:</b>\n` +
      `• SPF (IP Autorizado): ${spfText}\n` +
      `• DKIM (Assinatura Cripto): ${dkimText}\n` +
      `• DMARC (Política de Domínio): ${dmarcText}`;

    section.addWidget(CardService.newDivider());
    section.addWidget(
      CardService.newTextParagraph().setText(authText)
    );
  }

  // Sanitized URLs List Widget
  if (emailData && emailData.iocReport && emailData.iocReport.urls && emailData.iocReport.urls.length > 0) {
    const uniqueDefanged = [];
    const seen = new Set();
    emailData.iocReport.urls.forEach(function(u) {
      const defanged = defangUrl(u, true);
      if (defanged && !seen.has(defanged)) {
        seen.add(defanged);
        uniqueDefanged.push(defanged);
      }
    });

    const urlsList = uniqueDefanged.slice(0, 5).map(function(d) {
      return `• <font color="#555555"><code>${escapeHtml(d)}</code></font>`;
    }).join("\n");
    
    let urlText = `<b>Links Encontrados (${emailData.iocReport.urls.length}):</b>\n${urlsList}`;
    if (uniqueDefanged.length > 5) {
      urlText += `\n...e mais ${uniqueDefanged.length - 5} domínios.`;
    }
    
    section.addWidget(CardService.newDivider());
    section.addWidget(
      CardService.newTextParagraph().setText(urlText)
    );
  }

  return section
    .addWidget(CardService.newDivider())
    .addWidget(
      CardService.newButtonSet().addButton(
        CardService.newTextButton()
          .setText("Reportar Phishing")
          .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
          .setBackgroundColor("#d93025")
          .setOnClickAction(
            CardService.newAction().setFunctionName("reportPhishing")
          )
      )
    )
    .addWidget(
      CardService.newTextParagraph().setText(
        "Suspeita comum, ninguém interagiu, só quer sinalizar/treinar filtro."
      )
    )
    .addWidget(CardService.newDivider())
    .addWidget(
      CardService.newButtonSet().addButton(
        CardService.newTextButton()
          .setText("Solicitar Investigação por IA")
          .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
          .setBackgroundColor("#fbbc04")
          .setOnClickAction(
            CardService.newAction().setFunctionName("requestInvestigation")
          )
      )
    )
    .addWidget(
      CardService.newTextParagraph().setText(
        "Houve interação (clique/login/download), dúvida de comprometimento, ou impacto/urgência."
      )
    )

    .addWidget(CardService.newDivider());
}

/**
 * Handles the 'Report Phishing' action.
 *
 * @param {Object} e The event object from the button click.
 * @returns {ActionResponse} The response to show after the action.
 */
function reportPhishing(e) {
  return forwardEmail(e, CONFIG.PHISHING_PREFIX, "phishing");
}

/**
 * Handles the 'Request Investigation' action.
 *
 * @param {Object} e The event object from the button click.
 * @returns {ActionResponse} The response to show after the action.
 */
function requestInvestigation(e) {
  return forwardEmail(e, CONFIG.INVESTIGATION_PREFIX, "investigation");
}

/**
 * Forwards the current email as an .eml attachment to the security team.
 *
 * @param {Object} e The event object from the action.
 * @param {string} subjectPrefix The prefix for the report email subject.
 * @param {string} reportType The type of report ('phishing' or 'investigation').
 * @returns {ActionResponse} A success or error card.
 */
function forwardEmail(e, subjectPrefix, reportType) {
  try {
    const messageId = e && e.gmail && e.gmail.messageId;
    if (!messageId) {
      return createErrorCard(
        "Por favor, abra um e-mail e tente novamente pelo add-on."
      );
    }

    const emailData = getEmailData(messageId);

    const emlBlob = Utilities.newBlob(
      emailData.raw,
      "message/rfc822",
      generateEmlFilename(emailData.subject, emailData.date)
    );

    const reportSubject = `${subjectPrefix} ${emailData.subject}`.trim();

    // --- Gemini Analysis Integration (Only for Investigation) ---
    if (reportType === "investigation") {
      try {
        if (!emailData.geminiAnalysis) {
          emailData.geminiAnalysis = analyzePhishingWithGemini(emailData);
        }
      } catch (gErr) {
        console.warn(
          "Gemini analysis failed cleanly so we don't block reporting:",
          gErr
        );
        emailData.geminiAnalysis = "Análise ignorada devido a erro interno.";
      }
    }

    const { plainBody, htmlBody } = createReportBody(emailData, reportType);

    const iocBlob = Utilities.newBlob(
      JSON.stringify(emailData.iocReport, null, 2),
      "application/json",
      "ioc_report.json"
    );

    GmailApp.sendEmail(getSecurityEmail(reportType), reportSubject, plainBody, {
      attachments: [emlBlob, iocBlob],
      htmlBody: htmlBody,
    });

    try {
      // Label application
      const labelName = CONFIG.LABEL_REPORTED || "Reported/Phishing";
      const label = GmailApp.createLabel(labelName);
      const msg = GmailApp.getMessageById(messageId);
      msg.addLabel(label);
    } catch (labelErr) {
      console.warn("Não foi possível aplicar o label:", labelErr);
    }

    // --- Slack Integration ---
    try {
      sendSlackNotification(emailData, reportType);
    } catch (slackErr) {
      console.warn("Erro ao enviar notificação para o Slack:", slackErr);
    }

    return createSuccessCard(reportType, messageId);
  } catch (error) {
    console.error(`Erro ao processar reporte (${reportType}):`, error);
    return createErrorCard(getErrorMessage(error));
  }
}

/**
 * Retrieves email data using the Gmail API.
 *
 * @param {string} messageId The ID of the message to retrieve.
 * @returns {Object} An object containing the email data.
 */
function getEmailData(messageId) {
  try {
    const message = Gmail.Users.Messages.get("me", messageId, {
      format: "raw",
    });

    const rawBytes = Utilities.base64DecodeWebSafe(message.raw);
    const rawContent = Utilities.newBlob(rawBytes).getDataAsString();

    const headers = parseEmailHeaders(rawContent);

    return {
      raw: rawContent,
      gmailMessageId: messageId,
      subject: cleanSubject(headers.subject || "Sem Assunto"),
      from: cleanEmailAddress(headers.from || "Remetente Desconhecido"),
      to: cleanEmailAddress(headers.to || "Destinatário Desconhecido"),
      replyTo: headers.replyTo ? cleanEmailAddress(headers.replyTo) : null,
      returnPath: headers.returnPath
        ? cleanEmailAddress(headers.returnPath)
        : null,
      xOriginalFrom: headers.xOriginalFrom
        ? cleanEmailAddress(headers.xOriginalFrom)
        : null,
      date: headers.date ? new Date(headers.date) : new Date(),
      messageId: headers.messageId || null,
      userAgent: headers.userAgent || null,
      iocReport: buildIocReportFromRaw(rawContent),
      attachments: parseAttachments(rawContent),
    };
  } catch (error) {
    console.error("API Gmail falhou, usando GmailApp:", error);
    const message = GmailApp.getMessageById(messageId);

    return {
      raw:
        typeof message.getRawContent === "function"
          ? message.getRawContent()
          : message.getBody() || "",
      gmailMessageId: messageId,
      subject: cleanSubject(message.getSubject()),
      from: cleanEmailAddress(message.getFrom()),
      to: cleanEmailAddress(message.getTo()),
      replyTo: null,
      returnPath: null, // GmailApp doesn't easily expose Return-Path without raw content
      xOriginalFrom: null,
      date: message.getDate(),
      messageId: null,
      userAgent: null,
      attachments: message.getAttachments().map((att) => ({
        name: att.getName(),
        type: att.getContentType(),
        size: typeof att.getSize === "function" ? att.getSize() : null,
      })),
      iocReport: buildIocReportFromRaw(
        typeof message.getRawContent === "function"
          ? message.getRawContent()
          : message.getBody() || ""
      ),
    };
  }
}

/**
 * Parses email headers from raw email content.
 *
 * @param {string} rawContent The raw content of the email.
 * @returns {Object} An object containing the parsed headers.
 */
function parseEmailHeaders(rawContent) {
  const headers = {};
  const headerSection = rawContent.split(/\r?\n\r?\n/)[0] || "";

  const headerPatterns = {
    subject: /^Subject:\s*(.*)$/im,
    from: /^From:\s*(.*)$/im,
    to: /^To:\s*(.*)$/im,
    replyTo: /^Reply-To:\s*(.*)$/im,
    date: /^Date:\s*(.*)$/im,
    messageId: /^Message-ID:\s*(.*)$/im,
    userAgent: /^(User-Agent|X-Mailer):\s*(.*)$/im,
    returnPath: /^Return-Path:\s*(.*)$/im,
    xOriginalFrom: /^X-Original-From:\s*(.*)$/im,
  };

  for (const [key, pattern] of Object.entries(headerPatterns)) {
    const match = headerSection.match(pattern);
    if (match) {
      let val = (key === "userAgent" ? match[2] || match[1] : match[1]).trim();
      if (key === "messageId") {
        val = val.replace(/^<|>$/g, "");
      }
      headers[key] = val;
    }
  }

  return headers;
}

/**
 * Parses attachment information from raw email content.
 *
 * @param {string} rawContent The raw content of the email.
 * @returns {Array<Object>} An array of attachment objects.
 */
function parseAttachments(rawContent) {
  const attachments = [];
  const attachmentRegex =
    /Content-Disposition:\s*(attachment|inline)[^;]*;\s*filename[*]?=([^;\r\n]+)/gi;

  let match;
  while ((match = attachmentRegex.exec(rawContent))) {
    let filename = match[2].trim().replace(/["']/g, "");

    if (filename.includes("UTF-8''")) {
      filename = decodeURIComponent(filename.split("UTF-8''")[1]);
    }

    attachments.push({
      name: filename,
      type: "application/octet-stream",
    });
  }

  return attachments;
}

/**
 * Generates a filename for the .eml attachment.
 *
 * @param {string} subject The subject of the email.
 * @param {Date} date The date of the email.
 * @returns {string} The generated filename.
 */
function generateEmlFilename(subject, date) {
  const timestamp = Utilities.formatDate(date, "UTC", "yyyy-MM-dd_HH-mm-ss");
  const cleanedSubject = subject
    .replace(/[^a-zA-Z0-9\s]/g, "")
    .substring(0, 30)
    .trim()
    .replace(/\s+/g, "_");

  return `phishing_report_${timestamp}_${cleanedSubject}.eml`;
}

/**
 * Creates the body of the report email (plain text and HTML).
 *
 * @param {Object} emailData The data of the suspicious email.
 * @param {string} reportType The type of report ('phishing' or 'investigation').
 * @returns {{plainBody: string, htmlBody: string}} The plain text and HTML bodies of the report.
 */
/**
 * Creates the body of the report email (plain text and HTML).
 *
 * @param {Object} emailData The data of the suspicious email.
 * @param {string} reportType The type of report ('phishing' or 'investigation').
 * @returns {{plainBody: string, htmlBody: string}} The plain text and HTML bodies of the report.
 */
function createReportBody(emailData, reportType) {
  const reporter = Session.getActiveUser().getEmail();

  // Basic validation
  if (!reporter || !reporter.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
    // Fallback if needed, but usually Session.getActiveUser() is reliable
    console.warn("User email format check failed or empty.");
  }

  const nowUtc = new Date();
  const nowLocal = new Date();
  const reportTimeUtc =
    nowUtc.toISOString().replace("T", " ").split(".")[0] + " UTC";

  const userTimeZone = getUserTimeZone();
  const reportTimeLocal =
    nowLocal.toLocaleString("pt-BR", {
      timeZone: userTimeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }) + ` (${userTimeZone})`;
  const reportTime = `${reportTimeLocal}\n${reportTimeUtc}`;

  const emailDate = emailData.date
    ? emailData.date.toISOString().replace("T", " ").split(".")[0] + " UTC"
    : "Data desconhecida";

  const isInvestigation = reportType === "investigation";

  const attachmentInfo =
    emailData.attachments && emailData.attachments.length > 0
      ? emailData.attachments.map((a) => a.name).join(", ")
      : "Nenhum";

  const attachmentInfoHtml =
    emailData.attachments && emailData.attachments.length > 0
      ? emailData.attachments.map((a) => escapeHtml(a.name)).join(", ")
      : "Nenhum";

  const actionRequiredTxt = isInvestigation
    ? "\n\n⚠️ AÇÃO NECESSÁRIA: O usuário solicitou uma investigação e espera uma resposta.\n"
    : "";

  const rfc822Link = emailData.messageId
    ? buildRfc822SearchLink(emailData.messageId)
    : null;

  // --- IoC Data Preparation ---
  const ioc = emailData.iocReport || {};

  const receivedIpsStr =
    ioc.receivedIPs && ioc.receivedIPs.length > 0
      ? ioc.receivedIPs.join(", ")
      : "Nenhum identificado";

  const authResults = ioc.authenticationResults || {};
  const authStr = `SPF: ${authResults.spf || "N/A"}, DKIM: ${
    authResults.dkim || "N/A"
  }, DMARC: ${authResults.dmarc || "N/A"}`;

  const flagsStr =
    ioc.suspiciousFlags && ioc.suspiciousFlags.length > 0
      ? ioc.suspiciousFlags.join(", ")
      : "Nenhuma flag automática";

  // --- Risk Analysis Data ---
  const risk = ioc.riskAnalysis || {
    score: 0,
    classification: "UNKNOWN",
    reasons: [],
  };
  const riskColorMap = {
    "PHISHING CONFIRMED": "#990000", // Dark Red
    "PHISHING LIKELY": "#d93025", // Red
    SUSPICIOUS: "#f29900", // Orange
    BENIGN: "#188038", // Green
    UNKNOWN: "#555555",
  };
  const riskColor = riskColorMap[risk.classification] || "#555555";

  // --- Plain Text Body ---
  const plainBody = `${
    isInvestigation ? "SOLICITAÇÃO DE INVESTIGAÇÃO" : "REPORTE DE PHISHING"
  }
  Relatado em: ${reportTime}
  Repórter: ${reporter}
  
  ANÁLISE DE RISCO (SOC):
  • Score: ${risk.score}/100
  • Classificação: ${risk.classification}
  • Motivos: ${
    risk.reasons.length > 0
      ? risk.reasons.join(", ")
      : "Nenhum fator de risco identificado."
  }

  DETALHES DO E-MAIL SUSPEITO:
  • De: ${emailData.from}
  • Para: ${emailData.to}${
    emailData.replyTo ? `\n• Responder para: ${emailData.replyTo}` : ""
  }
  • Assunto: ${emailData.subject}
  • Data do e-mail: ${emailDate}${
    emailData.messageId ? `\n• Message-ID: ${emailData.messageId}` : ""
  }${emailData.userAgent ? `\n• User-Agent: ${emailData.userAgent}` : ""}
  
  INFO. TÉCNICAS (IOCs & SPOOFING):
  • Header From: ${emailData.from} (Domínio: ${getDomainFromEmail(
    emailData.from
  )})
  • Return-Path: ${
    emailData.returnPath || "N/A"
  } (Domínio: ${getDomainFromEmail(emailData.returnPath)})
  ${
    emailData.xOriginalFrom
      ? `• X-Original-From: ${emailData.xOriginalFrom}\n`
      : ""
  }
  • IPs de Origem (Received): ${receivedIpsStr}
  • Autenticação: ${authStr}
  • Flags Suspeitas: ${flagsStr}

  ANÁLISE IA (GEMINI):
  -------------------------------------------------------------
  ${emailData.geminiAnalysis || "Análise não disponível."}
  -------------------------------------------------------------
  
  • Anexos: ${attachmentInfo}${
    rfc822Link ? `\n• Link Gmail (busca por Message-ID): ${rfc822Link}` : ""
  }
  
  E-mail original anexado como arquivo .eml com cabeçalhos completos preservados.
  Relatório JSON de IoCs anexado.${actionRequiredTxt}`;

  // --- HTML Body ---
  const investigationAlert = isInvestigation
    ? `<div style="background:#fff3cd;border:1px solid #ffeaa7;padding:12px;margin:20px 0;border-left:4px solid #fbbc04;">
           <strong>⚠️ AÇÃO NECESSÁRIA:</strong> O usuário solicitou uma investigação e espera uma resposta.
         </div>`
    : "";

  const htmlBody = `
  <div style="font-family:Arial, sans-serif; max-width:640px;">
    <h2 style="color:${isInvestigation ? "#fbbc04" : "#d93025"};margin:0;">
      ${isInvestigation ? "SOLICITAÇÃO DE INVESTIGAÇÃO" : "REPORTE DE PHISHING"}
    </h2>
  
    <div style="background:#f5f5f5;padding:10px;margin:12px 0;">
      <strong>Relatado em:</strong><br>
      <div style="margin-left:10px;">
        <strong>Local (${escapeHtml(userTimeZone)}):</strong> ${escapeHtml(
    nowLocal.toLocaleString("pt-BR", {
      timeZone: userTimeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    })
  )}<br>
        <strong>UTC:</strong> ${escapeHtml(reportTimeUtc)}
      </div>
      <strong>Repórter:</strong> ${escapeHtml(reporter)}
    </div>
  
    ${investigationAlert}
    
    <div style="border: 2px solid ${riskColor}; border-radius: 8px; overflow: hidden; margin: 16px 0;">
      <div style="background: ${riskColor}; color: white; padding: 8px 12px; font-weight: bold;">
        ANÁLISE DE RISCO
      </div>
      <div style="padding: 12px; background: #fff;">
        <div style="font-size: 24px; font-weight: bold; color: ${riskColor}; margin-bottom: 4px;">
          ${
            risk.score
          } <span style="font-size: 14px; color: #555; font-weight: normal;">/ 100</span>
        </div>
        <div style="font-size: 16px; font-weight: bold; margin-bottom: 8px;">
          ${escapeHtml(risk.classification)}
        </div>
        ${
          risk.reasons.length > 0
            ? `<ul style="margin: 0; padding-left: 20px; color: #333;">
                ${risk.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}
              </ul>`
            : `<span style="color: #188038;">Nenhum fator de risco óbvio identificado automaticamente.</span>`
        }
      </div>
    </div>

    <!-- WIDGET GEMINI AI -->
    <div style="border: 2px solid #8e24aa; border-radius: 8px; overflow: hidden; margin: 16px 0;">
      <div style="background: linear-gradient(90deg, #8e24aa, #ba68c8); color: white; padding: 8px 12px; font-weight: bold; display: flex; align-items: center;">
         ✨ ANÁLISE IA (GEMINI)
      </div>
      <div style="padding: 12px; background: #fff; font-size: 14px; line-height: 1.5; color: #333;">
        ${
          emailData.geminiAnalysis
            ? escapeHtml(emailData.geminiAnalysis)
                .replace(/\n/g, "<br>")
                .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
            : "Análise não disponível."
        }
      </div>
    </div>
  
    <h3 style="margin:16px 0 8px;">Detalhes do e-mail suspeito</h3>
    <table style="border-collapse:collapse;width:100%;">
      <tr style="background:#f5f5f5;">
        <td style="padding:8px;border:1px solid #ddd;"><strong>De:</strong></td>
        <td style="padding:8px;border:1px solid #ddd;">${escapeHtml(
          emailData.from
        )}</td>
      </tr>
      <tr>
        <td style="padding:8px;border:1px solid #ddd;"><strong>Para:</strong></td>
        <td style="padding:8px;border:1px solid #ddd;">${escapeHtml(
          emailData.to
        )}</td>
      </tr>
      ${
        emailData.replyTo
          ? `
      <tr style="background:#f5f5f5;">
        <td style="padding:8px;border:1px solid #ddd;"><strong>Responder para:</strong></td>
        <td style="padding:8px;border:1px solid #ddd;color:#d93025;"><strong>${escapeHtml(
          emailData.replyTo
        )}</strong></td>
      </tr>`
          : ""
      }
      <tr${emailData.replyTo ? "" : ' style="background:#f5f5f5;"'}>
        <td style="padding:8px;border:1px solid #ddd;"><strong>Assunto:</strong></td>
        <td style="padding:8px;border:1px solid #ddd;">${escapeHtml(
          emailData.subject
        )}</td>
      </tr>
      <tr${emailData.replyTo ? ' style="background:#f5f5f5;"' : ""}>
        <td style="padding:8px;border:1px solid #ddd;"><strong>Data do e-mail:</strong></td>
        <td style="padding:8px;border:1px solid #ddd;">${escapeHtml(
          emailDate
        )}</td>
      </tr>
      ${
        emailData.messageId
          ? `
      <tr${emailData.replyTo ? "" : ' style="background:#f5f5f5;"'}>
        <td style="padding:8px;border:1px solid #ddd;"><strong>Message-ID:</strong></td>
        <td style="padding:8px;border:1px solid #ddd;font-family:monospace;font-size:12px;">${escapeHtml(
          emailData.messageId
        )}</td>
      </tr>`
          : ""
      }

      <tr>
        <td colspan="2" style="padding:8px;background:#e0f2f1;border:1px solid #ddd;"><strong>Indicators of Compromise (IoC)</strong></td>
      </tr>
      <tr>
        <td style="padding:8px;border:1px solid #ddd;"><strong>IPs de Origem:</strong></td>
        <td style="padding:8px;border:1px solid #ddd;font-family:monospace;">
          ${escapeHtml(receivedIpsStr)}
        </td>
      </tr>
      <tr>
        <td style="padding:8px;border:1px solid #ddd;"><strong>Consultar Reputação:</strong></td>
        <td style="padding:8px;border:1px solid #ddd;">
          ${
            ioc.receivedIPs && ioc.receivedIPs.length > 0
              ? ioc.receivedIPs
                  .map((ip) => {
                    return `
                    <div style="margin-bottom: 8px; border-bottom: 1px solid #eee; padding-bottom: 4px;">
                      <strong>${escapeHtml(ip)}</strong>: 
                      <a href="https://www.virustotal.com/gui/ip-address/${ip}" target="_blank">VirusTotal</a> |
                      <a href="https://www.shodan.io/host/${ip}" target="_blank">Shodan</a> |
                      <a href="https://www.abuseipdb.com/check/${ip}" target="_blank">AbuseIPDB</a> |
                      <a href="https://talosintelligence.com/reputation_center/lookup?search=${ip}" target="_blank">Talos</a>
                    </div>
                  `;
                  })
                  .join("")
              : "Nenhum IP para consultar."
          }
        </td>
      </tr>
      <tr style="background:#f5f5f5;">
        <td style="padding:8px;border:1px solid #ddd;"><strong>Autenticação:</strong></td>
        <td style="padding:8px;border:1px solid #ddd;">
           ${escapeHtml(authStr)}
        </td>
      </tr>
      <tr>
        <td style="padding:8px;border:1px solid #ddd;"><strong>Spoofing Check:</strong></td>
        <td style="padding:8px;border:1px solid #ddd;">
           From: ${escapeHtml(getDomainFromEmail(emailData.from))}<br>
           Return-Path: ${escapeHtml(
             getDomainFromEmail(emailData.returnPath)
           )}<br>
           Flags: <strong style="color:#d93025;">${escapeHtml(
             flagsStr
           )}</strong>
        </td>
      </tr>
      ${
        ioc.urls && ioc.urls.length > 0
          ? `
      <tr style="background:#f5f5f5;">
         <td style="padding:8px;border:1px solid #ddd;"><strong>URLs Encontradas:</strong></td>
         <td style="padding:8px;border:1px solid #ddd;font-size:11px;word-break:break-all;">
            ${ioc.urls
              .slice(0, 5)
              .map((u) => escapeHtml(u))
              .join("<br>")}
            ${ioc.urls.length > 5 ? `<br>...e mais ${ioc.urls.length - 5}` : ""}
         </td>
      </tr>`
          : ""
      }

      <tr>
        <td style="padding:8px;border:1px solid #ddd;"><strong>Anexos:</strong></td>
        <td style="padding:8px;border:1px solid #ddd;">${attachmentInfoHtml}</td>
      </tr>
      ${
        rfc822Link
          ? `
      <tr style="background:#f5f5f5;">
        <td style="padding:8px;border:1px solid #ddd;"><strong>Gmail:</strong></td>
        <td style="padding:8px;border:1px solid #ddd;"><a href="${escapeHtml(
          rfc822Link
        )}">Abrir busca por Message-ID</a></td>
      </tr>`
          : ""
      }
    </table>
  
    <p style="margin-top:20px;padding:10px;background:#e8f5e9;border-left:4px solid #34a853;">
      <strong>Anexos:</strong><br> 
      1. E-mail original (.eml) com cabeçalhos completos consultem em <a href="https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx">MXtoolbox EmailHeaders</a><br>
      2. Relatório de IoCs (.json) pronto para ingestão.
    </p>
  </div>
  `;

  return { plainBody, htmlBody };
}

/**
 * Creates a success card to display after a successful report.
 *
 * @param {string} reportType The type of report ('phishing' or 'investigation').
 * @param {string} messageId The ID of the reported message.
 * @returns {ActionResponse} The success card to display.
 */
function createSuccessCard(reportType, messageId) {
  const isInvestigation = reportType === "investigation";
  const title = isInvestigation
    ? "Investigação solicitada"
    : "Phishing relatado";
  const subtitle = isInvestigation
    ? "Sua solicitação foi enviada. A equipe de segurança entrará em contato em breve."
    : "Obrigado por denunciar. A equipe de segurança foi notificada.";

  const section = CardService.newCardSection().addWidget(
    CardService.newTextParagraph().setText(subtitle)
  );

  if (messageId) {
    section.addWidget(
      CardService.newButtonSet().addButton(
        CardService.newTextButton()
          .setText("Mover para Spam")
          .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
          .setBackgroundColor("#d93025")
          .setOnClickAction(
            CardService.newAction()
              .setFunctionName("moveToSpam")
              .setParameters({ messageId: messageId })
          )
      )
    );
  }

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle(title))
    .addSection(section)
    .build();

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card))
    .setNotification(
      CardService.newNotification()
        .setType(CardService.NotificationType.INFO)
        .setText("Relatório enviado com sucesso!")
    )
    .build();
}

/**
 * Moves the reported email to spam.
 *
 * @param {Object} e The event object.
 * @returns {ActionResponse} A notification indicating the action result.
 */
function moveToSpam(e) {
  try {
    const messageId = e.parameters.messageId;
    if (!messageId) {
      throw new Error("ID da mensagem não fornecido.");
    }

    const msg = GmailApp.getMessageById(messageId);
    const thread = msg.getThread();
    GmailApp.moveThreadToSpam(thread);

    return (
      CardService.newActionResponseBuilder()
        .setNotification(
          CardService.newNotification()
            .setType(CardService.NotificationType.INFO)
            .setText("E-mail movido para o Spam.")
        )
        // "Refresh" the card by updating it to a confirmed state
        .setNavigation(
          CardService.newNavigation().updateCard(createSpamMovedCard())
        )
        .build()
    );
  } catch (error) {
    console.error("Erro ao mover para spam:", error);

    // Se houver erro, assume que pode ser falta de permissão e oferece reautorização
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(createAuthCard()))
      .setNotification(
        CardService.newNotification()
          .setType(CardService.NotificationType.ERROR)
          .setText("Erro: " + error.toString() + ". Tente reautorizar.")
      )
      .build();
  }
}

/**
 * Creates a simple card showing that the email has been moved to spam.
 *
 * @returns {Card} The confirmation card.
 */
function createSpamMovedCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Concluído"))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          "✅ O e-mail foi movido para a caixa de Spam."
        )
      )
    )
    .build();
}

/**
 * Creates a card to request re-authorization.
 *
 * @returns {Card} The authorization card.
 */
function createAuthCard() {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Autorização Necessária")
        .setSubtitle("Novas permissões são necessárias")
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText(
            "O add-on foi atualizado e precisa de sua permissão para mover e-mails para o Spam. " +
              "Por favor, clique no botão abaixo para autorizar."
          )
        )
        .addWidget(
          CardService.newButtonSet().addButton(
            CardService.newTextButton()
              .setText("Autorizar Agora")
              .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
              .setBackgroundColor("#0b57d0")
              .setOnClickAction(
                CardService.newAction().setFunctionName("triggerAuth")
              )
          )
        )
    )
    .build();
}

/**
 * Triggers the authorization flow by calling a protected service.
 *
 * @returns {ActionResponse} A notification or card update.
 */
function triggerAuth() {
  // Tenta criar uma label para forçar a verificação do escopo gmail.modify
  // Se não tiver permissão, o runtime do Apps Script vai interromper e pedir autorização nativamente
  try {
    const label = GmailApp.createLabel(
      "AuthCheck_Temp_" + new Date().getTime()
    );
    GmailApp.deleteLabel(label);
  } catch (e) {
    // Se o erro for de permissão, relança para o Apps Script lidar
    if (
      e.toString().includes("permission") ||
      e.toString().includes("access")
    ) {
      throw e;
    }
    // Outros erros ignoramos por enquanto, pois o objetivo é só checar auth
    console.warn("Erro no triggerAuth (não permissão):", e);
  }

  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification()
        .setType(CardService.NotificationType.INFO)
        .setText(
          "Verificação de autorização concluída. Tente mover para spam novamente."
        )
    )
    .setNavigation(CardService.newNavigation().popCard())
    .build();
}

/**
 * Creates an error card to display when an action fails.
 *
 * @param {string} message The error message to display.
 * @returns {ActionResponse} The error card to display.
 */
function createErrorCard(message) {
  const card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Erro")
        .setSubtitle("Não foi possível enviar o relatório")
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText(message))
        .addWidget(
          CardService.newButtonSet().addButton(
            CardService.newTextButton()
              .setText("Tentar novamente")
              .setOnClickAction(
                CardService.newAction().setFunctionName("buildAddOn")
              )
          )
        )
    )
    .build();

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card))
    .build();
}

/**
 * Creates an error card for initial load failures.
 *
 * @param {string} message The error message to display.
 * @returns {Card} The error card to display.
 */
function createErrorViewCard(message) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Erro ao carregar")
        .setSubtitle("Tente novamente")
    )
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(message)
      )
    )
    .build();
}

/**
 * Maps error objects to user-friendly error messages.
 *
 * @param {Error} error The error object.
 * @returns {string} A user-friendly error message.
 */
function getErrorMessage(error) {
  const errorMap = {
    quota: "Limite diário de e-mails atingido. Tente novamente amanhã.",
    permission: "Permissão negada. Entre em contato com seu administrador.",
    invalid: "Configuração inválida. Entre em contato com o suporte.",
  };

  const errorStr = (error + "").toLowerCase();
  for (const [key, message] of Object.entries(errorMap)) {
    if (errorStr.includes(key)) return message;
  }

  return "Não foi possível enviar o relatório. Detalhes: " + errorStr;
}

/**
 * Detects the user's time zone.
 *
 * @returns {string} The user's time zone (e.g., 'America/Sao_Paulo').
 */
function getUserTimeZone() {
  try {
    const user = Session.getActiveUser();
    const userEmail = user.getEmail();

    if (userEmail && userEmail.includes("@")) {
      const domain = userEmail.split("@")[1].toLowerCase();

      const domainTimeZones = {
        "gmail.com": "America/Sao_Paulo",
        "google.com": "America/Sao_Paulo",
      };

      if (domainTimeZones[domain]) {
        return domainTimeZones[domain];
      }
    }

    const now = new Date();
    const utcOffset = now.getTimezoneOffset();

    if (utcOffset === -180) {
      return "America/Sao_Paulo";
    } else if (utcOffset === -240) {
      return "America/Manaus";
    } else if (utcOffset === -300) {
      return "America/Rio_Branco";
    }

    return "America/Sao_Paulo";
  } catch (error) {
    console.warn("Erro ao detectar fuso horário:", error);
    return "America/Sao_Paulo";
  }
}

/**
 * Escapes HTML special characters in a string.
 *
 * @param {string} text The string to escape.
 * @returns {string} The escaped string.
 */
function escapeHtml(text) {
  if (!text && text !== 0) return text;

  const htmlEntities = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "/": "&#x2F;",
  };
  return String(text).replace(/[&<>"'\/]/g, (m) => htmlEntities[m]);
}

/**
 * Cleans an email subject line by removing RFC 2047 encoded parts.
 *
 * @param {string} subject The email subject.
 * @returns {string} The cleaned subject.
 */
function cleanSubject(subject) {
  if (!subject) return "Sem Assunto";
  return (
    subject
      .replace(/=\?[^?]+\?[BbQq]\?[^?]*\?=/g, " ")
      .replace(/\s+/g, " ")
      .trim() || "Sem Assunto"
  );
}

/**
 * Extracts the email address from a sender string (e.g., "Name <email@example.com>").
 *
 * @param {string} sender The sender string.
 * @returns {string} The cleaned email address.
 */
function cleanEmailAddress(sender) {
  if (!sender) return "Remetente desconhecido";
  const match = sender.match(/<([^>]+@[^>]+)>/);
  return match ? match[1] : sender.trim();
}

/**
 * Extracts the domain from an email address.
 *
 * @param {string} email The email address.
 * @returns {string} The domain part of the email, or "N/A".
 */
function getDomainFromEmail(email) {
  if (!email) return "N/A";
  const m = email.match(/@([^\s>]+)/);
  if (m && m[1]) return m[1].toLowerCase();
  const hostm = email.match(/([a-z0-9\-._]+\.[a-z]{2,})/i);
  return hostm ? hostm[1].toLowerCase() : "N/A";
}

/**
 * Builds a Gmail search link for a given RFC822 Message-ID.
 *
 * @param {string} messageId The Message-ID of the email.
 * @returns {string|null} The Gmail search URL, or null on error.
 */
function buildRfc822SearchLink(messageId) {
  try {
    const q = "rfc822msgid:" + messageId;
    return "https://mail.google.com/mail/u/0/#search/" + encodeURIComponent(q);
  } catch (_) {
    return null;
  }
}

/** ======= Extensões para parseEmailHeaders e geração de IoC ======= */

/**
 * Extrai headers adicionais e normaliza em um objeto.
 * Recebe rawContent (string) e devolve headers básicos + arrays de Received, auth, dkim.
 */
function parseEmailHeadersExtended(rawContent) {
  const headers = {};
  const headerSection = rawContent.split(/\r?\n\r?\n/)[0] || "";

  // campos simples já existentes
  headers.subject =
    (headerSection.match(/^Subject:\s*(.*)$/im) || [null, null])[1] || null;
  headers.from =
    (headerSection.match(/^From:\s*(.*)$/im) || [null, null])[1] || null;
  headers.to =
    (headerSection.match(/^To:\s*(.*)$/im) || [null, null])[1] || null;
  headers.replyTo =
    (headerSection.match(/^Reply-To:\s*(.*)$/im) || [null, null])[1] || null;
  headers.date =
    (headerSection.match(/^Date:\s*(.*)$/im) || [null, null])[1] || null;
  headers.messageId =
    (headerSection.match(/^Message-ID:\s*(.*)$/im) || [null, null])[1] || null;
  headers.returnPath =
    (headerSection.match(/^Return-Path:\s*(.*)$/im) || [null, null])[1] || null;
  headers.xOriginalFrom =
    (headerSection.match(/^X-Original-From:\s*(.*)$/im) || [null, null])[1] ||
    null;

  // 1) Todas as Received (blocos possivelmente multilinha)
  const receivedBlocks = [];
  const receivedRegex = /(^Received:[\s\S]*?)(?=\r?\n[A-Za-z\-]+:|\r?\n$)/gim;
  let m;
  while ((m = receivedRegex.exec(headerSection))) {
    receivedBlocks.push(m[1].replace(/\r?\n\s+/g, " ")); // junta linhas continuadas
  }
  headers.receivedHeaders = receivedBlocks;

  // 2) Extrair IPs e hosts de received
  const ips = new Set();
  const hosts = new Set();

  // Helper validation for IPv4
  function isValidIp(ip) {
    // Avoid leading zeros if length > 1 (e.g., 024 is invalid octet in strict IPv4)
    const parts = ip.split(".");
    if (parts.length !== 4) return false;
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i];
      if (p.length > 1 && p.startsWith("0")) return false;
      var n = parseInt(p, 10);
      if (isNaN(n) || n < 0 || n > 255) return false;
    }
    return true;
  }

  receivedBlocks.forEach(function (rb) {
    // Regex that specifically looks for IPs with word boundaries or brackets
    // Prevents matching inside timestamps like 2024.10.23.20.13.07
    // [^0-9.] checks previous char is not digit/dot, matches strict start
    const ipRegex = /(?:^|[^0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?:[^0-9.]|$)/g;
    let mi;
    while ((mi = ipRegex.exec(rb))) {
      // mi[1] is the captured IP candidate
      if (isValidIp(mi[1])) {
        ips.add(mi[1]);
      }
    }

    // host antes de '(' ou ' [' ou ' by '
    const hostMatch = rb.match(/Received:\s*from\s+([^\s\(]+)\s*/i);
    if (hostMatch && hostMatch[1]) hosts.add(hostMatch[1]);
  });
  headers.receivedIPs = Array.from(ips);
  headers.receivedHosts = Array.from(hosts);

  // 3) Authentication-Results (single block parsing)
  const authMatch = headerSection.match(
    /(^Authentication-Results:[\s\S]*?)(?=\r?\n[A-Za-z\-]+:|\r?\n$)/im
  );
  if (authMatch && authMatch[1]) {
    headers.authenticationResultsRaw = authMatch[1].replace(/\r?\n\s+/g, " ");
    // tenta extrair spf/dkim/dmarc
    headers.authenticationResults = {
      spf: (authMatch[1].match(/spf=([a-z]+)/i) || [null, null])[1] || null,
      dkim: (authMatch[1].match(/dkim=([a-z]+)/i) || [null, null])[1] || null,
      dmarc: (authMatch[1].match(/dmarc=([a-z]+)/i) || [null, null])[1] || null,
    };
  }

  // 4) DKIM-Signature(s)
  const dkimBlocks = [];
  const dkimRegex = /(^DKIM-Signature:[\s\S]*?)(?=\r?\n[A-Za-z\-]+:|\r?\n$)/gim;
  while ((m = dkimRegex.exec(headerSection))) {
    const block = m[1].replace(/\r?\n\s+/g, " ");
    dkimBlocks.push(block);
  }
  headers.dkimSignatures = dkimBlocks.map(function (b) {
    const d = (b.match(/\bd=([^;\s]+)/i) || [null, null])[1] || null;
    const s = (b.match(/\bs=([^;\s]+)/i) || [null, null])[1] || null;
    const bh = (b.match(/\bb=([^;\s]+)/i) || [null, null])[1] || null;
    return { raw: b, d: d, s: s, b: bh };
  });

  // 5) qualquer X-Forwarded-Encrypted ou X-Google-Group-Id / List-ID
  headers.xForwardedEncrypted =
    (headerSection.match(/^X-Forwarded-Encrypted:\s*(.*)$/im) || [
      null,
      null,
    ])[1] || null;
  headers.listId =
    (headerSection.match(/^List-ID:\s*(.*)$/im) || [null, null])[1] || null;
  headers.xGoogleGroupId =
    (headerSection.match(/^X-Google-Group-Id:\s*(.*)$/im) || [null, null])[1] ||
    null;

  return headers;
}

/**
 * Calcula SHA-256 hex do raw .eml e das attachments (se houver blob).
 */
function computeSha256Hex(text) {
  const digest = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    text,
    Utilities.Charset.UTF_8
  );
  return digest
    .map(function (b) {
      const s = (b < 0 ? b + 256 : b).toString(16);
      return s.length === 1 ? "0" + s : s;
    })
    .join("");
}

/**
 * Extrai URLs do corpo (HTML + plain) — útil para IoC.
 * Trata codificações MIME como Quoted-Printable e Base64 recursivamente.
 */
function extractUrlsFromBody(rawContent) {
  const textParts = [];
  
  // Processa uma parte MIME recursivamente
  function processPart(headers, body) {
    const contentTypeMatch = headers.match(/Content-Type:\s*([^\s;]+)/i);
    const contentType = contentTypeMatch ? contentTypeMatch[1].toLowerCase() : "text/plain";
    
    if (contentType.startsWith("multipart/")) {
      const subBoundaryMatch = headers.match(/boundary=["']?([^"';\r\n]+)["']?/i);
      if (subBoundaryMatch) {
        const subBoundary = subBoundaryMatch[1];
        const subParts = body.split("--" + subBoundary);
        for (let i = 1; i < subParts.length - 1; i++) {
          const subPart = subParts[i];
          const splitIdx = subPart.search(/\r?\n\r?\n/);
          if (splitIdx !== -1) {
            const subHeaders = subPart.substring(0, splitIdx);
            const subBody = subPart.substring(splitIdx).replace(/^\r?\n\r?\n/, "");
            processPart(subHeaders, subBody);
          }
        }
      }
    } else if (contentType.startsWith("text/html") || contentType.startsWith("text/plain")) {
      const encodingMatch = headers.match(/Content-Transfer-Encoding:\s*([^\s;]+)/i);
      const encoding = encodingMatch ? encodingMatch[1].toLowerCase() : "";
      
      let decodedBody = body;
      if (encoding === "quoted-printable") {
        decodedBody = decodeQuotedPrintable(body);
      } else if (encoding === "base64") {
        decodedBody = decodeBase64(body);
      }
      textParts.push(decodedBody);
    }
  }
  
  // 1. Tenta decodificar via estrutura MIME
  const splitIdx = rawContent.search(/\r?\n\r?\n/);
  if (splitIdx !== -1) {
    const headers = rawContent.substring(0, splitIdx);
    const body = rawContent.substring(splitIdx).replace(/^\r?\n\r?\n/, "");
    processPart(headers, body);
  }
  
  // 2. Fail-safe Fallback: Se o parsing MIME falhar ou não encontrar partes,
  // ou para garantir que não perdemos nada, decodificamos o conteúdo bruto como QP
  const qpDecodedRaw = decodeQuotedPrintable(rawContent);
  textParts.push(qpDecodedRaw);
  
  // 3. Extração e limpeza de URLs
  const combinedBody = textParts.join("\n\n");
  const urlRegex = /https?:\/\/[^\s"'<>()\\]+/gi;
  const rawUrls = combinedBody.match(urlRegex) || [];
  
  const cleanedUrls = [];
  const seen = new Set();
  
  rawUrls.forEach(function(url) {
    // Limpeza de caracteres finais indesejados
    let cleanUrl = url.replace(/["';,>]+$/, "");
    
    // Filtro de namespaces XML, esquemas W3C e metadados que não são links reais
    if (cleanUrl && !isExcludedUrl(cleanUrl)) {
      if (!seen.has(cleanUrl)) {
        seen.add(cleanUrl);
        cleanedUrls.push(cleanUrl);
      }
    }
  });
  
  return cleanedUrls;
}

/**
 * Filtra URLs de metadados, esquemas XML e namespaces (como w3.org, schemas.microsoft.com).
 */
function isExcludedUrl(url) {
  const lowercaseUrl = url.toLowerCase();
  const exclusionPatterns = [
    "w3.org",
    "schemas.microsoft.com",
    "schemas.xmlsoap.org",
    "xml.org",
    "openxmlformats.org",
    "schemas.google.com",
    "activex.microsoft.com",
    "schemas.openxmlformats.org"
  ];
  return exclusionPatterns.some(function(pattern) {
    return lowercaseUrl.indexOf(pattern) !== -1;
  });
}

/**
 * Decodifica o formato Quoted-Printable.
 */
function decodeQuotedPrintable(text) {
  if (!text) return "";
  
  // 1. Remove quebras de linha suaves (sinal de igual no fim da linha)
  const temp = text.replace(/=\r?\n/g, "");
  
  // 2. Converte os bytes hexadecimais (=XX)
  const bytes = [];
  for (let i = 0; i < temp.length; i++) {
    const charCode = temp.charCodeAt(i);
    if (charCode === 61 && i + 2 < temp.length) { // 61 é '='
      const hex = temp.substring(i + 1, i + 3);
      if (/^[0-9A-F]{2}$/i.test(hex)) {
        bytes.push(parseInt(hex, 16));
        i += 2;
        continue;
      }
    }
    
    if (charCode < 128) {
      bytes.push(charCode);
    } else {
      const encoded = unescape(encodeURIComponent(temp.charAt(i)));
      for (let j = 0; j < encoded.length; j++) {
        bytes.push(encoded.charCodeAt(j));
      }
    }
  }
  
  const signedBytes = bytes.map(function(b) {
    return b > 127 ? b - 256 : b;
  });
  
  try {
    return Utilities.newBlob(signedBytes).getDataAsString("UTF-8");
  } catch (e) {
    return temp.replace(/=([0-9A-F]{2})/gi, function(match, hex) {
      return String.fromCharCode(parseInt(hex, 16));
    });
  }
}

/**
 * Decodifica o formato Base64.
 */
function decodeBase64(text) {
  if (!text) return "";
  try {
    const cleaned = text.replace(/\s+/g, "");
    const decodedBytes = Utilities.base64Decode(cleaned);
    return Utilities.newBlob(decodedBytes).getDataAsString("UTF-8");
  } catch (e) {
    return text;
  }
}

/**
 * Monta o JSON final de IoCs a partir do raw .eml.
 * Retorna objeto pronto para enviar ao SIEM/Elastic/CTI feed.
 */
function buildIocReportFromRaw(rawContent) {
  const headers = parseEmailHeadersExtended(rawContent);
  const rawSha = computeSha256Hex(rawContent);
  const urls = extractUrlsFromBody(rawContent);

  // domains únicos coletados de campos chaves
  const domainSet = new Set();
  function pushDomainFromEmailString(emailStr) {
    if (!emailStr) return;
    const m = emailStr.match(/@([^\s>]+)/);
    if (m && m[1]) domainSet.add(m[1].toLowerCase());
    // também tenta extrair hostnames do campo (ex: host.domain.com)
    const hostm = emailStr.match(/([a-z0-9\-._]+\.[a-z]{2,})/i);
    if (hostm && hostm[1]) domainSet.add(hostm[1].toLowerCase());
  }
  pushDomainFromEmailString(headers.from);
  pushDomainFromEmailString(headers.returnPath);
  pushDomainFromEmailString(headers.replyTo);
  headers.receivedHosts.forEach((h) => domainSet.add(h.toLowerCase()));
  urls.forEach((u) => {
    try {
      const host = new URL(u).hostname;
      domainSet.add(host.toLowerCase());
    } catch (e) {}
  });

  const report = {
    generated_at: new Date().toISOString(),
    raw_sha256: rawSha,
    subject: headers.subject || null,
    from: headers.from || null,
    to: headers.to || null,
    replyTo: headers.replyTo || null,
    returnPath: headers.returnPath || null,
    messageId: headers.messageId || null,
    receivedHeaders: headers.receivedHeaders,
    receivedIPs: headers.receivedIPs,
    receivedHosts: headers.receivedHosts,
    dkimSignatures: headers.dkimSignatures,
    authenticationResults: headers.authenticationResults || null,
    xForwardedEncrypted: headers.xForwardedEncrypted || null,
    listId: headers.listId || null,
    xGoogleGroupId: headers.xGoogleGroupId || null,
    urls: urls,
    domains: Array.from(domainSet),
    attachments: [], // preencha com parseAttachments e hashes se tiver
    suspiciousFlags: [],
  };

  // flags básicas automatizadas:
  if (
    report.replyTo &&
    !report.replyTo.includes(getDomainFromEmail(report.from))
  ) {
    report.suspiciousFlags.push("reply-to_different_from_from_domain");
  }
  if (
    report.returnPath &&
    getDomainFromEmail(report.returnPath) !== getDomainFromEmail(report.from)
  ) {
    report.suspiciousFlags.push("returnpath_different_from_from");
  }
  if (headers.dkimSignatures.length === 0)
    report.suspiciousFlags.push("no_dkim_signature_found");
  if (
    headers.authenticationResults &&
    headers.authenticationResults.dmarc &&
    headers.authenticationResults.dmarc.toLowerCase() !== "pass"
  ) {
    report.suspiciousFlags.push("dmarc_not_pass");
  }
  // examplo: se ARC/DARA falhar (procure 'dara=fail' no raw)
  if (/dara=fail/i.test(rawContent) || /darn=.*fail/i.test(rawContent)) {
    report.suspiciousFlags.push("arc_dara_fail");
  }

  // Checar Display Name Spoofing usando lista de contatos
  if (headers.from) {
    const displayName = getDisplayName(headers.from);
    if (displayName && displayName.length > 2) {
      try {
        const contacts = ContactsApp.getContactsByName(displayName);
        if (contacts && contacts.length > 0) {
          const senderEmail = cleanEmailAddress(headers.from);
          let emailMatched = false;
          
          for (let i = 0; i < contacts.length; i++) {
            const emails = contacts[i].getEmails();
            for (let j = 0; j < emails.length; j++) {
              if (emails[j].getAddress().toLowerCase() === senderEmail.toLowerCase()) {
                emailMatched = true;
                break;
              }
            }
            if (emailMatched) break;
          }
          
          if (!emailMatched) {
            report.suspiciousFlags.push("display_name_spoofing_contacts");
          }
        }
      } catch (contactErr) {
        console.warn("Erro ao consultar a lista de contatos:", contactErr);
      }
    }
  }

  // Risk Scoring Calculation
  report.riskAnalysis = calculateRiskScore(report);

  return report;
}

/** ======= Risk Scoring Model (SOC Logic) ======= */

const KNOWN_ESPS = [
  "mailchimp.com",
  "sendgrid.net",
  "amazonses.com",
  "hubspot.com",
  "hubspotemail.net",
  "salesforce.com",
  "pardot.com",
  "constantcontact.com",
  "sparkpostmail.com",
  "mailgun.org",
  "1e100.net", // Google
  "google.com",
];

const FLAG_WEIGHTS = {
  reply_to_mismatch: 25,
  returnpath_mismatch: 10,
  no_dkim: 20,
  dmarc_fail: 40,
  arc_fail: 15,
  display_name_spoof: 45,
};

/**
 * Checks if a domain belongs to a known/trusted ESP.
 */
function isKnownESP(domain) {
  if (!domain) return false;
  return KNOWN_ESPS.some((esp) => domain.endsWith(esp));
}

/**
 * Calculates a numeric risk score based on flags and context (ESP allowlist).
 *
 * @param {Object} report The IocReport object (with suspiciousFlags).
 * @returns {Object} { score: number, reasons: string[], classification: string }
 */
function calculateRiskScore(report) {
  let score = 0;
  const reasons = [];

  const fromDomain = getDomainFromEmail(report.from);
  const returnPathDomain = getDomainFromEmail(report.returnPath);
  const replyToDomain = getDomainFromEmail(report.replyTo);

  // --- Mailing List / Google Group Detection ---
  const isGoogleGroup =
    report.xGoogleGroupId ||
    (report.returnPath && report.returnPath.includes("googlegroups.com")) ||
    (report.listId && report.listId.includes("googlegroups.com"));

  const isMailingList = isGoogleGroup || !!report.listId;

  // Reply-To diferente
  if (report.suspiciousFlags.includes("reply-to_different_from_from_domain")) {
    // If it's a mailing list, mismatch is expected (From: sender, Reply-To: list OR From: list, Reply-To: sender)
    // We ignore it for lists to avoid false positives.
    if (!isMailingList) {
      const weight = isKnownESP(replyToDomain)
        ? 10
        : FLAG_WEIGHTS.reply_to_mismatch;
      score += weight;
      reasons.push(`Reply-To mismatch (+${weight})`);
    } else {
      // Optional: log mitigation
      // reasons.push(`Reply-To mismatch (Mitigated: Mailing List)`);
    }
  }

  // Return-Path diferente
  if (report.suspiciousFlags.includes("returnpath_different_from_from")) {
    // Return-Path for lists is usually the bouncer address (e.g. groupname+bnc...@googlegroups.com)
    // This is expected for lists.
    if (!isMailingList) {
      const weight = isKnownESP(returnPathDomain)
        ? 3
        : FLAG_WEIGHTS.returnpath_mismatch;
      score += weight;
      reasons.push(`Return-Path mismatch (+${weight})`);
    }
  }

  // DKIM ausente
  if (report.suspiciousFlags.includes("no_dkim_signature_found")) {
    score += FLAG_WEIGHTS.no_dkim;
    reasons.push("No DKIM signature (+20)");
  }

  // DMARC falhou
  if (report.suspiciousFlags.includes("dmarc_not_pass")) {
    // If it's a list, DMARC might fail if the list modifies the subject/body (breaking DKIM) and envelopes are rewritten (breaking SPF alignment for original sender)
    // However, ARC should handle this. If DMARC fails, it's still risky, but maybe less so if we identify it as a known group.
    // For now, we keep DMARC penalty but you might want to reduce it for Google Groups if ARC passes (but we only check DMARC here).
    score += FLAG_WEIGHTS.dmarc_fail;
    reasons.push("DMARC fail (+40)");
  }

  // ARC/DARA fail
  if (report.suspiciousFlags.includes("arc_dara_fail")) {
    // Lists are notorious for complicating ARC.
    // If identified strictly as a Google Group, we trust Google's infra more.
    if (!isGoogleGroup) {
      score += FLAG_WEIGHTS.arc_fail;
      reasons.push("ARC/DARA fail (+15)");
    } else {
      // Mitigate for Google Groups
      // reasons.push("ARC/DARA fail (Mitigated: Google Group)");
    }
  }

  // Display Name Spoofing baseada em Contatos
  if (report.suspiciousFlags.includes("display_name_spoofing_contacts")) {
    score += FLAG_WEIGHTS.display_name_spoof;
    reasons.push("Display Name matches contact but email differs (+45)");
  }

  const classification = classifyEmail(score);

  return {
    score,
    reasons,
    classification,
  };
}

/**
 * Classifies the email based on the score.
 */
function classifyEmail(score) {
  if (score >= 70) return "PHISHING CONFIRMED";
  if (score >= 40) return "PHISHING LIKELY";
  if (score >= 20) return "SUSPICIOUS";
  return "BENIGN";
}

/**
 * Sends a rich alert message to Slack using Incoming Webhooks.
 *
 * @param {Object} emailData The suspicious email data.
 * @param {string} reportType The type of report ('phishing' or 'investigation').
 */
function sendSlackNotification(emailData, reportType) {
  const webhookUrl = CONFIG.SLACK_WEBHOOK_URL;
  if (!webhookUrl || !webhookUrl.startsWith("https://hooks.slack.com/")) {
    console.log("Slack Webhook URL não configurada ou inválida. Notificação ignorada.");
    return;
  }

  const reporter = Session.getActiveUser().getEmail();
  const isInvestigation = reportType === "investigation";
  
  // Detalhes do Risco
  const risk = (emailData.iocReport && emailData.iocReport.riskAnalysis) || {
    score: 0,
    classification: "UNKNOWN",
    reasons: []
  };

  // Cores de barra lateral para o anexo do Slack baseadas na classificação
  let riskColor = "#555555"; // Grey
  if (risk.classification.includes("CONFIRMED")) riskColor = "#990000"; // Dark Red
  else if (risk.classification.includes("LIKELY")) riskColor = "#d93025"; // Red
  else if (risk.classification === "SUSPICIOUS") riskColor = "#f29900"; // Orange
  else if (risk.classification === "BENIGN") riskColor = "#188038"; // Green

  // Cabeçalho e Título
  const emoji = isInvestigation ? "🚨" : "⚠️";
  const title = isInvestigation 
    ? "*Nova Solicitação de Investigação por IA*" 
    : "*Novo Reporte de Phishing*";

  // --- IoC Data Preparation ---
  const ioc = emailData.iocReport || {};

  const receivedIpsStr =
    ioc.receivedIPs && ioc.receivedIPs.length > 0
      ? ioc.receivedIPs.join(", ")
      : "Nenhum identificado";

  const authResults = ioc.authenticationResults || {};
  const authStr = `SPF: ${authResults.spf || "N/A"}, DKIM: ${authResults.dkim || "N/A"}, DMARC: ${authResults.dmarc || "N/A"}`;

  const flagsStr =
    ioc.suspiciousFlags && ioc.suspiciousFlags.length > 0
      ? ioc.suspiciousFlags.join(", ")
      : "Nenhuma flag automática";

  let reputationLinksStr = "Nenhum IP para consultar";
  if (ioc.receivedIPs && ioc.receivedIPs.length > 0) {
    reputationLinksStr = ioc.receivedIPs.map(function(ip) {
      const vt = `https://www.virustotal.com/gui/ip-address/${ip}`;
      const shodan = `https://www.shodan.io/host/${ip}`;
      const abuse = `https://www.abuseipdb.com/check/${ip}`;
      const talos = `https://talosintelligence.com/reputation_center/lookup?search=${ip}`;
      return `• *${ip}*: <${vt}|VirusTotal> | <${shodan}|Shodan> | <${abuse}|AbuseIPDB> | <${talos}|Talos>`;
    }).join("\n");
  }

  const fromDomain = getDomainFromEmail(emailData.from);
  const returnPathDomain = getDomainFromEmail(emailData.returnPath);
  const spoofingCheckStr = `• *From:* \`${fromDomain}\`\n` +
    `• *Return-Path:* \`${emailData.returnPath || "N/A"}\` (Domínio: \`${returnPathDomain}\`)\n` +
    `• *Flags:* \`${flagsStr}\``;

  const emailDate = emailData.date
    ? emailData.date.toISOString().replace("T", " ").split(".")[0] + " UTC"
    : "Data desconhecida";

  const urlsList = ioc.urls && ioc.urls.length > 0
    ? ioc.urls.slice(0, 5).map(function(u) { return `\`${defangUrl(u)}\``; }).join("\n")
    : "Nenhuma identificada";
  const urlsCountText = ioc.urls && ioc.urls.length > 5
    ? `\n...e mais ${ioc.urls.length - 5} URLs.`
    : "";

  const attachmentInfo =
    emailData.attachments && emailData.attachments.length > 0
      ? emailData.attachments.map((a) => a.name).join(", ")
      : "Nenhum";

  // Blocos Slack
  const blocks = [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": `${emoji} ${title}`
      }
    },
    {
      "type": "divider"
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": `*ANÁLISE DE RISCO (SOC)*\n` +
          `• *Score:* ${risk.score}/100\n` +
          `• *Classificação:* \`${risk.classification}\`\n` +
          `• *Motivos:* ${risk.reasons && risk.reasons.length > 0 ? risk.reasons.join(" | ") : "Nenhum fator de risco identificado."}`
      }
    },
    {
      "type": "divider"
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": `*Detalhes do e-mail suspeito*\n` +
          `• *De:* ${emailData.from}\n` +
          `• *Para:* ${emailData.to}\n` +
          `• *Assunto:* ${emailData.subject}\n` +
          `• *Data do e-mail:* ${emailDate}`
      }
    },
    {
      "type": "divider"
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": `*Indicators of Compromise (IoC)*\n` +
          `• *IPs de Origem:* ${receivedIpsStr}\n` +
          `• *Consultar Reputação:*\n${reputationLinksStr}\n` +
          `• *Autenticação:* ${authStr}\n\n` +
          `*Spoofing Check*\n${spoofingCheckStr}\n\n` +
          `*URLs Encontradas:*\n${urlsList}${urlsCountText}\n\n` +
          `*Anexos:* ${attachmentInfo}`
      }
    }
  ];

  // Adiciona seção da Análise do Gemini se for investigação
  if (isInvestigation && emailData.geminiAnalysis) {
    blocks.push({
      "type": "divider"
    });
    blocks.push({
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": `*✨ Análise IA (Gemini):*\n${emailData.geminiAnalysis}`
      }
    });
  }

  // Adiciona contexto/footer
  blocks.push({
    "type": "divider"
  });
  
  const contextElements = [
    {
      "type": "mrkdwn",
      "text": `*Repórter:* ${reporter}`
    }
  ];
  
  if (emailData.messageId) {
    const rfc822Link = buildRfc822SearchLink(emailData.messageId);
    if (rfc822Link) {
      contextElements.push({
        "type": "mrkdwn",
        "text": `*Gmail:* <${rfc822Link}|Buscar por Message-ID>`
      });
    }
  }

  blocks.push({
    "type": "context",
    "elements": contextElements
  });

  const payload = {
    "text": isInvestigation ? `🚨 Investigação solicitada por ${reporter}` : `⚠️ Phishing reportado por ${reporter}`,
    "attachments": [
      {
        "color": riskColor,
        "blocks": blocks
      }
    ]
  };

  const options = {
    "method": "post",
    "contentType": "application/json",
    "payload": JSON.stringify(payload),
    "muteHttpExceptions": true
  };

  const response = UrlFetchApp.fetch(webhookUrl, options);
  const responseCode = response.getResponseCode();
  if (responseCode !== 200) {
    console.error("Erro ao enviar notificação ao Slack. Código: " + responseCode + ". Resposta: " + response.getContentText());
  } else {
    console.log("✓ Notificação do Slack enviada com sucesso.");
  }
}

/**
 * Sanitiza uma URL (defanging) para evitar que seja clicável ou interpretada como link ativo.
 * Ex: http://malicious.com/path -> http://malicious[.]com/path
 *
 * @param {string} url A URL original.
 * @param {boolean} [domainOnly] Se verdadeiro, retorna apenas o protocolo e o domínio.
 * @returns {string} A URL sanitizada.
 */
function defangUrl(url, domainOnly) {
  if (!url) return "";
  
  // Encontra a parte do domínio (entre // e a próxima / ou fim da string)
  const match = url.match(/^(https?:\/\/)([^\/\s?#]+)(.*)$/i);
  if (match) {
    const protocol = match[1];
    const domain = match[2];
    const path = match[3];
    const defangedDomain = domain.replace(/\./g, "[.]");
    return protocol + defangedDomain + (domainOnly ? "" : path);
  }
  
  if (domainOnly) {
    const simpleMatch = url.match(/^([^\/\s?#]+)(.*)$/);
    if (simpleMatch) {
      return simpleMatch[1].replace(/\./g, "[.]");
    }
  }
  
  return url.replace(/\./g, "[.]");
}

/**
 * Converte um status de autenticação de e-mail (SPF/DKIM/DMARC) em um texto com emoji amigável.
 *
 * @param {string} status O status bruto (ex: 'pass', 'fail', 'softfail').
 * @returns {string} O status formatado para exibição visual.
 */
function getAuthStatusIcon(status) {
  if (!status) return "⚪ Desconhecido / Ausente";
  
  const normalized = status.toLowerCase().trim();
  if (normalized === "pass") {
    return "🟢 PASS";
  }
  if (normalized.indexOf("fail") !== -1) {
    return "🔴 FAIL";
  }
  if (normalized === "neutral" || normalized === "none" || normalized === "temperror" || normalized === "permerror") {
    return "🟡 " + normalized.toUpperCase();
  }
  
  return "⚪ " + status.toUpperCase();
}

/**
 * Extrai o nome de exibição (Display Name) a partir do cabeçalho From bruto.
 * Ex: "John Doe" <john@example.com> -> John Doe
 *
 * @param {string} fromHeader O cabeçalho From bruto.
 * @returns {string} O Display Name limpo.
 */
function getDisplayName(fromHeader) {
  if (!fromHeader) return "";
  // Combina com formatos contendo <email> ex: "Nome" <email@dom.com> ou Nome <email@dom.com>
  const match = fromHeader.match(/^\s*["']?([^"']+)["']?\s*<[^>]+>/);
  if (match && match[1]) {
    return match[1].trim();
  }
  return "";
}
