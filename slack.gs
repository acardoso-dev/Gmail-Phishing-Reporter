/**
 * @fileoverview Notificação no Slack via Incoming Webhook.
 *
 * Duas correções importantes em relação à versão anterior:
 *  - o conteúdo controlado pelo atacante (assunto, remetente, nome de
 *    exibição) ia cru para o Slack. Um assunto como
 *    `<https://evil.com|Clique aqui>` virava um LINK ATIVO dentro do canal do
 *    SOC. Agora tudo passa por escapeSlackText;
 *  - blocos do Slack têm limite de 3000 caracteres por campo de texto e 50
 *    blocos por mensagem. A análise da IA e a seção de IoC estouravam esse
 *    limite com facilidade, e o webhook devolvia invalid_blocks — a
 *    notificação era perdida em silêncio.
 */

/** Limite de caracteres por campo de texto de um bloco. */
const SLACK_TEXT_LIMIT = 2900;

/** Limite de blocos por mensagem (o Slack aceita 50; deixamos margem). */
const SLACK_MAX_BLOCKS = 45;

/**
 * Envia o alerta de reporte ao Slack.
 *
 * @param {Object} emailData Dados do e-mail suspeito.
 * @param {string} reportType Um valor de REPORT_TYPES.
 * @returns {boolean} True se a notificação foi entregue.
 */
function sendSlackNotification(emailData, reportType) {
  const webhookUrl = getSlackWebhookUrl();
  if (!webhookUrl) {
    console.log("Webhook do Slack não configurado; notificação ignorada.");
    return false;
  }

  const payload = buildSlackPayload(emailData, reportType);

  const response = fetchWithRetry(
    webhookUrl,
    {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true,
    },
    3
  );

  const code = response.getResponseCode();
  if (code !== 200) {
    console.error(
      `Falha ao notificar o Slack. Código ${code}. Resposta: ` +
        truncateText(response.getContentText(), 500)
    );
    return false;
  }

  console.log("✓ Notificação enviada ao Slack.");
  return true;
}

/**
 * Monta o payload de blocos do Slack.
 *
 * @param {Object} emailData Dados do e-mail suspeito.
 * @param {string} reportType Um valor de REPORT_TYPES.
 * @returns {Object} Payload pronto para o webhook.
 */
function buildSlackPayload(emailData, reportType) {
  const isInvestigation = reportType === REPORT_TYPES.INVESTIGATION;
  const reporter = getReporterEmail();
  const ioc = emailData.iocReport || {};
  const risk = ioc.riskAnalysis || { score: 0, classification: "UNKNOWN", reasons: [] };

  const blocks = [];

  addSlackSection(
    blocks,
    `${isInvestigation ? "🚨" : "⚠️"} *${
      isInvestigation
        ? "Nova Solicitação de Investigação por IA"
        : "Novo Reporte de Phishing"
    }*`
  );
  blocks.push({ type: "divider" });

  // --- Risco ---
  const reasons = (risk.reasons || []).length
    ? risk.reasons.map(escapeSlackText).join(" | ")
    : "Nenhum fator de risco identificado.";

  addSlackSection(
    blocks,
    "*ANÁLISE DE RISCO (SOC)*\n" +
      `• *Score:* ${risk.score}/100\n` +
      `• *Classificação:* \`${escapeSlackCode(risk.classification)}\`\n` +
      `• *Motivos:* ${reasons}`
  );

  if ((risk.mitigations || []).length) {
    addSlackSection(
      blocks,
      "_Mitigações aplicadas: " +
        risk.mitigations.map(escapeSlackText).join("; ") +
        "_"
    );
  }
  blocks.push({ type: "divider" });

  // --- Detalhes ---
  addSlackSection(
    blocks,
    "*Detalhes do e-mail suspeito*\n" +
      `• *De:* ${escapeSlackText(emailData.from)}\n` +
      (ioc.fromDisplayName
        ? `• *Nome exibido:* ${escapeSlackText(ioc.fromDisplayName)}\n`
        : "") +
      `• *Para:* ${escapeSlackText(emailData.to)}\n` +
      `• *Assunto:* ${escapeSlackText(emailData.subject)}\n` +
      `• *Data:* ${escapeSlackText(formatUtc(emailData.date))}`
  );
  blocks.push({ type: "divider" });

  // --- IoC: IPs ---
  const ips = ioc.receivedIPs || [];
  const originating = ioc.originatingIP;

  addSlackSection(
    blocks,
    "*Indicators of Compromise*\n" +
      `• *IP de origem:* ${originating ? "`" + escapeSlackCode(originating) + "`" : "Não identificado"}\n` +
      `• *IPs públicos na cadeia:* ${
        ips.length ? escapeSlackText(ips.slice(0, 8).join(", ")) : "Nenhum"
      }\n` +
      `• *Autenticação:* ${escapeSlackText(formatAuthSummary(ioc.authenticationResults))}`
  );

  if (originating) {
    addSlackSection(blocks, "*Consultar reputação do IP de origem*\n" + buildReputationLine(originating));
  }

  // --- IoC: spoofing ---
  addSlackSection(
    blocks,
    "*Spoofing check*\n" +
      `• *From:* \`${escapeSlackCode(getDomainFromEmail(emailData.from))}\`\n` +
      `• *Return-Path:* \`${escapeSlackCode(emailData.returnPath || "N/A")}\`\n` +
      `• *Reply-To:* \`${escapeSlackCode(emailData.replyTo || "N/A")}\`\n` +
      `• *Flags:* ${formatFlagList(ioc.suspiciousFlags)}`
  );

  // --- IoC: anexos ---
  const attachments = ioc.attachments || [];
  if (attachments.length) {
    const listed = attachments.slice(0, 8).map(function (attachment) {
      const hash = attachment.sha256
        ? `\n   └ SHA-256: \`${escapeSlackCode(attachment.sha256)}\``
        : "";
      return `• \`${escapeSlackCode(attachment.name)}\` (${escapeSlackText(
        attachment.type || "?"
      )}, ${formatBytes(attachment.size)})${hash}`;
    });
    addSlackSection(blocks, `*Anexos (${attachments.length})*\n` + listed.join("\n"));
  }

  // --- Análise da IA ---
  const ai = emailData.aiAnalysis;
  if (ai && ai.available && ai.text) {
    blocks.push({ type: "divider" });
    const header = ai.structured
      ? `*✨ Análise IA — ${escapeSlackText(ai.structured.veredito)} (${
          ai.structured.confianca
        }%)*\n`
      : "*✨ Análise IA (Gemini)*\n";
    // Um único bloco não comporta análises longas; a função quebra em vários.
    addSlackSection(blocks, header + escapeSlackText(ai.text));
  }

  // --- Rodapé ---
  blocks.push({ type: "divider" });
  const contextElements = [
    { type: "mrkdwn", text: `*Repórter:* ${escapeSlackText(reporter || "desconhecido")}` },
    { type: "mrkdwn", text: `*SHA-256 do .eml:* \`${escapeSlackCode(ioc.raw_sha256 || "N/A")}\`` },
  ];

  const searchLink = buildRfc822SearchLink(emailData.messageId);
  if (searchLink) {
    contextElements.push({
      type: "mrkdwn",
      text: `*Gmail:* <${searchLink}|Buscar por Message-ID>`,
    });
  }
  blocks.push({ type: "context", elements: contextElements.slice(0, 10) });

  return {
    text: isInvestigation
      ? `🚨 Investigação solicitada por ${reporter}`
      : `⚠️ Phishing reportado por ${reporter}`,
    attachments: [
      {
        color: getRiskColor(risk.classification),
        blocks: blocks.slice(0, SLACK_MAX_BLOCKS),
      },
    ],
  };
}

/**
 * Acrescenta uma seção, dividindo em vários blocos quando o texto ultrapassa
 * o limite do Slack.
 *
 * @param {Array<Object>} blocks Lista de blocos, alterada no lugar.
 * @param {string} text Texto em mrkdwn (já escapado pelo chamador).
 */
function addSlackSection(blocks, text) {
  const value = String(text || "");
  if (!value.trim()) return;

  for (let offset = 0; offset < value.length; offset += SLACK_TEXT_LIMIT) {
    if (blocks.length >= SLACK_MAX_BLOCKS - 2) {
      blocks.push({
        type: "context",
        elements: [{ type: "mrkdwn", text: "_Conteúdo truncado; veja o e-mail do relatório._" }],
      });
      return;
    }
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: value.substr(offset, SLACK_TEXT_LIMIT) },
    });
  }
}

/**
 * Resume os resultados de autenticação em uma linha.
 *
 * @param {Object} auth Resultados de autenticação.
 * @returns {string} Resumo legível.
 */
function formatAuthSummary(auth) {
  const results = auth || {};
  return (
    `SPF: ${results.spf || "N/A"}, ` +
    `DKIM: ${results.dkim || "N/A"}, ` +
    `DMARC: ${results.dmarc || "N/A"}`
  );
}

/**
 * Formata a lista de flags com rótulos legíveis.
 *
 * @param {string[]} flags Identificadores de flag.
 * @returns {string} Lista formatada.
 */
function formatFlagList(flags) {
  if (!flags || !flags.length) return "Nenhuma flag automática";
  return flags
    .map(function (flag) {
      return "`" + escapeSlackCode(FLAG_LABELS[flag] || flag) + "`";
    })
    .join(", ");
}

/**
 * Monta os links de reputação de um IP.
 *
 * @param {string} ip O endereço IP.
 * @returns {string} Linha em mrkdwn com os links.
 */
function buildReputationLine(ip) {
  const encoded = encodeURIComponent(ip);
  return (
    `• \`${escapeSlackCode(ip)}\`: ` +
    `<https://www.virustotal.com/gui/ip-address/${encoded}|VirusTotal> | ` +
    `<https://www.shodan.io/host/${encoded}|Shodan> | ` +
    `<https://www.abuseipdb.com/check/${encoded}|AbuseIPDB> | ` +
    `<https://talosintelligence.com/reputation_center/lookup?search=${encoded}|Talos>`
  );
}
