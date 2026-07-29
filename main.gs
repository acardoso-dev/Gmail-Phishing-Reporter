/**
 * @fileoverview Ponto de entrada e orquestração do add-on.
 *
 * gr-cyber.dev - Add-on do Gmail para Reporte de Phishing
 *
 * A lógica foi distribuída em módulos: mime.gs (parsing), ioc.gs (indicadores),
 * detection.gs (score), gemini.gs (IA), slack.gs, report.gs e ui.gs. Aqui fica
 * apenas o fluxo.
 */

/** Prefixo das chaves de cache da análise. */
const ANALYSIS_CACHE_PREFIX = "analysis:v2:";

/** Prefixo das chaves de controle de duplicidade. */
const REPORTED_CACHE_PREFIX = "reported:v2:";

/**
 * Ponto de entrada do add-on, disparado ao abrir uma mensagem.
 *
 * @param {Object} e Evento do Gmail.
 * @returns {Card[]} Cards a exibir.
 */
function buildAddOn(e) {
  try {
    // Permite ler a mensagem atual com o escopo estreito
    // gmail.addons.current.message.readonly.
    applyCurrentMessageAccessToken(e);

    const configStatus = checkConfig();
    if (!configStatus.valid) {
      return [createConfigErrorCard(configStatus.errors)];
    }

    const messageId = extractMessageId(e);
    let emailData = null;

    if (messageId) {
      try {
        emailData = getEmailData(messageId, { useCache: true });
      } catch (err) {
        console.warn("Não foi possível carregar os dados do e-mail:", err);
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
    return [createErrorViewCard("Falha ao carregar o add-on. Tente novamente.")];
  }
}

/**
 * Extrai o ID da mensagem do evento, cobrindo os dois formatos possíveis.
 *
 * @param {Object} e Evento do Gmail.
 * @returns {string|null} O ID da mensagem.
 */
function extractMessageId(e) {
  if (!e) return null;
  if (e.gmail && e.gmail.messageId) return e.gmail.messageId;
  if (e.messageMetadata && e.messageMetadata.messageId) return e.messageMetadata.messageId;
  return null;
}

/**
 * Aplica o token de acesso da mensagem atual, quando presente no evento.
 *
 * @param {Object} e Evento do Gmail.
 */
function applyCurrentMessageAccessToken(e) {
  try {
    if (e && e.gmail && e.gmail.accessToken) {
      GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    }
  } catch (err) {
    console.warn("Não foi possível aplicar o token da mensagem atual:", err);
  }
}

/**
 * Lê o fuso horário do usuário a partir do evento.
 *
 * A função anterior tentava deduzir o fuso por getTimezoneOffset() — que no
 * Apps Script devolve o fuso do SCRIPT, não o do usuário — e por um mapa
 * chumbado de domínios, de modo que só conseguia devolver America/Sao_Paulo.
 *
 * @param {Object} e Evento do Gmail.
 * @returns {string} Identificador IANA do fuso.
 */
function getUserTimeZone(e) {
  try {
    if (e && e.commonEventObject && e.commonEventObject.timeZone) {
      const id = e.commonEventObject.timeZone.id;
      if (id) return id;
    }
    if (e && e.userTimezone && e.userTimezone.id) return e.userTimezone.id;
  } catch (err) {
    console.warn("Fuso do usuário indisponível no evento:", err);
  }
  return getScriptTimeZone();
}

/**
 * Fuso configurado no manifesto do script.
 *
 * @returns {string} Identificador IANA do fuso.
 */
function getScriptTimeZone() {
  try {
    return Session.getScriptTimeZone() || "America/Sao_Paulo";
  } catch (err) {
    return "America/Sao_Paulo";
  }
}

/**
 * Ação do botão "Reportar Phishing".
 *
 * @param {Object} e Evento do clique.
 * @returns {ActionResponse} Resposta com o card resultante.
 */
function reportPhishing(e) {
  return forwardEmail(e, CONFIG.PHISHING_PREFIX, REPORT_TYPES.PHISHING);
}

/**
 * Ação do botão "Solicitar Investigação por IA".
 *
 * @param {Object} e Evento do clique.
 * @returns {ActionResponse} Resposta com o card resultante.
 */
function requestInvestigation(e) {
  return forwardEmail(e, CONFIG.INVESTIGATION_PREFIX, REPORT_TYPES.INVESTIGATION);
}

/**
 * Encaminha o e-mail à equipe de segurança como anexo .eml, com o relatório
 * de IoCs e (quando pedido) a análise de IA.
 *
 * @param {Object} e Evento do clique.
 * @param {string} subjectPrefix Prefixo do assunto do relatório.
 * @param {string} reportType Um valor de REPORT_TYPES.
 * @returns {ActionResponse} Card de sucesso ou de erro.
 */
function forwardEmail(e, subjectPrefix, reportType) {
  let lock = null;

  try {
    applyCurrentMessageAccessToken(e);

    const messageId = extractMessageId(e);
    if (!messageId) {
      return createErrorCard("Abra um e-mail e tente novamente pelo add-on.");
    }

    const configStatus = checkConfig();
    if (!configStatus.valid) {
      return createErrorCard(configStatus.errors.join(" "));
    }

    // Sem o lock, dois cliques seguidos geravam dois e-mails ao SOC e dois
    // alertas no Slack.
    lock = LockService.getUserLock();
    if (!lock.tryLock(15000)) {
      return createErrorCard("Já existe um reporte em andamento. Aguarde alguns segundos.");
    }

    if (wasRecentlyReported(messageId)) {
      return createErrorCard(
        "Este e-mail já foi reportado há poucos minutos. Nenhum novo relatório foi enviado."
      );
    }

    const emailData = getEmailData(messageId, { useCache: true });

    // A checagem de contatos é uma chamada de rede: fica fora da renderização
    // do card e roda só aqui, no momento do reporte.
    checkContactSpoofing(emailData.iocReport);

    if (reportType === REPORT_TYPES.INVESTIGATION) {
      emailData.aiAnalysis = runAiAnalysis(emailData);
      applyAiVerdictToRisk(emailData.iocReport, emailData.aiAnalysis);
    }

    const recipients = getReportRecipients(reportType);
    const { plainBody, htmlBody } = createReportBody(emailData, reportType, {
      timeZone: getUserTimeZone(e),
    });

    const emlBlob = Utilities.newBlob(
      // Bytes originais: reencodar a string como UTF-8 corrompia mensagens em
      // outros charsets e fazia o hash do .eml não bater.
      emailData.rawBytes || emailData.raw,
      "message/rfc822",
      generateEmlFilename(emailData.subject, emailData.date)
    );

    const iocBlob = Utilities.newBlob(
      JSON.stringify(emailData.iocReport, null, 2),
      "application/json",
      "ioc_report.json"
    );

    const sendOptions = {
      attachments: [emlBlob, iocBlob],
      htmlBody: htmlBody,
      name: "Gmail Phishing Reporter",
    };
    if (recipients.cc) sendOptions.cc = recipients.cc;

    GmailApp.sendEmail(
      recipients.to,
      `${subjectPrefix} ${emailData.subject}`.trim(),
      plainBody,
      sendOptions
    );

    markReported(messageId);
    applyReportedLabel(messageId);

    try {
      sendSlackNotification(emailData, reportType);
    } catch (slackErr) {
      // O Slack é canal secundário: nunca deve derrubar o reporte.
      console.warn("Erro ao notificar o Slack:", slackErr);
    }

    return createSuccessCard(reportType, messageId, {
      riskAnalysis: emailData.iocReport.riskAnalysis,
      aiVerdict:
        emailData.aiAnalysis && emailData.aiAnalysis.structured
          ? `${emailData.aiAnalysis.structured.veredito} ` +
            `(${emailData.aiAnalysis.structured.confianca}% de confiança)`
          : null,
    });
  } catch (error) {
    console.error(`Erro ao processar o reporte (${reportType}):`, error);
    return createErrorCard(getErrorMessage(error));
  } finally {
    if (lock) {
      try {
        lock.releaseLock();
      } catch (releaseErr) {
        console.warn("Falha ao liberar o lock:", releaseErr);
      }
    }
  }
}

/**
 * Executa a análise de IA sem deixar que uma falha bloqueie o reporte.
 *
 * @param {Object} emailData Dados do e-mail.
 * @returns {Object} Resultado da análise.
 */
function runAiAnalysis(emailData) {
  try {
    return analyzePhishingWithGemini(emailData);
  } catch (err) {
    console.warn("Análise de IA falhou; o reporte segue sem ela:", err);
    return buildAiUnavailable("Análise ignorada por erro interno.");
  }
}

/**
 * Aplica a label de reportado à mensagem.
 *
 * @param {string} messageId ID da mensagem.
 */
function applyReportedLabel(messageId) {
  try {
    const labelName = CONFIG.LABEL_REPORTED;
    const label = GmailApp.getUserLabelByName(labelName) || GmailApp.createLabel(labelName);
    GmailApp.getMessageById(messageId).addLabel(label);
  } catch (err) {
    console.warn("Não foi possível aplicar a label:", err);
  }
}

/**
 * Indica se a mensagem foi reportada há pouco tempo.
 *
 * @param {string} messageId ID da mensagem.
 * @returns {boolean} True se já houve reporte recente.
 */
function wasRecentlyReported(messageId) {
  try {
    return CacheService.getUserCache().get(REPORTED_CACHE_PREFIX + messageId) !== null;
  } catch (err) {
    return false;
  }
}

/**
 * Registra que a mensagem acabou de ser reportada.
 *
 * @param {string} messageId ID da mensagem.
 */
function markReported(messageId) {
  try {
    CacheService.getUserCache().put(
      REPORTED_CACHE_PREFIX + messageId,
      "1",
      CONFIG.DUPLICATE_WINDOW_SECONDS
    );
  } catch (err) {
    console.warn("Falha ao registrar o reporte no cache:", err);
  }
}

/**
 * Carrega e analisa uma mensagem.
 *
 * O pipeline (fetch + parse MIME + SHA-256 + detecção) rodava duas vezes por
 * reporte: uma na renderização do card e outra no envio. Agora a parte
 * derivada é cacheada; só os bytes do .eml são buscados de novo, porque são
 * necessários para o anexo.
 *
 * @param {string} messageId ID da mensagem no Gmail.
 * @param {Object} [options] Opções.
 * @param {boolean} [options.useCache] Se deve usar o cache da análise.
 * @returns {Object} Dados do e-mail com o relatório de IoC.
 */
function getEmailData(messageId, options) {
  const opts = options || {};
  const cacheKey = ANALYSIS_CACHE_PREFIX + messageId;

  const rawResult = fetchRawMessage(messageId);

  if (opts.useCache) {
    const cached = cacheGetJson(cacheKey);
    if (cached && cached.iocReport && cached.iocReport.raw_sha256) {
      // Só reaproveita se for de fato a mesma mensagem.
      const currentHash = sha256HexFromBytes(rawResult.bytes);
      if (currentHash === cached.iocReport.raw_sha256) {
        return hydrateEmailData(cached, rawResult, null, messageId);
      }
    }
  }

  const iocReport = buildIocReport(rawResult.text, {
    rawBytes: rawResult.bytes,
    messageId: messageId,
  });
  runDetection(iocReport, { protectedDomains: getProtectedDomains() });

  const emailData = {
    gmailMessageId: messageId,
    subject: iocReport.subject,
    from: iocReport.from,
    to: iocReport.to,
    replyTo: iocReport.replyTo,
    returnPath: iocReport.returnPath,
    xOriginalFrom: iocReport.xOriginalFrom,
    messageId: iocReport.messageId,
    userAgent: iocReport.userAgent,
    date: iocReport.date ? new Date(iocReport.date) : coerceDate(null),
    attachments: iocReport.attachments,
    iocReport: iocReport,
    aiAnalysis: null,
  };

  if (opts.useCache) {
    cachePutJson(
      cacheKey,
      { iocReport: iocReport },
      CONFIG.ANALYSIS_CACHE_SECONDS
    );
  }

  return hydrateEmailData({ iocReport: iocReport }, rawResult, emailData, messageId);
}

/**
 * Reconstrói o objeto de dados a partir do relatório (cacheado ou recém-gerado).
 *
 * @param {Object} cached Objeto com o iocReport.
 * @param {Object} rawResult Bytes e texto do .eml.
 * @param {Object} [prebuilt] Objeto já montado, se houver.
 * @param {string} [messageId] ID da mensagem no Gmail.
 * @returns {Object} Dados do e-mail completos.
 */
function hydrateEmailData(cached, rawResult, prebuilt, messageId) {
  const iocReport = cached.iocReport;

  // O cache serializa em JSON, então a propriedade não enumerável _bodies se
  // perde. Reconstruímos porque a IA e a detecção de conteúdo dependem dela.
  if (!iocReport._bodies) {
    Object.defineProperty(iocReport, "_bodies", {
      value: walkMimeParts(rawResult.text),
      enumerable: false,
      configurable: true,
    });
  }

  const emailData =
    prebuilt || {
      gmailMessageId: messageId || null,
      subject: iocReport.subject,
      from: iocReport.from,
      to: iocReport.to,
      replyTo: iocReport.replyTo,
      returnPath: iocReport.returnPath,
      xOriginalFrom: iocReport.xOriginalFrom,
      messageId: iocReport.messageId,
      userAgent: iocReport.userAgent,
      date: iocReport.date ? new Date(iocReport.date) : coerceDate(null),
      attachments: iocReport.attachments,
      iocReport: iocReport,
      aiAnalysis: null,
    };

  emailData.raw = rawResult.text;
  emailData.rawBytes = rawResult.bytes;
  return emailData;
}

/**
 * Busca o conteúdo bruto da mensagem.
 *
 * Devolve bytes E uma string byte-transparente (lida como ISO-8859-1). Assim
 * o parser decodifica cada parte MIME no charset correto, em vez de assumir
 * UTF-8 para a mensagem inteira, e o hash bate com o do arquivo anexado.
 *
 * @param {string} messageId ID da mensagem no Gmail.
 * @returns {{bytes: number[], text: string}} Conteúdo bruto.
 */
function fetchRawMessage(messageId) {
  try {
    const message = Gmail.Users.Messages.get("me", messageId, { format: "raw" });
    const bytes = Utilities.base64DecodeWebSafe(message.raw);
    return {
      bytes: bytes,
      text: Utilities.newBlob(bytes).getDataAsString("ISO-8859-1"),
    };
  } catch (err) {
    console.warn("API Gmail indisponível; usando GmailApp:", err);

    const message = GmailApp.getMessageById(messageId);
    const raw =
      typeof message.getRawContent === "function"
        ? message.getRawContent()
        : message.getBody() || "";

    return { bytes: latin1Bytes(raw), text: raw };
  }
}

/**
 * Move a mensagem reportada para o spam.
 *
 * @param {Object} e Evento do clique.
 * @returns {ActionResponse} Resposta com o resultado.
 */
function moveToSpam(e) {
  try {
    const messageId = e && e.parameters && e.parameters.messageId;
    if (!messageId) throw new Error("ID da mensagem não fornecido.");

    const thread = GmailApp.getMessageById(messageId).getThread();
    GmailApp.moveThreadToSpam(thread);

    return CardService.newActionResponseBuilder()
      .setNotification(
        CardService.newNotification()
          .setType(CardService.NotificationType.INFO)
          .setText("E-mail movido para o Spam.")
      )
      .setNavigation(CardService.newNavigation().updateCard(createSpamMovedCard()))
      .build();
  } catch (error) {
    console.error("Erro ao mover para spam:", error);

    // A versão anterior mostrava o card de autorização para QUALQUER erro,
    // o que confundia o usuário em falhas que nada tinham a ver com escopo.
    const message = String(error);
    const looksLikeAuthIssue =
      /permission|access|authoriz|scope|autoriza/i.test(message);

    if (looksLikeAuthIssue) {
      return CardService.newActionResponseBuilder()
        .setNavigation(CardService.newNavigation().pushCard(createAuthCard()))
        .setNotification(
          CardService.newNotification()
            .setType(CardService.NotificationType.ERROR)
            .setText("Permissão insuficiente. Tente reautorizar.")
        )
        .build();
    }

    return CardService.newActionResponseBuilder()
      .setNotification(
        CardService.newNotification()
          .setType(CardService.NotificationType.ERROR)
          .setText(truncateText("Não foi possível mover: " + message, 100))
      )
      .build();
  }
}

/**
 * Dispara o fluxo de autorização exercitando um escopo protegido.
 *
 * @returns {ActionResponse} Resposta com o resultado.
 */
function triggerAuth() {
  try {
    const label = GmailApp.createLabel("AuthCheck_Temp_" + Date.now());
    GmailApp.deleteLabel(label);
  } catch (err) {
    if (/permission|access|authoriz|scope/i.test(String(err))) throw err;
    console.warn("Erro em triggerAuth (não relacionado a permissão):", err);
  }

  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification()
        .setType(CardService.NotificationType.INFO)
        .setText("Autorização verificada. Tente mover para o spam novamente.")
    )
    .setNavigation(CardService.newNavigation().popCard())
    .build();
}

/**
 * Volta ao card raiz. Usado pelo botão de erro.
 *
 * @returns {ActionResponse} Resposta de navegação.
 */
function popToRoot() {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().popToRoot())
    .build();
}

/**
 * Traduz exceções em mensagens compreensíveis para o usuário.
 *
 * @param {Error} error A exceção.
 * @returns {string} Mensagem amigável.
 */
function getErrorMessage(error) {
  const text = String(error || "").toLowerCase();

  if (text.indexOf("quota") !== -1 || text.indexOf("limit") !== -1) {
    return "Limite diário de envio atingido. Tente novamente amanhã.";
  }
  if (text.indexOf("permission") !== -1 || text.indexOf("authoriz") !== -1) {
    return "Permissão negada. Entre em contato com o administrador do add-on.";
  }
  if (text.indexOf("security_email") !== -1 || text.indexOf("não configurado") !== -1) {
    return String(error);
  }
  if (text.indexOf("invalid") !== -1) {
    return "Configuração inválida. Entre em contato com o suporte.";
  }
  return "Não foi possível enviar o relatório. Detalhes: " + truncateText(String(error), 200);
}
