/**
 * @fileoverview Construção dos cards do add-on (CardService).
 */

/**
 * Monta a seção principal com o resumo da análise e os botões de ação.
 *
 * @param {Object} emailData Dados do e-mail atual (opcional).
 * @returns {CardSection} A seção principal.
 */
function createMainSection(emailData) {
  const section = CardService.newCardSection();
  const ioc = (emailData && emailData.iocReport) || null;

  if (emailData) {
    section.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("De")
        .setText(escapeHtml(emailData.from))
        .setBottomLabel(truncateText(emailData.subject, 120))
        .setWrapText(true)
    );
  }

  if (ioc && ioc.riskAnalysis) {
    section.addWidget(CardService.newDivider());
    section.addWidget(createRiskWidget(ioc.riskAnalysis));

    const reasons = ioc.riskAnalysis.reasons || [];
    if (reasons.length) {
      section.addWidget(
        CardService.newTextParagraph().setText(
          "<b>Motivos:</b>\n" +
            reasons
              .slice(0, 4)
              .map(function (reason) {
                return "• " + escapeHtml(reason);
              })
              .join("\n") +
            (reasons.length > 4 ? `\n• ...e mais ${reasons.length - 4}` : "")
        )
      );
    }
  }

  if (ioc && ioc.authenticationResults) {
    const auth = ioc.authenticationResults;
    section.addWidget(CardService.newDivider());
    section.addWidget(
      CardService.newTextParagraph().setText(
        "<b>Segurança do Remetente:</b>\n" +
          `• SPF (IP autorizado): ${getAuthStatusIcon(auth.spf)}\n` +
          `• DKIM (assinatura): ${getAuthStatusIcon(auth.dkim)}\n` +
          `• DMARC (política): ${getAuthStatusIcon(auth.dmarc)}`
      )
    );
  }

  if (ioc && ioc.attachments && ioc.attachments.length) {
    section.addWidget(CardService.newDivider());
    section.addWidget(
      CardService.newTextParagraph().setText(
        `<b>Anexos (${ioc.attachments.length}):</b>\n` +
          ioc.attachments
            .slice(0, 4)
            .map(function (attachment) {
              return `• <code>${escapeHtml(attachment.name)}</code>`;
            })
            .join("\n")
      )
    );
  }

  if (ioc && ioc.urlDetails && ioc.urlDetails.length) {
    section.addWidget(CardService.newDivider());
    section.addWidget(CardService.newTextParagraph().setText(buildUrlSummary(ioc.urlDetails)));
  }

  section.addWidget(CardService.newDivider());
  section.addWidget(
    CardService.newButtonSet().addButton(
      CardService.newTextButton()
        .setText("Reportar Phishing")
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setBackgroundColor("#d93025")
        .setOnClickAction(CardService.newAction().setFunctionName("reportPhishing"))
    )
  );
  section.addWidget(
    CardService.newTextParagraph().setText(
      "Suspeita comum, ninguém interagiu, só quer sinalizar/treinar o filtro."
    )
  );

  section.addWidget(CardService.newDivider());
  section.addWidget(
    CardService.newButtonSet().addButton(
      CardService.newTextButton()
        .setText("Solicitar Investigação por IA")
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setBackgroundColor("#fbbc04")
        .setOnClickAction(CardService.newAction().setFunctionName("requestInvestigation"))
    )
  );
  section.addWidget(
    CardService.newTextParagraph().setText(
      "Houve interação (clique/login/download), dúvida de comprometimento, ou impacto/urgência."
    )
  );

  return section;
}

/**
 * Widget de score de risco.
 *
 * @param {Object} risk A análise de risco.
 * @returns {DecoratedText} O widget.
 */
function createRiskWidget(risk) {
  const color = getRiskColor(risk.classification);
  return CardService.newDecoratedText()
    .setTopLabel("Análise de risco")
    .setText(
      `<b><font color="${color}">${risk.score}/100 — ${escapeHtml(
        risk.classification
      )}</font></b>`
    )
    .setWrapText(true);
}

/**
 * Resume as URLs encontradas.
 *
 * A versão anterior misturava contagens: rotulava "Links Encontrados (N)" com
 * o total de URLs, mas listava domínios únicos e dizia "...e mais X domínios"
 * calculado sobre a lista de domínios.
 *
 * @param {Array<Object>} urlDetails Detalhes das URLs.
 * @returns {string} Texto formatado para o card.
 */
function buildUrlSummary(urlDetails) {
  const hosts = [];
  const seen = Object.create(null);

  urlDetails.forEach(function (entry) {
    const host = entry.host || getHostname(entry.url);
    if (!host || seen[host]) return;
    seen[host] = true;
    hosts.push(host);
  });

  const shown = hosts.slice(0, 5).map(function (host) {
    return `• <font color="#555555"><code>${escapeHtml(
      defangUrl(host, true)
    )}</code></font>`;
  });

  let text =
    `<b>Links: ${urlDetails.length} URL(s) em ${hosts.length} domínio(s)</b>\n` +
    shown.join("\n");

  if (hosts.length > 5) {
    text += `\n...e mais ${hosts.length - 5} domínio(s).`;
  }
  return text;
}

/**
 * Converte um status de autenticação em texto com indicador visual.
 *
 * @param {string} status O status bruto (pass, fail, softfail...).
 * @returns {string} O status formatado.
 */
function getAuthStatusIcon(status) {
  if (!status) return "⚪ Desconhecido / Ausente";

  const normalized = String(status).toLowerCase().trim();
  if (normalized === "pass") return "🟢 PASS";
  if (normalized.indexOf("fail") !== -1) return "🔴 " + normalized.toUpperCase();
  if (["neutral", "none", "temperror", "permerror"].indexOf(normalized) !== -1) {
    return "🟡 " + normalized.toUpperCase();
  }
  return "⚪ " + normalized.toUpperCase();
}

/**
 * Card exibido após um reporte bem-sucedido.
 *
 * @param {string} reportType Um valor de REPORT_TYPES.
 * @param {string} messageId ID da mensagem reportada.
 * @param {Object} [details] Informações complementares.
 * @returns {ActionResponse} Resposta com o card de sucesso.
 */
function createSuccessCard(reportType, messageId, details) {
  const isInvestigation = reportType === REPORT_TYPES.INVESTIGATION;
  const info = details || {};

  const section = CardService.newCardSection().addWidget(
    CardService.newTextParagraph().setText(
      isInvestigation
        ? "Sua solicitação foi enviada à equipe de segurança, com cópia para você. " +
            "A equipe entrará em contato."
        : "Obrigado por denunciar. A equipe de segurança foi notificada."
    )
  );

  if (info.riskAnalysis) {
    section.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Classificação registrada")
        .setText(
          `<b><font color="${getRiskColor(info.riskAnalysis.classification)}">` +
            `${info.riskAnalysis.score}/100 — ${escapeHtml(
              info.riskAnalysis.classification
            )}</font></b>`
        )
        .setWrapText(true)
    );
  }

  if (info.aiVerdict) {
    section.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Veredito da IA")
        .setText(escapeHtml(info.aiVerdict))
        .setWrapText(true)
    );
  }

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
    .setHeader(
      CardService.newCardHeader().setTitle(
        isInvestigation ? "Investigação solicitada" : "Phishing relatado"
      )
    )
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
 * Card de confirmação após mover para spam.
 *
 * @returns {Card} O card.
 */
function createSpamMovedCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Concluído"))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText("✅ O e-mail foi movido para a caixa de Spam.")
      )
    )
    .build();
}

/**
 * Card de reautorização.
 *
 * @returns {Card} O card.
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
            "O add-on precisa da sua permissão para mover e-mails para o Spam. " +
              "Clique abaixo para autorizar."
          )
        )
        .addWidget(
          CardService.newButtonSet().addButton(
            CardService.newTextButton()
              .setText("Autorizar Agora")
              .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
              .setBackgroundColor("#0b57d0")
              .setOnClickAction(CardService.newAction().setFunctionName("triggerAuth"))
          )
        )
    )
    .build();
}

/**
 * Card exibido quando a configuração do add-on está incompleta.
 *
 * Antes, um PHISHING_EMAIL não configurado só aparecia como um erro críptico
 * do GmailApp no momento do envio.
 *
 * @param {string[]} errors Erros de configuração.
 * @returns {Card} O card.
 */
function createConfigErrorCard(errors) {
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        "O add-on ainda não está configurado. Um administrador precisa concluir a instalação."
      )
    )
    .addWidget(
      CardService.newTextParagraph().setText(
        errors
          .map(function (error) {
            return "• " + escapeHtml(error);
          })
          .join("\n")
      )
    )
    .addWidget(
      CardService.newTextParagraph().setText(
        "<i>Defina a propriedade de script <b>SECURITY_EMAIL</b> em " +
          "Configurações do Projeto &gt; Propriedades do Script.</i>"
      )
    );

  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Configuração Incompleta")
        .setSubtitle("Reporte indisponível")
    )
    .addSection(section)
    .build();
}

/**
 * Card de erro para uma ação, com botão de nova tentativa funcional.
 *
 * O botão anterior chamava buildAddOn, que devolve Card[]; um callback de
 * ação precisa devolver ActionResponse, então "Tentar novamente" quebrava.
 *
 * @param {string} message Mensagem de erro.
 * @returns {ActionResponse} Resposta com o card de erro.
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
        .addWidget(CardService.newTextParagraph().setText(escapeHtml(message)))
        .addWidget(
          CardService.newButtonSet().addButton(
            CardService.newTextButton()
              .setText("Voltar")
              .setOnClickAction(CardService.newAction().setFunctionName("popToRoot"))
          )
        )
    )
    .build();

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card))
    .setNotification(
      CardService.newNotification()
        .setType(CardService.NotificationType.ERROR)
        .setText(truncateText(message, 100))
    )
    .build();
}

/**
 * Card de erro exibido quando o add-on não consegue carregar.
 *
 * @param {string} message Mensagem de erro.
 * @returns {Card} O card.
 */
function createErrorViewCard(message) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader().setTitle("Erro ao carregar").setSubtitle("Tente novamente")
    )
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(escapeHtml(message))
      )
    )
    .build();
}
