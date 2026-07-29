/**
 * @fileoverview Configuração do Gmail Phishing Reporter.
 *
 * Gr-Cyber - Add-on do Gmail para Reporte de Phishing
 *
 * IMPORTANTE: este arquivo é versionado. Nada de segredo aqui.
 * Webhook do Slack, chave do Gemini e o e-mail da equipe devem ficar em
 * Propriedades do Script (Configurações do Projeto > Propriedades do Script),
 * que sobrescrevem os valores abaixo sem exigir novo deploy.
 */

/** Tipos de reporte aceitos pelo add-on. */
const REPORT_TYPES = Object.freeze({
  PHISHING: "phishing",
  INVESTIGATION: "investigation",
});

/** Chaves lidas de PropertiesService.getScriptProperties(). */
const SCRIPT_PROPERTIES = Object.freeze({
  GEMINI_API_KEY: "GEMINI_API_KEY",
  SLACK_WEBHOOK_URL: "SLACK_WEBHOOK_URL",
  SECURITY_EMAIL: "SECURITY_EMAIL",
  PROTECTED_DOMAINS: "PROTECTED_DOMAINS",
});

const CONFIG = {
  /**
   * Fallback do e-mail da equipe de segurança. Prefira a propriedade de script
   * SECURITY_EMAIL — ela tem precedência e não exige alterar código.
   */
  PHISHING_EMAIL: "",

  // Prefixos de assunto.
  PHISHING_PREFIX: "[PHISHING]", // Apenas para conhecimento, não exige resposta.
  INVESTIGATION_PREFIX: "[INVESTIGAR]", // O usuário espera resposta da equipe.

  /**
   * Solicitações de investigação vão para a equipe de segurança com o
   * reportante em cópia, para que ele receba o retorno da análise.
   * Antes o e-mail ia SÓ para o reportante e a equipe nunca era acionada
   * justamente no caso mais urgente.
   */
  INVESTIGATION_CC_REPORTER: true,

  /** Label aplicada à mensagem reportada. */
  LABEL_REPORTED: "Reported/Phishing",

  // Branding complementar.
  LOGO_URL:
    "https://raw.githubusercontent.com/acardoso-dev/Gmail-Phishing-Reporter/refs/heads/online/logo.png",

  /**
   * Domínios da própria organização, usados na detecção de domínios sósia.
   * Aceita também a propriedade de script PROTECTED_DOMAINS (separada por vírgula).
   * O domínio do usuário logado é sempre incluído automaticamente.
   */
  PROTECTED_DOMAINS: [],

  /** Janela, em segundos, em que a mesma mensagem não é reportada de novo. */
  DUPLICATE_WINDOW_SECONDS: 600,

  /** TTL do cache da análise entre a renderização do card e o envio. */
  ANALYSIS_CACHE_SECONDS: 900,

  // --- Gemini ---
  GEMINI_MODEL: "gemini-2.5-flash-lite",
  /** Caracteres do corpo DECODIFICADO enviados ao modelo. */
  GEMINI_MAX_BODY_CHARS: 20000,
  /** Máximo de imagens enviadas para análise visual (quishing). */
  GEMINI_MAX_IMAGES: 3,
  /**
   * Piso de tamanho para uma imagem ser analisada. QR codes costumam ter
   * 2-5 KB; o valor antigo (10 KB) descartava justamente o alvo da feature.
   */
  GEMINI_MIN_IMAGE_BYTES: 2 * 1024,
  /** Teto para não estourar a cota de payload em e-mails com imagens grandes. */
  GEMINI_MAX_IMAGE_BYTES: 4 * 1024 * 1024,

  /**
   * Checagem de spoofing de display name contra a lista de contatos.
   * Desligada por padrão: exige o escopo contacts.readonly (consentimento
   * pesado) e é uma chamada de rede. As heurísticas de display name em
   * detection.gs cobrem o caso de maior valor sem escopo nenhum.
   * Para ligar: true + adicione o escopo no appsscript.json.
   */
  ENABLE_CONTACT_SPOOF_CHECK: false,
};

/**
 * Lê uma propriedade de script, tolerando ambientes onde o serviço não existe.
 *
 * @param {string} key Nome da propriedade.
 * @returns {string|null} O valor, ou null se ausente.
 */
function getScriptProperty(key) {
  try {
    const value = PropertiesService.getScriptProperties().getProperty(key);
    return value && value.trim() ? value.trim() : null;
  } catch (err) {
    console.warn(`Não foi possível ler a propriedade ${key}:`, err);
    return null;
  }
}

/**
 * Valida o formato de um endereço de e-mail.
 *
 * @param {string} email O endereço a validar.
 * @returns {boolean} True se parecer um endereço válido.
 */
function isValidEmail(email) {
  return !!email && /^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]{2,}$/.test(String(email).trim());
}

/**
 * E-mail da equipe de segurança (propriedade de script tem precedência).
 *
 * @returns {string} O endereço configurado.
 * @throws {Error} Se não estiver configurado ou for inválido.
 */
function getSecurityEmail() {
  const configured =
    getScriptProperty(SCRIPT_PROPERTIES.SECURITY_EMAIL) || CONFIG.PHISHING_EMAIL;

  if (!isValidEmail(configured)) {
    throw new Error(
      "E-mail da equipe de segurança não configurado. Defina a propriedade de " +
        "script SECURITY_EMAIL ou CONFIG.PHISHING_EMAIL em config.gs."
    );
  }
  return configured.trim();
}

/**
 * E-mail do usuário que está reportando.
 *
 * @returns {string} O endereço do usuário ativo, ou string vazia.
 */
function getReporterEmail() {
  try {
    return Session.getActiveUser().getEmail() || "";
  } catch (err) {
    console.warn("Não foi possível obter o e-mail do usuário ativo:", err);
    return "";
  }
}

/**
 * Resolve destinatários do relatório conforme o tipo de reporte.
 *
 * @param {string} reportType Um valor de REPORT_TYPES.
 * @returns {{to: string, cc: string|null}} Destinatários.
 * @throws {Error} Se o tipo for inválido.
 */
function getReportRecipients(reportType) {
  if (
    reportType !== REPORT_TYPES.PHISHING &&
    reportType !== REPORT_TYPES.INVESTIGATION
  ) {
    throw new Error(`Tipo de reporte inválido: ${reportType}`);
  }

  const to = getSecurityEmail();
  const reporter = getReporterEmail();

  const cc =
    reportType === REPORT_TYPES.INVESTIGATION &&
    CONFIG.INVESTIGATION_CC_REPORTER &&
    isValidEmail(reporter) &&
    reporter.toLowerCase() !== to.toLowerCase()
      ? reporter
      : null;

  return { to, cc };
}

/**
 * URL do Incoming Webhook do Slack, se configurada e bem formada.
 *
 * @returns {string|null} A URL, ou null se ausente/inválida.
 */
function getSlackWebhookUrl() {
  const url = getScriptProperty(SCRIPT_PROPERTIES.SLACK_WEBHOOK_URL);
  if (!url) return null;

  if (!/^https:\/\/hooks\.slack\.com\//.test(url)) {
    console.warn("SLACK_WEBHOOK_URL não aponta para hooks.slack.com; ignorada.");
    return null;
  }
  return url;
}

/**
 * Domínios protegidos usados na detecção de sósias: os configurados mais o
 * domínio do próprio usuário.
 *
 * @returns {string[]} Lista de domínios em minúsculas, sem duplicatas.
 */
function getProtectedDomains() {
  const fromProperty = getScriptProperty(SCRIPT_PROPERTIES.PROTECTED_DOMAINS);
  const configured = (fromProperty ? fromProperty.split(",") : []).concat(
    CONFIG.PROTECTED_DOMAINS || []
  );

  const reporter = getReporterEmail();
  if (reporter && reporter.indexOf("@") !== -1) {
    configured.push(reporter.split("@")[1]);
  }

  const seen = Object.create(null);
  const result = [];
  configured.forEach(function (domain) {
    const normalized = String(domain || "").trim().toLowerCase();
    if (normalized && !seen[normalized]) {
      seen[normalized] = true;
      result.push(normalized);
    }
  });
  return result;
}

/**
 * Valida a configuração. Diferente da versão anterior, roda também em runtime
 * (ver buildAddOn) para que o usuário veja um card explicativo em vez de um
 * erro críptico do GmailApp na hora do envio.
 *
 * @returns {{valid: boolean, errors: string[], warnings: string[]}} Diagnóstico.
 */
function checkConfig() {
  const errors = [];
  const warnings = [];

  try {
    getSecurityEmail();
  } catch (err) {
    errors.push(err.message);
  }

  if (!getScriptProperty(SCRIPT_PROPERTIES.GEMINI_API_KEY)) {
    warnings.push(
      "GEMINI_API_KEY não configurada — a análise por IA ficará indisponível."
    );
  }
  if (!getSlackWebhookUrl()) {
    warnings.push(
      "SLACK_WEBHOOK_URL não configurada — notificações no Slack desativadas."
    );
  }

  return { valid: errors.length === 0, errors, warnings };
}

/**
 * Versão que lança exceção, para uso nos scripts de instalação.
 *
 * @returns {boolean} True se a configuração for válida.
 * @throws {Error} Se houver qualquer erro de configuração.
 */
function validateConfig() {
  const result = checkConfig();
  if (!result.valid) {
    throw new Error(result.errors.join(" | "));
  }
  result.warnings.forEach(function (warning) {
    console.warn("⚠ " + warning);
  });
  console.log("✓ Configuração validada");
  return true;
}
