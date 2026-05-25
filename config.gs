/**
 * @fileoverview Configuration for the Gmail Phishing Reporter add-on.
 *
 * Gr-Cyber - Add-on do Gmail para Reporte de Phishing
 * Update these values before deployment
 */
const CONFIG = {
  // Endereço de e-mail para onde serão enviados os relatórios de phishing
  PHISHING_EMAIL: "MY-MAIL",

  // Email subject prefixes
  PHISHING_PREFIX: "[PHISHING]", // Apenas para conhecimento, não é necessária resposta.
  INVESTIGATION_PREFIX: "[INVESTIGAR]", // O usuário espera uma resposta da equipe de segurança.

  // Branding complementar
  LOGO_URL:
    "https://raw.githubusercontent.com/acardoso-dev/Gmail-Phishing-Reporter/refs/heads/online/logo.png",

  // URL do Webhook do Slack (Incoming Webhook) para envio de alertas
  SLACK_WEBHOOK_URL: "",
};

/**
 * Returns the appropriate security email address based on the report type.
 *
 * @param {string} reportType The type of report, either 'phishing' or 'investigation'.
 * @returns {string} The email address for the specified report type.
 * @throws {Error} If the report type is invalid.
 */
function getSecurityEmail(reportType) {
  switch (reportType) {
    case "phishing":
      return CONFIG.PHISHING_EMAIL;
    case "investigation":
      return Session.getActiveUser().getEmail();
    default:
      throw new Error(`Tipo de reporte inválido: ${reportType}`);
  }
}

/**
 * Validates the configuration on startup.
 *
 * @returns {boolean} True if the configuration is valid.
 * @throws {Error} If any configuration value is invalid.
 */
function validateConfig() {
  if (!CONFIG.PHISHING_EMAIL || !CONFIG.PHISHING_EMAIL.includes("@")) {
    throw new Error("PHISHING_EMAIL inválido em Config.js");
  }

  console.log("✓ Configuração validada");
  return true;
}
