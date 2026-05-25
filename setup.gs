/**
 * Validador de Configuração GR-CYBER
 * Verificação simples de instalação
 */

/**
 * Validates the add-on's installation and configuration.
 * This function can be run manually from the Apps Script editor to check
 * if the environment is set up correctly.
 *
 * @returns {boolean} True if the installation is valid, false otherwise.
 */
function installAddOn() {
  console.log("=== Verificação de Instalação ===");

  try {
    // Valida a configuração
    validateConfig();

    // Valida os serviços necessários
    validateServices();

    console.log("\n✓ Instalação completa - Pronto para implantação");
    console.log(`✓ Relatórios de phishing serão enviados para: ${CONFIG.PHISHING_EMAIL}`);
    console.log(`✓ Solicitações de investigação serão enviadas para o próprio usuário que reportar (para receber a análise)`);
    console.log("\nPróximos passos:");
    console.log("1. Implantar como add-on do Gmail");
    console.log("2. Instalar na sua organização");
    console.log("3. Testar com um e-mail de exemplo");

    return true;
  } catch (error) {
    console.error("❌ Verificação de instalação falhou:", error.message);
    return false;
  }
}

/**
 * Validates that the necessary Google Apps Script services are available.
 *
 * @throws {Error} If a required service is not available.
 */
function validateServices() {
  // Testa o CardService
  try {
    CardService.newCardBuilder().build();
    console.log("✓ CardService disponível");
  } catch (e) {
    throw new Error("CardService não está disponível");
  }

  // Testa a API do Gmail
  try {
    // Apenas verifica se o serviço Gmail está disponível
    if (typeof Gmail === "undefined") {
      throw new Error("API do Gmail não está habilitada");
    }
    console.log("✓ API do Gmail habilitada");
  } catch (e) {
    throw new Error("API do Gmail não está habilitada - Verifique os Serviços Avançados do Google");
  }

  // Testa a formatação de data
  const testDate = new Date();
  const formatted = Utilities.formatDate(testDate, "UTC", "yyyy-MM-dd");
  if (!formatted) {
    throw new Error("Utilitários não estão funcionando corretamente");
  }
  console.log("✓ Utilitários funcionando");
}