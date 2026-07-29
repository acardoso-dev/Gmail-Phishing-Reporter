/**
 * @fileoverview Validador de instalação GR-CYBER.
 *
 * Rode installAddOn() manualmente no editor do Apps Script para conferir o
 * ambiente antes de implantar.
 */

/**
 * Verifica configuração e serviços necessários.
 *
 * @returns {boolean} True se a instalação estiver correta.
 */
function installAddOn() {
  console.log("=== Verificação de Instalação ===");

  try {
    const status = checkConfig();

    if (!status.valid) {
      status.errors.forEach(function (error) {
        console.error("❌ " + error);
      });
      throw new Error("Configuração incompleta.");
    }
    console.log("✓ Configuração válida");

    status.warnings.forEach(function (warning) {
      console.warn("⚠ " + warning);
    });

    validateServices();
    console.log("");
    console.log("✓ Instalação completa — pronto para implantação");
    console.log(`✓ Relatórios serão enviados para: ${getSecurityEmail()}`);
    console.log(
      "✓ Solicitações de investigação vão para a equipe, com o reportante em cópia"
    );
    console.log(`✓ Domínios protegidos: ${getProtectedDomains().join(", ") || "(nenhum)"}`);
    console.log("");
    console.log("Próximos passos:");
    console.log("1. Implantar como add-on do Google Workspace");
    console.log("2. Instalar na sua organização");
    console.log("3. Testar com um e-mail de exemplo");

    return true;
  } catch (error) {
    console.error("❌ Verificação de instalação falhou:", error.message);
    return false;
  }
}

/**
 * Verifica se os serviços usados pelo add-on estão disponíveis.
 *
 * @throws {Error} Se algum serviço necessário faltar.
 */
function validateServices() {
  try {
    CardService.newCardBuilder().build();
    console.log("✓ CardService disponível");
  } catch (err) {
    throw new Error("CardService não está disponível");
  }

  if (typeof Gmail === "undefined") {
    throw new Error(
      "API do Gmail não habilitada — adicione o serviço avançado 'Gmail' na aba Serviços"
    );
  }
  console.log("✓ API do Gmail habilitada");

  try {
    CacheService.getUserCache();
    LockService.getUserLock();
    console.log("✓ CacheService e LockService disponíveis");
  } catch (err) {
    throw new Error("CacheService/LockService indisponíveis");
  }

  if (!Utilities.formatDate(new Date(), "UTC", "yyyy-MM-dd")) {
    throw new Error("Utilities não está funcionando corretamente");
  }
  console.log("✓ Utilities funcionando");
}