/**
 * @fileoverview Gemini API Integration for Phishing Analysis
 *
 * Handles communication with Google's Gemini 2.5 Flash API to analyze
 * suspicious emails and provide a narrative + verdict.
 */

/**
 * Analyzes the potential phishing email using Gemini 2.5 Flash.
 *
 * @param {Object} emailData The full email data object.
 * @returns {string} The analysis result from Gemini.
 */
function analyzePhishingWithGemini(emailData) {
  try {
    const apiKey =
      PropertiesService.getScriptProperties().getProperty("GEMINI_API_KEY");
    if (!apiKey) {
      console.warn(
        "GEMINI_API_KEY not found in Script Properties. Skipping analysis."
      );
      return "Análise de IA indisponível: Chave de API não configurada.";
    }

    // Switching to canonical version -001 to ensure stability
    const model = "gemini-2.5-flash-lite";
    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

    // Check for Mailing List / Google Group to filter false positives
    const ioc = emailData.iocReport || {};
    const isMailingList =
      ioc.xGoogleGroupId ||
      ioc.listId ||
      (ioc.returnPath && ioc.returnPath.includes("googlegroups.com"));

    let flagsToSend = ioc.suspiciousFlags || [];

    if (isMailingList) {
      // Remove flags that are expected/common for mailing lists
      flagsToSend = flagsToSend.filter(
        (f) =>
          f !== "reply-to_different_from_from_domain" &&
          f !== "returnpath_different_from_from" &&
          f !== "arc_dara_fail"
      );
    }

    // Prepare context for the model
    const iocSummary = emailData.iocReport
      ? JSON.stringify(
          {
            riskScore: emailData.iocReport.riskAnalysis
              ? emailData.iocReport.riskAnalysis.score
              : "N/A",
            classification: emailData.iocReport.riskAnalysis
              ? emailData.iocReport.riskAnalysis.classification
              : "N/A",
            suspiciousFlags: flagsToSend, // Send filtered flags
            authResults: emailData.iocReport.authenticationResults || {},
            receivedIPs: emailData.iocReport.receivedIPs || [],
            isMailingList: isMailingList, // Explicit signal to AI
          },
          null,
          2
        )
      : "N/A";

    const prompt = `
      Você é um especialista em Cibersegurança e análise de Phishing.
      Analise o seguinte e-mail e forneça um relatório curto e direto para um analista de SOC.
      
      DADOS DO E-MAIL:
      - Remetente: ${emailData.from}
      - Assunto: ${emailData.subject}
      - Data: ${emailData.date}
      - IoCs Técnicos (JSON): ${iocSummary}

      CONTEÚDO DO E-MAIL (CORPO):
      """
      ${(emailData.raw || "").substring(0, 10000)} 
      """
      (O conteúdo pode estar truncado se for muito longo)

      TAREFA:
      1. Resuma brevemente o que o e-mail está pedindo ou oferecendo (Narrativa).
      2. Analise se parece phishing ou legítimo, citando evidências do conteúdo ou dos IoCs fornecidos.
      3. Dê um veredito final: PHISHING, SUSPEITO ou LEGÍTIMO (com grau de confiança).

      FORMATO DE RESPOSTA (em Português do Brasil):
      • **Resumo da Mensagem**: [Sua narrativa breve]
      • **Análise de Segurança**: [Seus pontos chave]
      • **Veredito**: [Sua conclusão]
    `;

    const payload = {
      contents: [
        {
          parts: [{ text: prompt }],
        },
      ],
    };

    const options = {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true,
    };

    const response = UrlFetchApp.fetch(apiUrl, options);
    const responseCode = response.getResponseCode();
    const responseBody = response.getContentText();

    if (responseCode !== 200) {
      console.error(
        `Gemini API Error. Code: ${responseCode}. Model: ${model}. Response: ${responseBody}`
      );
      return `Erro na análise de IA (Código ${responseCode}). Detalhes no log: ${responseBody}`;
    }

    const json = JSON.parse(responseBody);

    if (
      json.candidates &&
      json.candidates.length > 0 &&
      json.candidates[0].content &&
      json.candidates[0].content.parts
    ) {
      return json.candidates[0].content.parts[0].text;
    } else {
      console.warn("Unexpected Gemini response structure:", responseBody);
      return "Não foi possível gerar a análise (resposta inesperada da API).";
    }
  } catch (err) {
    console.error("Critical error in analyzePhishingWithGemini:", err);
    return `Erro interno ao contatar a IA: ${err.toString()}`;
  }
}
