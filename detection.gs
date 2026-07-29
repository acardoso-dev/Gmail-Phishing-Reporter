/**
 * @fileoverview Motor de detecção: flags, pesos e cálculo do score de risco.
 *
 * Antes as flags eram strings mágicas espalhadas por três arquivos, com dois
 * esquemas de nomenclatura diferentes (`reply_to_mismatch` na tabela de pesos
 * vs. `reply-to_different_from_from_domain` na produção). Aqui há uma fonte
 * única de verdade.
 */

/** Identificadores canônicos das flags. */
const FLAGS = Object.freeze({
  REPLY_TO_MISMATCH: "reply_to_domain_mismatch",
  RETURN_PATH_MISMATCH: "return_path_domain_mismatch",
  NO_DKIM: "no_dkim_signature",
  DKIM_FAIL: "dkim_fail",
  SPF_FAIL: "spf_fail",
  SPF_SOFTFAIL: "spf_softfail",
  SPF_NONE: "spf_none",
  DMARC_FAIL: "dmarc_fail",
  DMARC_NONE: "dmarc_none",
  DMARC_ERROR: "dmarc_temperror",
  NO_AUTH_RESULTS: "no_authentication_results",
  ARC_FAIL: "arc_fail",
  DISPLAY_NAME_EMAIL: "display_name_contains_other_email",
  DISPLAY_NAME_BRAND: "display_name_impersonates_brand",
  DISPLAY_NAME_CONTACT: "display_name_matches_contact_different_email",
  LOOKALIKE_DOMAIN: "lookalike_domain",
  PUNYCODE_DOMAIN: "punycode_domain",
  HIGH_RISK_ATTACHMENT: "high_risk_attachment",
  MEDIUM_RISK_ATTACHMENT: "medium_risk_attachment",
  DOUBLE_EXTENSION: "double_extension_attachment",
  ANCHOR_HREF_MISMATCH: "anchor_text_href_mismatch",
  URL_SHORTENER: "url_shortener",
  IP_LITERAL_URL: "url_with_ip_literal",
  LINK_DOMAIN_MISMATCH: "link_domain_unrelated_to_sender",
  URGENCY_LANGUAGE: "urgency_language",
  CREDENTIAL_REQUEST: "credential_request_language",
  AI_VERDICT_PHISHING: "ai_verdict_phishing",
  AI_PROMPT_INJECTION: "ai_prompt_injection_attempt",
});

/**
 * Pesos por flag. Recalibrados: DMARC ausente deixou de valer o mesmo que
 * DMARC reprovado, e a falta do header DKIM deixou de punir mensagens em que
 * o Authentication-Results já diz dkim=pass.
 */
const FLAG_WEIGHTS = Object.freeze({
  [FLAGS.REPLY_TO_MISMATCH]: 20,
  [FLAGS.RETURN_PATH_MISMATCH]: 8,
  [FLAGS.NO_DKIM]: 12,
  [FLAGS.DKIM_FAIL]: 20,
  [FLAGS.SPF_FAIL]: 20,
  [FLAGS.SPF_SOFTFAIL]: 10,
  [FLAGS.SPF_NONE]: 8,
  [FLAGS.DMARC_FAIL]: 35,
  [FLAGS.DMARC_NONE]: 10,
  [FLAGS.DMARC_ERROR]: 5,
  [FLAGS.NO_AUTH_RESULTS]: 15,
  [FLAGS.ARC_FAIL]: 10,
  [FLAGS.DISPLAY_NAME_EMAIL]: 40,
  [FLAGS.DISPLAY_NAME_BRAND]: 35,
  [FLAGS.DISPLAY_NAME_CONTACT]: 25,
  [FLAGS.LOOKALIKE_DOMAIN]: 35,
  [FLAGS.PUNYCODE_DOMAIN]: 20,
  [FLAGS.HIGH_RISK_ATTACHMENT]: 30,
  [FLAGS.MEDIUM_RISK_ATTACHMENT]: 12,
  [FLAGS.DOUBLE_EXTENSION]: 25,
  [FLAGS.ANCHOR_HREF_MISMATCH]: 18,
  [FLAGS.URL_SHORTENER]: 10,
  [FLAGS.IP_LITERAL_URL]: 15,
  [FLAGS.LINK_DOMAIN_MISMATCH]: 5,
  [FLAGS.URGENCY_LANGUAGE]: 5,
  [FLAGS.CREDENTIAL_REQUEST]: 10,
  [FLAGS.AI_VERDICT_PHISHING]: 25,
  [FLAGS.AI_PROMPT_INJECTION]: 30,
});

/** Descrição legível de cada flag, usada nos relatórios. */
const FLAG_LABELS = Object.freeze({
  [FLAGS.REPLY_TO_MISMATCH]: "Reply-To em domínio diferente do From",
  [FLAGS.RETURN_PATH_MISMATCH]: "Return-Path em domínio diferente do From",
  [FLAGS.NO_DKIM]: "Sem assinatura DKIM",
  [FLAGS.DKIM_FAIL]: "DKIM reprovado",
  [FLAGS.SPF_FAIL]: "SPF reprovado",
  [FLAGS.SPF_SOFTFAIL]: "SPF softfail",
  [FLAGS.SPF_NONE]: "Domínio sem registro SPF",
  [FLAGS.DMARC_FAIL]: "DMARC reprovado",
  [FLAGS.DMARC_NONE]: "Domínio sem política DMARC",
  [FLAGS.DMARC_ERROR]: "Erro temporário na avaliação DMARC",
  [FLAGS.NO_AUTH_RESULTS]: "Sem cabeçalho Authentication-Results",
  [FLAGS.ARC_FAIL]: "Cadeia ARC reprovada",
  [FLAGS.DISPLAY_NAME_EMAIL]: "Nome de exibição contém outro endereço de e-mail",
  [FLAGS.DISPLAY_NAME_BRAND]: "Nome de exibição imita uma marca conhecida",
  [FLAGS.DISPLAY_NAME_CONTACT]: "Nome bate com um contato, mas o e-mail é outro",
  [FLAGS.LOOKALIKE_DOMAIN]: "Domínio sósia de um domínio protegido",
  [FLAGS.PUNYCODE_DOMAIN]: "Domínio em punycode (possível homógrafo)",
  [FLAGS.HIGH_RISK_ATTACHMENT]: "Anexo executável ou de altíssimo risco",
  [FLAGS.MEDIUM_RISK_ATTACHMENT]: "Anexo de risco (HTML, macro ou compactado)",
  [FLAGS.DOUBLE_EXTENSION]: "Anexo com extensão dupla",
  [FLAGS.ANCHOR_HREF_MISMATCH]: "Texto do link aponta para domínio diferente do href",
  [FLAGS.URL_SHORTENER]: "Uso de encurtador de URL",
  [FLAGS.IP_LITERAL_URL]: "URL apontando diretamente para um IP",
  [FLAGS.LINK_DOMAIN_MISMATCH]: "Nenhum link no domínio do remetente",
  [FLAGS.URGENCY_LANGUAGE]: "Linguagem de urgência ou ameaça",
  [FLAGS.CREDENTIAL_REQUEST]: "Solicitação de credenciais ou dados sensíveis",
  [FLAGS.AI_VERDICT_PHISHING]: "IA classificou como phishing",
  [FLAGS.AI_PROMPT_INJECTION]: "Conteúdo tentou manipular o analisador de IA",
});

/** Marcas frequentemente personificadas (globais e Brasil). */
const IMPERSONATED_BRANDS = Object.freeze([
  { name: "microsoft", domains: ["microsoft.com", "office.com", "live.com", "microsoftonline.com"] },
  { name: "google", domains: ["google.com", "gmail.com", "googlemail.com"] },
  { name: "apple", domains: ["apple.com", "icloud.com"] },
  { name: "amazon", domains: ["amazon.com", "amazon.com.br", "amazonses.com"] },
  { name: "paypal", domains: ["paypal.com", "paypal.com.br"] },
  { name: "netflix", domains: ["netflix.com"] },
  { name: "whatsapp", domains: ["whatsapp.com"] },
  { name: "instagram", domains: ["instagram.com"] },
  { name: "facebook", domains: ["facebook.com", "fb.com"] },
  { name: "linkedin", domains: ["linkedin.com"] },
  { name: "dropbox", domains: ["dropbox.com"] },
  { name: "docusign", domains: ["docusign.com", "docusign.net"] },
  { name: "adobe", domains: ["adobe.com"] },
  { name: "binance", domains: ["binance.com"] },
  { name: "itau", domains: ["itau.com.br", "itau.com"] },
  { name: "bradesco", domains: ["bradesco.com.br"] },
  { name: "santander", domains: ["santander.com.br"] },
  { name: "nubank", domains: ["nubank.com.br"] },
  { name: "caixa", domains: ["caixa.gov.br"] },
  { name: "banco do brasil", domains: ["bb.com.br"] },
  { name: "serasa", domains: ["serasa.com.br", "serasaexperian.com.br"] },
  { name: "receita federal", domains: ["gov.br", "fazenda.gov.br"] },
  { name: "correios", domains: ["correios.com.br"] },
  { name: "mercado livre", domains: ["mercadolivre.com.br", "mercadolibre.com"] },
  { name: "magazine luiza", domains: ["magazineluiza.com.br"] },
  { name: "pix", domains: ["bcb.gov.br"] },
]);

/** Extensões que praticamente nunca são legítimas por e-mail. */
const HIGH_RISK_EXTENSIONS = Object.freeze([
  "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
  "wsh", "hta", "lnk", "iso", "img", "vhd", "vhdx", "msi", "msix", "jar",
  "ps1", "psm1", "reg", "cpl", "dll", "apk", "chm", "scf", "inf", "gadget",
]);

/** Extensões de risco moderado: HTML de captura, macros, compactados. */
const MEDIUM_RISK_EXTENSIONS = Object.freeze([
  "html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml",
  "docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam",
  "zip", "rar", "7z", "ace", "cab", "gz", "tgz", "z", "arj", "lzh",
  "one", "iqy", "slk", "xll",
]);

/** Extensões "inofensivas" usadas em ataques de extensão dupla. */
const DECOY_EXTENSIONS = Object.freeze([
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg",
  "png", "gif", "csv", "rtf", "xml", "json",
]);

/** Termos de urgência/ameaça, pt-BR e inglês. */
const URGENCY_PATTERNS = Object.freeze([
  /\burgent[e]?\b/i, /\bimediat[ao]/i, /\bexpir[ao]/i, /\bvence\s+hoje\b/i,
  /\búltim[oa]\s+(aviso|chance|oportunidade)/i, /\bsuspens[ãa]o\b/i,
  /\bbloquead[oa]\b/i, /\bcancelament[o]\b/i, /\ba[cç][ãa]o\s+necess[áa]ria/i,
  /\bem\s+24\s*h/i, /\bact\s+now\b/i, /\bimmediate(ly)?\b/i,
  /\bfinal\s+notice\b/i, /\baccount\s+(suspended|locked)\b/i,
  /\bverify\s+(your\s+)?account\b/i,
]);

/** Termos que indicam captura de credenciais ou dados sensíveis. */
const CREDENTIAL_PATTERNS = Object.freeze([
  /\bsenha\b/i, /\bpassword\b/i, /\bcredenciais\b/i, /\bcredentials\b/i,
  /\bconfirm(e|ar|ação)\s+(sua|seus?)\s+(conta|dados|identidade)/i,
  /\batualiz(e|ar)\s+(sua|seus?)\s+(senha|dados|cadastro)/i,
  /\bvalidar?\s+(sua\s+)?identidade/i, /\bc[óo]digo\s+de\s+verifica[çc][ãa]o/i,
  /\bcart[ãa]o\s+de\s+cr[ée]dito\b/i, /\bcpf\b/i, /\bdados\s+banc[áa]rios\b/i,
  /\bsign\s+in\s+to\s+(verify|confirm)/i, /\btwo[- ]factor\b/i,
]);

/** Limiares de classificação. */
const RISK_THRESHOLDS = Object.freeze({
  CONFIRMED: 70,
  LIKELY: 40,
  SUSPICIOUS: 20,
});

/**
 * Adiciona uma flag ao relatório, evitando duplicatas.
 *
 * @param {Object} report Relatório de IoC.
 * @param {string} flag Identificador da flag.
 * @param {Object} [detail] Detalhe opcional para o contexto.
 */
function addFlag(report, flag, detail) {
  if (report.suspiciousFlags.indexOf(flag) === -1) {
    report.suspiciousFlags.push(flag);
  }
  if (detail) {
    report.flagDetails = report.flagDetails || {};
    report.flagDetails[flag] = detail;
  }
}

/**
 * Avalia os resultados de autenticação (SPF/DKIM/DMARC/ARC).
 *
 * @param {Object} report Relatório de IoC, alterado no lugar.
 */
function evaluateAuthentication(report) {
  const auth = report.authenticationResults;

  if (!auth) {
    addFlag(report, FLAGS.NO_AUTH_RESULTS);
    if (!report.dkimSignatures.length) addFlag(report, FLAGS.NO_DKIM);
    return;
  }

  // SPF
  if (auth.spf === "fail") addFlag(report, FLAGS.SPF_FAIL);
  else if (auth.spf === "softfail") addFlag(report, FLAGS.SPF_SOFTFAIL);
  else if (auth.spf === "none") addFlag(report, FLAGS.SPF_NONE);

  // DKIM: só marca ausência quando o receptor também não validou.
  // Gateways frequentemente removem o header DKIM-Signature depois de
  // verificá-lo, e a versão anterior punia esses e-mails legítimos.
  if (auth.dkim === "fail") {
    addFlag(report, FLAGS.DKIM_FAIL);
  } else if (auth.dkim !== "pass" && !report.dkimSignatures.length) {
    addFlag(report, FLAGS.NO_DKIM);
  }

  // DMARC: "none" significa domínio sem política publicada, não reprovação.
  if (auth.dmarc === "fail") addFlag(report, FLAGS.DMARC_FAIL);
  else if (auth.dmarc === "none") addFlag(report, FLAGS.DMARC_NONE);
  else if (auth.dmarc === "temperror" || auth.dmarc === "permerror") {
    addFlag(report, FLAGS.DMARC_ERROR);
  }

  // ARC: avaliado apenas nos cabeçalhos ARC. A checagem anterior varria o raw
  // inteiro, então qualquer e-mail com "dara=fail" no CORPO ganhava a flag.
  const arcBlob = (report.arcResults || []).join(" ");
  if (/\barc=fail\b/i.test(arcBlob) || /\bdara=fail\b/i.test(arcBlob)) {
    addFlag(report, FLAGS.ARC_FAIL);
  }
}

/**
 * Avalia alinhamento de domínio entre From, Reply-To e Return-Path.
 *
 * @param {Object} report Relatório de IoC, alterado no lugar.
 */
function evaluateDomainAlignment(report) {
  const fromDomain = getDomainFromEmail(report.from);

  // A versão anterior usava String.includes, então Reply-To em
  // "evil-gmail.com" passava batido quando o From era "@gmail.com".
  if (report.replyTo) {
    const replyDomain = getDomainFromEmail(report.replyTo);
    if (replyDomain !== "N/A" && !domainsAligned(replyDomain, fromDomain)) {
      addFlag(report, FLAGS.REPLY_TO_MISMATCH, {
        from: fromDomain,
        replyTo: replyDomain,
      });
    }
  }

  if (report.returnPath) {
    const returnDomain = getDomainFromEmail(report.returnPath);
    if (returnDomain !== "N/A" && !domainsAligned(returnDomain, fromDomain)) {
      addFlag(report, FLAGS.RETURN_PATH_MISMATCH, {
        from: fromDomain,
        returnPath: returnDomain,
      });
    }
  }
}

/**
 * Avalia o nome de exibição do remetente.
 *
 * Cobre o vetor clássico `"suporte@banco.com" <atacante@evil.ru>`, que a
 * versão anterior não detectava de forma alguma.
 *
 * @param {Object} report Relatório de IoC, alterado no lugar.
 */
function evaluateDisplayName(report) {
  const displayName = report.fromDisplayName;
  if (!displayName) return;

  const senderAddress = extractEmailAddress(report.from);
  const fromDomain = getDomainFromEmail(report.from);

  const embedded = displayName.match(/[^\s<>,;:"]+@[^\s<>,;:"]+\.[a-z]{2,}/i);
  if (embedded) {
    const embeddedAddress = embedded[0].toLowerCase();
    if (embeddedAddress !== senderAddress) {
      addFlag(report, FLAGS.DISPLAY_NAME_EMAIL, {
        displayName: displayName,
        claimed: embeddedAddress,
        actual: senderAddress,
      });
    }
  }

  // Sem remover acentos, "Segurança Itaú" não casa com a marca "itau".
  const normalizedName = stripDiacritics(displayName).toLowerCase();
  for (let i = 0; i < IMPERSONATED_BRANDS.length; i++) {
    const brand = IMPERSONATED_BRANDS[i];
    if (normalizedName.indexOf(brand.name) === -1) continue;

    const claimsBrandDomain = brand.domains.some(function (domain) {
      return domainsAligned(fromDomain, domain);
    });
    if (!claimsBrandDomain) {
      addFlag(report, FLAGS.DISPLAY_NAME_BRAND, {
        brand: brand.name,
        displayName: displayName,
        actualDomain: fromDomain,
      });
    }
    break;
  }
}

/**
 * Detecta domínios sósia de um domínio protegido ou de uma marca conhecida.
 *
 * @param {string} domain O domínio do remetente.
 * @param {string[]} protectedDomains Domínios da organização.
 * @returns {Object|null} Detalhe da detecção, ou null.
 */
function detectLookalikeDomain(domain, protectedDomains) {
  if (!domain || domain === "N/A") return null;

  const registrable = registrableDomain(domain);
  if (!registrable) return null;

  const candidates = (protectedDomains || []).slice();
  IMPERSONATED_BRANDS.forEach(function (brand) {
    brand.domains.forEach(function (brandDomain) {
      candidates.push(brandDomain);
    });
  });

  for (let i = 0; i < candidates.length; i++) {
    const target = registrableDomain(candidates[i]);
    if (!target || target.length < 6) continue;
    if (registrable === target) return null; // é o domínio legítimo

    const distance = levenshteinDistance(registrable, target);
    if (distance > 0 && distance <= 2) {
      return { type: "levenshtein", target: target, observed: registrable, distance: distance };
    }

    // Marca embutida como subdomínio ou prefixo: paypal.evil.com,
    // paypal-secure.com, login-itau.xyz.
    const targetLabel = target.split(".")[0];
    if (targetLabel.length >= 5 && domain.indexOf(targetLabel) !== -1) {
      return { type: "brand_embedded", target: target, observed: domain };
    }
  }
  return null;
}

/**
 * Avalia o domínio do remetente contra sósias e punycode.
 *
 * @param {Object} report Relatório de IoC, alterado no lugar.
 * @param {string[]} protectedDomains Domínios da organização.
 */
function evaluateSenderDomain(report, protectedDomains) {
  const fromDomain = getDomainFromEmail(report.from);
  if (fromDomain === "N/A") return;

  if (fromDomain.indexOf("xn--") !== -1) {
    addFlag(report, FLAGS.PUNYCODE_DOMAIN, { domain: fromDomain });
  }

  const lookalike = detectLookalikeDomain(fromDomain, protectedDomains);
  if (lookalike) addFlag(report, FLAGS.LOOKALIKE_DOMAIN, lookalike);
}

/**
 * Avalia as URLs encontradas no corpo.
 *
 * @param {Object} report Relatório de IoC, alterado no lugar.
 * @param {string[]} protectedDomains Domínios da organização.
 */
function evaluateUrls(report, protectedDomains) {
  const details = report.urlDetails || [];
  if (!details.length) return;

  const fromDomain = getDomainFromEmail(report.from);

  const shorteners = details.filter(function (u) { return u.isShortener; });
  if (shorteners.length) {
    addFlag(report, FLAGS.URL_SHORTENER, {
      hosts: shorteners.map(function (u) { return u.host; }).slice(0, 5),
    });
  }

  const ipLiterals = details.filter(function (u) { return u.isIpLiteral; });
  if (ipLiterals.length) {
    addFlag(report, FLAGS.IP_LITERAL_URL, {
      urls: ipLiterals.map(function (u) { return defangUrl(u.url); }).slice(0, 5),
    });
  }

  const punycode = details.filter(function (u) { return u.isPunycode; });
  if (punycode.length) {
    addFlag(report, FLAGS.PUNYCODE_DOMAIN, {
      hosts: punycode.map(function (u) { return u.host; }).slice(0, 5),
    });
  }

  for (let i = 0; i < details.length; i++) {
    const lookalike = detectLookalikeDomain(details[i].host, protectedDomains);
    if (lookalike) {
      addFlag(report, FLAGS.LOOKALIKE_DOMAIN, lookalike);
      break;
    }
  }

  if ((report.anchorMismatches || []).length) {
    addFlag(report, FLAGS.ANCHOR_HREF_MISMATCH, {
      examples: report.anchorMismatches.slice(0, 3),
    });
  }

  // Nenhum link aponta para o domínio do remetente nem para um ESP conhecido.
  if (fromDomain !== "N/A") {
    const anyAligned = details.some(function (u) {
      return domainsAligned(u.host, fromDomain) || isKnownESP(u.host);
    });
    if (!anyAligned) addFlag(report, FLAGS.LINK_DOMAIN_MISMATCH);
  }
}

/**
 * Avalia os anexos.
 *
 * @param {Object} report Relatório de IoC, alterado no lugar.
 */
function evaluateAttachments(report) {
  const attachments = report.attachments || [];
  if (!attachments.length) return;

  const high = [];
  const medium = [];
  const doubles = [];

  attachments.forEach(function (attachment) {
    const name = String(attachment.name || "");
    const extension = attachment.extension || getFileExtension(name);

    if (HIGH_RISK_EXTENSIONS.indexOf(extension) !== -1) high.push(name);
    else if (MEDIUM_RISK_EXTENSIONS.indexOf(extension) !== -1) medium.push(name);

    const doubleMatch = name.match(/\.([A-Za-z0-9]{2,5})\.([A-Za-z0-9]{2,5})$/);
    if (
      doubleMatch &&
      DECOY_EXTENSIONS.indexOf(doubleMatch[1].toLowerCase()) !== -1 &&
      doubleMatch[2].toLowerCase() !== doubleMatch[1].toLowerCase()
    ) {
      doubles.push(name);
    }
  });

  if (high.length) addFlag(report, FLAGS.HIGH_RISK_ATTACHMENT, { files: high });
  if (medium.length) addFlag(report, FLAGS.MEDIUM_RISK_ATTACHMENT, { files: medium });
  if (doubles.length) addFlag(report, FLAGS.DOUBLE_EXTENSION, { files: doubles });
}

/**
 * Avalia sinais linguísticos no assunto e no corpo.
 *
 * @param {Object} report Relatório de IoC, alterado no lugar.
 * @param {{text: string[], html: string[]}} bodies Corpos decodificados.
 */
function evaluateContentLanguage(report, bodies) {
  const parts = [report.subject || ""]
    .concat(bodies && bodies.text ? bodies.text : [])
    .concat((bodies && bodies.html ? bodies.html : []).map(htmlToText));

  // Analisar o texto inteiro de newsletters longas é desperdício.
  const sample = truncateText(parts.join("\n"), 20000);

  const urgencyHits = URGENCY_PATTERNS.filter(function (pattern) {
    return pattern.test(sample);
  });
  if (urgencyHits.length >= 2) addFlag(report, FLAGS.URGENCY_LANGUAGE);

  const credentialHits = CREDENTIAL_PATTERNS.filter(function (pattern) {
    return pattern.test(sample);
  });
  if (credentialHits.length >= 2) addFlag(report, FLAGS.CREDENTIAL_REQUEST);
}

/**
 * Executa todas as regras de detecção sobre o relatório.
 *
 * @param {Object} report Relatório de IoC vindo de buildIocReport.
 * @param {Object} [options] Opções.
 * @param {string[]} [options.protectedDomains] Domínios da organização.
 * @returns {Object} O mesmo relatório, com flags e riskAnalysis preenchidos.
 */
function runDetection(report, options) {
  const opts = options || {};
  const protectedDomains = opts.protectedDomains || [];
  const bodies = report._bodies || { text: [], html: [] };

  report.suspiciousFlags = report.suspiciousFlags || [];
  report.flagDetails = report.flagDetails || {};

  evaluateAuthentication(report);
  evaluateDomainAlignment(report);
  evaluateDisplayName(report);
  evaluateSenderDomain(report, protectedDomains);
  evaluateUrls(report, protectedDomains);
  evaluateAttachments(report);
  evaluateContentLanguage(report, bodies);

  report.riskAnalysis = calculateRiskScore(report);
  return report;
}

/**
 * Calcula o score de risco a partir das flags, aplicando mitigações de
 * contexto (listas de distribuição, ESPs conhecidos) e teto de 100.
 *
 * @param {Object} report Relatório com suspiciousFlags preenchido.
 * @returns {{score: number, rawScore: number, reasons: string[], classification: string, mitigations: string[]}} Análise.
 */
function calculateRiskScore(report) {
  let score = 0;
  const reasons = [];
  const mitigations = [];

  const isMailingList = !!report.isMailingList;
  const isGoogleGroup = !!report.isGoogleGroup;
  const replyToDomain = getDomainFromEmail(report.replyTo);
  const returnPathDomain = getDomainFromEmail(report.returnPath);

  const flags = report.suspiciousFlags || [];

  flags.forEach(function (flag) {
    let weight = FLAG_WEIGHTS[flag];
    if (weight === undefined) return;

    // Numa lista de distribuição, From e Reply-To divergirem é o esperado.
    if (flag === FLAGS.REPLY_TO_MISMATCH) {
      if (isMailingList) {
        mitigations.push("Reply-To divergente ignorado (lista de distribuição)");
        return;
      }
      if (isKnownESP(replyToDomain)) weight = 10;
    }

    if (flag === FLAGS.RETURN_PATH_MISMATCH) {
      if (isMailingList) {
        mitigations.push("Return-Path divergente ignorado (lista de distribuição)");
        return;
      }
      if (isKnownESP(returnPathDomain)) weight = 3;
    }

    // Listas quebram ARC com frequência; na infra do Google confiamos mais.
    if (flag === FLAGS.ARC_FAIL && isGoogleGroup) {
      mitigations.push("Falha de ARC ignorada (Google Group)");
      return;
    }

    // Newsletters legítimas usam encurtadores o tempo todo.
    if (flag === FLAGS.URL_SHORTENER && isMailingList) {
      mitigations.push("Encurtador ignorado (lista de distribuição)");
      return;
    }

    if (flag === FLAGS.LINK_DOMAIN_MISMATCH && isMailingList) {
      return;
    }

    score += weight;
    reasons.push(`${FLAG_LABELS[flag] || flag} (+${weight})`);
  });

  const rawScore = score;
  // A versão anterior podia somar 155 e exibir "155/100".
  const capped = Math.max(0, Math.min(100, score));

  return {
    score: capped,
    rawScore: rawScore,
    reasons: reasons,
    mitigations: mitigations,
    classification: classifyEmail(capped),
  };
}

/**
 * Traduz o score numérico em uma classificação.
 *
 * @param {number} score O score de 0 a 100.
 * @returns {string} A classificação.
 */
function classifyEmail(score) {
  if (score >= RISK_THRESHOLDS.CONFIRMED) return "PHISHING CONFIRMED";
  if (score >= RISK_THRESHOLDS.LIKELY) return "PHISHING LIKELY";
  if (score >= RISK_THRESHOLDS.SUSPICIOUS) return "SUSPICIOUS";
  return "BENIGN";
}

/**
 * Cor associada a uma classificação, usada na UI, no e-mail e no Slack.
 *
 * @param {string} classification A classificação.
 * @returns {string} Cor hexadecimal.
 */
function getRiskColor(classification) {
  const value = String(classification || "");
  if (value.indexOf("CONFIRMED") !== -1) return "#990000";
  if (value.indexOf("LIKELY") !== -1) return "#d93025";
  if (value === "SUSPICIOUS") return "#f29900";
  if (value === "BENIGN") return "#188038";
  return "#555555";
}

/**
 * Incorpora o veredito da IA ao score, depois que a análise roda.
 *
 * @param {Object} report Relatório de IoC.
 * @param {Object} aiResult Resultado estruturado do Gemini.
 * @returns {Object} O relatório atualizado.
 */
function applyAiVerdictToRisk(report, aiResult) {
  if (!report || !aiResult || !aiResult.structured) return report;

  const structured = aiResult.structured;
  let changed = false;

  if (structured.veredito === "PHISHING" && (structured.confianca || 0) >= 70) {
    addFlag(report, FLAGS.AI_VERDICT_PHISHING, {
      confianca: structured.confianca,
    });
    changed = true;
  }

  if (structured.tentativa_de_manipulacao === true) {
    addFlag(report, FLAGS.AI_PROMPT_INJECTION);
    changed = true;
  }

  if (changed) report.riskAnalysis = calculateRiskScore(report);
  return report;
}

/**
 * Checagem de spoofing de display name contra os contatos do usuário.
 *
 * Reescrita sobre a People API: ContactsApp está descontinuada, fazia busca
 * difusa por nome e era uma chamada de rede no caminho de renderização do
 * card — todo e-mail aberto pagava esse custo. Agora roda só no momento do
 * reporte, com a lista de contatos em cache.
 *
 * Desligada por padrão (CONFIG.ENABLE_CONTACT_SPOOF_CHECK); exige adicionar o
 * escopo contacts.readonly ao appsscript.json.
 *
 * @param {Object} report Relatório de IoC, alterado no lugar.
 * @returns {Object} O relatório.
 */
function checkContactSpoofing(report) {
  if (!CONFIG.ENABLE_CONTACT_SPOOF_CHECK) return report;

  const displayName = report.fromDisplayName;
  if (!displayName || displayName.length <= 2) return report;

  try {
    const contacts = loadContactIndex();
    const key = displayName.trim().toLowerCase();
    const knownAddresses = contacts[key];
    if (!knownAddresses || !knownAddresses.length) return report;

    const senderAddress = extractEmailAddress(report.from);
    const matches = knownAddresses.some(function (address) {
      return address === senderAddress;
    });

    if (!matches) {
      addFlag(report, FLAGS.DISPLAY_NAME_CONTACT, {
        displayName: displayName,
        knownAddresses: knownAddresses.slice(0, 3),
        actual: senderAddress,
      });
      report.riskAnalysis = calculateRiskScore(report);
    }
  } catch (err) {
    console.warn("Checagem de contatos indisponível:", err);
  }

  return report;
}

/**
 * Carrega e indexa os contatos do usuário pela People API, com cache de 6h.
 *
 * @returns {Object<string, string[]>} Nome em minúsculas -> endereços.
 */
function loadContactIndex() {
  const cacheKey = "contactIndex:v1";
  const cached = cacheGetJson(cacheKey);
  if (cached) return cached;

  const index = Object.create(null);
  const url =
    "https://people.googleapis.com/v1/people/me/connections" +
    "?personFields=names,emailAddresses&pageSize=1000";

  const response = UrlFetchApp.fetch(url, {
    method: "get",
    headers: { Authorization: "Bearer " + ScriptApp.getOAuthToken() },
    muteHttpExceptions: true,
  });

  if (response.getResponseCode() !== 200) {
    // Tipicamente 403: o escopo contacts.readonly não foi concedido.
    console.warn(
      "People API indisponível (código " + response.getResponseCode() + ")."
    );
    return index;
  }

  const connections = (JSON.parse(response.getContentText()).connections || []);
  connections.forEach(function (person) {
    const names = person.names || [];
    const emails = (person.emailAddresses || [])
      .map(function (entry) {
        return String(entry.value || "").toLowerCase();
      })
      .filter(Boolean);
    if (!emails.length) return;

    names.forEach(function (name) {
      const key = String(name.displayName || "").trim().toLowerCase();
      if (!key) return;
      index[key] = (index[key] || []).concat(emails);
    });
  });

  cachePutJson(cacheKey, index, 6 * 60 * 60);
  return index;
}
