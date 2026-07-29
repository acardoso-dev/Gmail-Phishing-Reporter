/**
 * @fileoverview Extração de Indicadores de Comprometimento a partir do .eml.
 *
 * Cobre IPs (v4 e v6, com filtro de faixas privadas e identificação do salto
 * de origem), URLs (com desembrulho de SafeLinks/Proofpoint/etc.) e anexos
 * com hash SHA-256.
 */

/** Encurtadores e redirecionadores comuns. */
const URL_SHORTENERS = Object.freeze([
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
  "cutt.ly", "rebrand.ly", "shorturl.at", "bit.do", "rb.gy", "tiny.cc",
  "lnkd.in", "t.ly", "s.id", "encurtador.com.br", "urlz.fr", "soo.gd",
  "clck.ru", "shorte.st", "adf.ly", "qrco.de",
]);

/** Domínios de infraestrutura que não são IoC útil (namespaces, esquemas). */
const NON_IOC_URL_PATTERNS = Object.freeze([
  "w3.org",
  "schemas.microsoft.com",
  "schemas.xmlsoap.org",
  "schemas.openxmlformats.org",
  "openxmlformats.org",
  "schemas.google.com",
  "activex.microsoft.com",
  "xml.org",
  "purl.org",
  "iptc.org",
  "adobe.com/xap",
  "ns.adobe.com",
]);

/** ESPs e infraestrutura de entrega conhecidos. */
const KNOWN_ESPS = Object.freeze([
  "mailchimp.com", "mcsv.net", "sendgrid.net", "amazonses.com", "hubspot.com",
  "hubspotemail.net", "salesforce.com", "pardot.com", "constantcontact.com",
  "sparkpostmail.com", "mailgun.org", "postmarkapp.com", "mandrillapp.com",
  "sendinblue.com", "brevo.com", "zendesk.com", "freshdesk.com", "intercom.io",
  "1e100.net", "google.com", "googlemail.com", "outlook.com", "protection.outlook.com",
  "rsgsv.net", "sendpulse.com", "klaviyomail.com",
]);

/**
 * Verifica se um domínio pertence a um ESP/infra conhecida.
 *
 * @param {string} domain O domínio.
 * @returns {boolean} True se for um ESP conhecido.
 */
function isKnownESP(domain) {
  if (!domain || domain === "N/A") return false;
  const normalized = String(domain).toLowerCase();
  return KNOWN_ESPS.some(function (esp) {
    return normalized === esp || normalized.slice(-(esp.length + 1)) === "." + esp;
  });
}

/**
 * Verifica se um host é um encurtador conhecido.
 *
 * @param {string} host O hostname.
 * @returns {boolean} True se for encurtador.
 */
function isUrlShortener(host) {
  if (!host) return false;
  const registrable = registrableDomain(host);
  return URL_SHORTENERS.indexOf(host) !== -1 || URL_SHORTENERS.indexOf(registrable) !== -1;
}

/**
 * Valida um IPv4 em notação decimal pontuada.
 *
 * @param {string} ip O candidato.
 * @returns {boolean} True se for um IPv4 válido.
 */
function isValidIPv4(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4) return false;

  for (let i = 0; i < 4; i++) {
    const part = parts[i];
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.charAt(0) === "0") return false; // octeto com zero à esquerda
    const value = parseInt(part, 10);
    if (value < 0 || value > 255) return false;
  }
  return true;
}

/**
 * Indica se um IPv4 é privado, reservado ou não roteável.
 *
 * Sem esse filtro o relatório gerava links de VirusTotal/Shodan para
 * 10.x.x.x e 127.0.0.1, poluindo a análise.
 *
 * @param {string} ip O endereço.
 * @returns {boolean} True se não for um IP público.
 */
function isPrivateIPv4(ip) {
  const parts = String(ip).split(".").map(Number);
  const [a, b] = parts;

  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0) return true; // 192.0.0.0/24 e 192.0.2.0/24
  if (a === 169 && b === 254) return true; // link-local
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmark
  if (a === 198 && b === 51) return true; // TEST-NET-2
  if (a === 203 && b === 0) return true; // TEST-NET-3
  if (a >= 224) return true; // multicast e reservado
  return false;
}

/**
 * Indica se um IPv6 é privado, reservado ou não roteável.
 *
 * @param {string} ip O endereço.
 * @returns {boolean} True se não for um IP público.
 */
function isPrivateIPv6(ip) {
  const normalized = String(ip).toLowerCase();
  if (normalized === "::1" || normalized === "::") return true;
  if (/^fe[89ab]/.test(normalized)) return true; // link-local
  if (/^f[cd]/.test(normalized)) return true; // unique local
  if (/^ff/.test(normalized)) return true; // multicast
  return false;
}

/**
 * Extrai IPs públicos de um bloco de texto de cabeçalho.
 *
 * @param {string} block O bloco (tipicamente um header Received).
 * @returns {{ipv4: string[], ipv6: string[]}} IPs públicos encontrados.
 */
function extractIpsFromBlock(block) {
  const ipv4 = [];
  const ipv6 = [];
  const value = String(block || "");

  // O delimitador evita casar dentro de timestamps como 2024.10.23.20.13.07
  const v4Pattern = /(?:^|[^0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9.])/g;
  let match;
  while ((match = v4Pattern.exec(value))) {
    const candidate = match[1];
    if (isValidIPv4(candidate) && !isPrivateIPv4(candidate) && ipv4.indexOf(candidate) === -1) {
      ipv4.push(candidate);
    }
  }

  // IPv6 aparece como [IPv6:2607:f8b0::1] ou [2607:f8b0::1]. Colhemos o token
  // inteiro de hex e ":" e validamos depois — tentar casar todas as formas
  // comprimidas num único regex trunca endereços com "::".
  const v6Pattern = /(?:IPv6:)?([0-9A-Fa-f:]{3,45})/g;
  while ((match = v6Pattern.exec(value))) {
    let candidate = match[1].toLowerCase();
    // Apara um ":" solto nas pontas sem destruir a compressão "::".
    if (/^:[^:]/.test(candidate)) candidate = candidate.substring(1);
    if (/[^:]:$/.test(candidate)) candidate = candidate.substring(0, candidate.length - 1);

    if (!isValidIPv6(candidate)) continue;
    if (!isPrivateIPv6(candidate) && ipv6.indexOf(candidate) === -1) {
      ipv6.push(candidate);
    }
  }

  return { ipv4: ipv4, ipv6: ipv6 };
}

/**
 * Valida um endereço IPv6, incluindo a forma comprimida com "::".
 *
 * @param {string} ip O candidato.
 * @returns {boolean} True se for um IPv6 válido.
 */
function isValidIPv6(ip) {
  const value = String(ip || "");
  if (value.indexOf(":") === -1) return false;
  if (!/^[0-9A-Fa-f:]+$/.test(value)) return false;
  if ((value.match(/::/g) || []).length > 1) return false;
  if (/:::/.test(value)) return false;

  const compressed = value.indexOf("::") !== -1;
  const groups = value.split(":").filter(function (group) {
    return group !== "";
  });

  if (groups.some(function (group) { return group.length > 4; })) return false;
  if (compressed) return groups.length <= 7;
  return value.split(":").length === 8 && groups.length === 8;
}

/**
 * Analisa a cadeia de Received e identifica o salto de origem.
 *
 * Os Received são empilhados do mais recente (topo) para o mais antigo
 * (base), então o último é o primeiro salto — o único IP que realmente
 * interessa ao analista.
 *
 * @param {string[]} receivedHeaders Cabeçalhos Received na ordem do raw.
 * @returns {Object} IPs, hosts e o salto de origem.
 */
function analyzeReceivedChain(receivedHeaders) {
  const headers = receivedHeaders || [];
  const allIps = [];
  const hosts = [];

  headers.forEach(function (block) {
    const found = extractIpsFromBlock(block);
    found.ipv4.concat(found.ipv6).forEach(function (ip) {
      if (allIps.indexOf(ip) === -1) allIps.push(ip);
    });

    const hostMatch = block.match(/^from\s+([^\s([]+)/i);
    if (hostMatch && hostMatch[1]) {
      const host = hostMatch[1].toLowerCase().replace(/[.,;]+$/, "");
      if (host && hosts.indexOf(host) === -1) hosts.push(host);
    }
  });

  let originatingIp = null;
  for (let i = headers.length - 1; i >= 0 && !originatingIp; i--) {
    const found = extractIpsFromBlock(headers[i]);
    originatingIp = found.ipv4[0] || found.ipv6[0] || null;
  }

  return {
    receivedIPs: allIps,
    receivedHosts: hosts,
    originatingIP: originatingIp,
    hopCount: headers.length,
  };
}

/** Regras de desembrulho de URLs reescritas por gateways de segurança. */
const URL_UNWRAP_RULES = Object.freeze([
  {
    name: "Microsoft SafeLinks",
    test: /safelinks\.protection\.outlook\.com/i,
    extract: function (url) {
      return getQueryParam(url, "url");
    },
  },
  {
    name: "Proofpoint URLDefense v3",
    test: /urldefense\.(?:com|proofpoint\.com)\/v3\//i,
    extract: function (url) {
      const match = url.match(/\/v3\/__(.+?)__;/);
      if (!match) return null;
      try {
        return decodeURIComponent(match[1]);
      } catch (err) {
        return match[1];
      }
    },
  },
  {
    name: "Proofpoint URLDefense v1/v2",
    test: /urldefense\.(?:com|proofpoint\.com)/i,
    extract: function (url) {
      const raw = getQueryParam(url, "u");
      if (!raw) return null;
      // v2 substitui "/" por "_" e "%" por "-".
      const restored = raw.replace(/-/g, "%").replace(/_/g, "/");
      try {
        return decodeURIComponent(restored);
      } catch (err) {
        return raw;
      }
    },
  },
  {
    name: "Barracuda LinkProtect",
    test: /linkprotect\.cudasvc\.com/i,
    extract: function (url) {
      return getQueryParam(url, "a");
    },
  },
  {
    name: "Mimecast",
    test: /protect(?:-[a-z]{2})?\.mimecast\.com/i,
    extract: function (url) {
      return getQueryParam(url, "domain") || getQueryParam(url, "url");
    },
  },
  {
    name: "Google redirect",
    test: /^https?:\/\/(?:www\.)?google\.[a-z.]+\/url\?/i,
    extract: function (url) {
      return getQueryParam(url, "q") || getQueryParam(url, "url");
    },
  },
  {
    name: "Redirect genérico",
    test: /[?&](?:url|target|redirect|redirect_uri|dest|destination)=https?(?::|%3a)/i,
    extract: function (url) {
      return (
        getQueryParam(url, "url") ||
        getQueryParam(url, "target") ||
        getQueryParam(url, "redirect") ||
        getQueryParam(url, "dest") ||
        getQueryParam(url, "destination")
      );
    },
  },
]);

/**
 * Lê um parâmetro de query string sem depender do construtor `URL`.
 *
 * @param {string} url A URL.
 * @param {string} name Nome do parâmetro.
 * @returns {string|null} O valor decodificado, ou null.
 */
function getQueryParam(url, name) {
  const match = String(url || "").match(
    new RegExp("[?&]" + name + "=([^&#]*)", "i")
  );
  if (!match || !match[1]) return null;
  try {
    return decodeURIComponent(match[1].replace(/\+/g, " "));
  } catch (err) {
    return match[1];
  }
}

/**
 * Desembrulha URLs reescritas por gateways, seguindo até 3 camadas.
 *
 * Sem isso o SOC recebia como IoC o link do próprio gateway em vez do destino
 * real do phishing.
 *
 * @param {string} url A URL possivelmente reescrita.
 * @returns {{url: string, wrappers: string[]}} URL final e camadas removidas.
 */
function unwrapUrl(url) {
  let current = String(url || "");
  const wrappers = [];

  for (let round = 0; round < 3; round++) {
    let unwrapped = null;
    let wrapperName = null;

    for (let i = 0; i < URL_UNWRAP_RULES.length; i++) {
      const rule = URL_UNWRAP_RULES[i];
      if (!rule.test.test(current)) continue;

      const candidate = rule.extract(current);
      if (candidate && /^https?:\/\//i.test(candidate) && candidate !== current) {
        unwrapped = candidate;
        wrapperName = rule.name;
      }
      break;
    }

    if (!unwrapped) break;
    wrappers.push(wrapperName);
    current = unwrapped;
  }

  return { url: current, wrappers: wrappers };
}

/**
 * Indica se uma URL é apenas metadado (namespace XML, esquema) e não IoC.
 *
 * @param {string} url A URL.
 * @returns {boolean} True se deve ser descartada.
 */
function isExcludedUrl(url) {
  const normalized = String(url || "").toLowerCase();
  return NON_IOC_URL_PATTERNS.some(function (pattern) {
    return normalized.indexOf(pattern) !== -1;
  });
}

/**
 * Extrai URLs dos corpos já decodificados.
 *
 * @param {{text: string[], html: string[]}} bodies Corpos decodificados.
 * @returns {Array<Object>} URLs normalizadas com metadados.
 */
function extractUrls(bodies) {
  const parts = (bodies.text || []).concat(bodies.html || []);
  const combined = parts.join("\n\n");
  const pattern = /https?:\/\/[^\s"'<>()\[\]\\`]+/gi;
  const found = combined.match(pattern) || [];

  const results = [];
  const seen = Object.create(null);

  found.forEach(function (candidate) {
    // Pontuação final costuma pertencer à frase, não à URL.
    const cleaned = candidate.replace(/[.,;:!?)>'"]+$/, "");
    if (!cleaned || isExcludedUrl(cleaned)) return;

    const unwrapResult = unwrapUrl(cleaned);
    const finalUrl = unwrapResult.url;
    if (isExcludedUrl(finalUrl)) return;

    const key = finalUrl.toLowerCase();
    if (seen[key]) return;
    seen[key] = true;

    const host = getHostname(finalUrl);
    results.push({
      url: finalUrl,
      original: unwrapResult.wrappers.length ? cleaned : null,
      wrappers: unwrapResult.wrappers,
      host: host,
      registrable: registrableDomain(host),
      isShortener: isUrlShortener(host),
      isIpLiteral: !!host && /^\d{1,3}(\.\d{1,3}){3}$/.test(host),
      isPunycode: !!host && host.indexOf("xn--") !== -1,
    });
  });

  return results;
}

/**
 * Encontra links cujo texto visível aponta para um domínio diferente do href
 * — o disfarce mais clássico de phishing em HTML.
 *
 * @param {string[]} htmlParts Corpos HTML decodificados.
 * @returns {Array<{href: string, text: string, hrefHost: string, textHost: string}>} Divergências.
 */
function findAnchorMismatches(htmlParts) {
  const mismatches = [];
  const pattern = /<a\b[^>]*href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;

  (htmlParts || []).forEach(function (html) {
    let match;
    while ((match = pattern.exec(html))) {
      const href = (match[1] || match[2] || match[3] || "").trim();
      if (!/^https?:\/\//i.test(href)) continue;

      const text = htmlToText(match[4] || "").trim();
      // Só interessa quando o texto visível SE PARECE com um endereço.
      const textUrlMatch = text.match(
        /(?:https?:\/\/)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})/i
      );
      if (!textUrlMatch) continue;

      const hrefHost = getHostname(unwrapUrl(href).url);
      const textHost = textUrlMatch[1].toLowerCase();

      if (hrefHost && !domainsAligned(hrefHost, textHost)) {
        mismatches.push({
          href: unwrapUrl(href).url,
          text: truncateText(text, 120),
          hrefHost: hrefHost,
          textHost: textHost,
        });
      }
      if (mismatches.length >= 20) return;
    }
  });

  return mismatches;
}

/**
 * Lê os anexos reais da mensagem e calcula o SHA-256 de cada um.
 *
 * O relatório anterior enviava `attachments: []` ao SIEM, justamente o IoC
 * mais pesquisável (VirusTotal aceita hash direto).
 *
 * @param {string} messageId ID da mensagem no Gmail.
 * @param {Array<Object>} [declared] Anexos vistos no raw, como fallback.
 * @returns {Array<Object>} Anexos com nome, tipo, tamanho e hash.
 */
function collectAttachments(messageId, declared) {
  const results = [];
  if (!messageId) return declared || [];

  try {
    const message = GmailApp.getMessageById(messageId);
    const attachments = message.getAttachments({
      includeInlineImages: true,
      includeAttachments: true,
    });

    attachments.forEach(function (attachment) {
      const entry = {
        name: attachment.getName(),
        type: attachment.getContentType(),
        size: attachment.getSize(),
        sha256: null,
        extension: getFileExtension(attachment.getName()),
      };

      try {
        // Hashear arquivos muito grandes estoura o tempo de execução.
        if (entry.size && entry.size <= 20 * 1024 * 1024) {
          entry.sha256 = sha256HexFromBytes(attachment.getBytes());
        }
      } catch (hashErr) {
        console.warn(`Falha ao hashear o anexo ${entry.name}:`, hashErr);
      }

      results.push(entry);
    });
  } catch (err) {
    console.warn("Falha ao ler anexos via GmailApp; usando os declarados:", err);
    return declared || [];
  }

  return results.length ? results : declared || [];
}

/**
 * Extrai a extensão de um nome de arquivo, em minúsculas.
 *
 * @param {string} filename O nome do arquivo.
 * @returns {string} A extensão sem ponto, ou string vazia.
 */
function getFileExtension(filename) {
  const match = String(filename || "").match(/\.([A-Za-z0-9]{1,10})$/);
  return match ? match[1].toLowerCase() : "";
}

/**
 * Monta o relatório de IoCs completo a partir do .eml.
 *
 * @param {string} rawContent Conteúdo bruto do .eml (byte-transparente).
 * @param {Object} [options] Opções.
 * @param {number[]} [options.rawBytes] Bytes originais, para o hash forense.
 * @param {string} [options.messageId] ID no Gmail, para hashear anexos.
 * @returns {Object} Relatório pronto para ingestão em SIEM.
 */
function buildIocReport(rawContent, options) {
  const opts = options || {};
  const headers = parseEmailHeaders(rawContent);
  const bodies = walkMimeParts(rawContent);
  const urls = extractUrls(bodies);
  const chain = analyzeReceivedChain(headers.receivedHeaders);
  const anchorMismatches = findAnchorMismatches(bodies.html);

  const attachments = collectAttachments(opts.messageId, parseAttachments(rawContent));

  // Hash dos BYTES originais — bate com o sha256sum do .eml anexado.
  const rawSha256 = opts.rawBytes
    ? sha256HexFromBytes(opts.rawBytes)
    : sha256HexFromBytes(latin1Bytes(rawContent));

  const domains = collectDomains(headers, chain, urls);

  const report = {
    generated_at: new Date().toISOString(),
    raw_sha256: rawSha256,
    subject: headers.subject,
    from: headers.from,
    fromDisplayName: headers.displayName || null,
    to: headers.to,
    replyTo: headers.replyTo,
    returnPath: headers.returnPath,
    xOriginalFrom: headers.xOriginalFrom,
    messageId: headers.messageId,
    date: headers.date ? headers.date.toISOString() : null,
    userAgent: headers.userAgent,

    receivedHeaders: headers.receivedHeaders.map(function (h) {
      return truncateText(h, 500);
    }),
    receivedIPs: chain.receivedIPs,
    receivedHosts: chain.receivedHosts,
    originatingIP: chain.originatingIP,
    hopCount: chain.hopCount,

    authenticationResults: headers.authenticationResults,
    dkimSignatures: headers.dkimSignatures,
    arcResults: headers.arcResults,

    listId: headers.listId,
    xGoogleGroupId: headers.xGoogleGroupId,
    xForwardedEncrypted: headers.xForwardedEncrypted,
    isMailingList: detectMailingList(headers),
    isGoogleGroup: detectGoogleGroup(headers),

    urls: urls.map(function (u) {
      return u.url;
    }),
    urlDetails: urls,
    anchorMismatches: anchorMismatches,
    domains: domains,
    attachments: attachments,

    bodyPreview: truncateText(
      (bodies.text[0] || htmlToText(bodies.html[0] || "")).replace(/\s+/g, " ").trim(),
      500
    ),

    suspiciousFlags: [],
  };

  // Guardados fora do JSON para não inflar o anexo do SIEM.
  Object.defineProperty(report, "_bodies", { value: bodies, enumerable: false });

  return report;
}

/**
 * Reúne todos os domínios observados na mensagem.
 *
 * @param {Object} headers Cabeçalhos analisados.
 * @param {Object} chain Resultado da cadeia de Received.
 * @param {Array<Object>} urls URLs extraídas.
 * @returns {string[]} Domínios únicos.
 */
function collectDomains(headers, chain, urls) {
  const seen = Object.create(null);
  const domains = [];

  const add = function (candidate) {
    const value = String(candidate || "").toLowerCase().replace(/[.,;]+$/, "");
    if (!value || value === "n/a" || seen[value]) return;
    seen[value] = true;
    domains.push(value);
  };

  [headers.from, headers.returnPath, headers.replyTo, headers.xOriginalFrom].forEach(
    function (address) {
      if (address) {
        const domain = getDomainFromEmail(address);
        if (domain !== "N/A") add(domain);
      }
    }
  );

  (chain.receivedHosts || []).forEach(add);
  // Antes esta parte usava `new URL()`, inexistente no Apps Script, e o catch
  // vazio fazia todos os hosts de URL sumirem do relatório.
  (urls || []).forEach(function (entry) {
    if (entry.host) add(entry.host);
  });

  return domains;
}

/**
 * Detecta se a mensagem veio de uma lista de distribuição.
 *
 * Centralizado aqui porque antes existiam duas implementações divergentes
 * (uma em gemini.gs, outra no cálculo de risco).
 *
 * @param {Object} headers Cabeçalhos analisados.
 * @returns {boolean} True se for lista de distribuição.
 */
function detectMailingList(headers) {
  return !!(
    headers.listId ||
    headers.listUnsubscribe ||
    headers.xGoogleGroupId ||
    (headers.precedence && /^(list|bulk)$/i.test(headers.precedence.trim())) ||
    detectGoogleGroup(headers)
  );
}

/**
 * Detecta especificamente um Google Group.
 *
 * @param {Object} headers Cabeçalhos analisados.
 * @returns {boolean} True se for Google Group.
 */
function detectGoogleGroup(headers) {
  return !!(
    headers.xGoogleGroupId ||
    (headers.returnPath && headers.returnPath.indexOf("googlegroups.com") !== -1) ||
    (headers.listId && headers.listId.indexOf("googlegroups.com") !== -1)
  );
}
