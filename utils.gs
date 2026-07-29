/**
 * @fileoverview Utilitários compartilhados: escaping, domínios, defanging,
 * hashing e cache. Sem dependências de outros arquivos do projeto, para que a
 * ordem de carregamento do Apps Script não importe.
 */

/** Sufixos de segundo nível comuns, usados para achar o domínio registrável. */
const MULTI_PART_TLDS = Object.freeze([
  "com.br", "net.br", "org.br", "gov.br", "edu.br", "jus.br", "leg.br", "mil.br",
  "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "co.kr", "co.in", "co.za",
  "com.au", "net.au", "org.au", "com.ar", "com.mx", "com.co", "com.pe",
  "com.pt", "com.es", "com.tr", "com.cn", "com.hk", "com.sg", "com.tw",
]);

/**
 * Escapa caracteres especiais de HTML.
 *
 * Diferente da versão anterior, NÃO escapa "/" (quebrava URLs em href) e
 * sempre devolve string, evitando "undefined" impresso em templates.
 *
 * @param {*} text Valor a escapar.
 * @returns {string} Texto seguro para interpolar em HTML.
 */
function escapeHtml(text) {
  if (text === null || text === undefined) return "";

  const entities = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };
  return String(text).replace(/[&<>"']/g, function (char) {
    return entities[char];
  });
}

/**
 * Escapa texto para mrkdwn do Slack.
 *
 * Sem isso, um assunto como `<https://evil.com|Clique aqui>` vira um link
 * ativo e convincente dentro do canal do SOC — o atacante controla o assunto.
 *
 * @param {*} text Valor a escapar.
 * @returns {string} Texto seguro para um bloco do Slack.
 */
function escapeSlackText(text) {
  if (text === null || text === undefined) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/**
 * Escapa texto que vai dentro de crase (código) no Slack, onde a crase
 * encerraria o trecho.
 *
 * @param {*} text Valor a escapar.
 * @returns {string} Texto seguro para code span.
 */
function escapeSlackCode(text) {
  return escapeSlackText(text).replace(/`/g, "ˋ");
}

/**
 * Valida e escapa uma URL destinada a um atributo href.
 * Só permite http, https e mailto — bloqueia javascript: e data:.
 *
 * @param {string} url A URL candidata.
 * @returns {string|null} A URL escapada, ou null se não for segura.
 */
function sanitizeHref(url) {
  if (!url) return null;
  const trimmed = String(url).trim();
  if (!/^(https?:|mailto:)/i.test(trimmed)) return null;
  // Sem escapar "/", senão o href sai quebrado visualmente.
  return trimmed.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "%3C").replace(/>/g, "%3E");
}

/**
 * Trunca um texto preservando o início e sinalizando o corte.
 *
 * @param {*} text Texto de entrada.
 * @param {number} maxLength Tamanho máximo do resultado.
 * @returns {string} Texto truncado.
 */
function truncateText(text, maxLength) {
  const value = text === null || text === undefined ? "" : String(text);
  if (value.length <= maxLength) return value;
  const suffix = "… [truncado]";
  return value.substring(0, Math.max(0, maxLength - suffix.length)) + suffix;
}

/**
 * Extrai o hostname de uma URL sem depender do construtor `URL`, que não
 * existe no runtime V8 do Apps Script (era engolido por um catch vazio,
 * fazendo o relatório de IoC sair sem os domínios das URLs).
 *
 * @param {string} url A URL.
 * @returns {string|null} O hostname em minúsculas, ou null.
 */
function getHostname(url) {
  if (!url) return null;
  const match = String(url).match(
    /^[a-z][a-z0-9+.\-]*:\/\/(?:[^@/\s]*@)?([^/:\s?#]+)/i
  );
  if (!match) return null;

  let host = match[1].toLowerCase().replace(/\.+$/, "");
  // Remove colchetes de literais IPv6.
  host = host.replace(/^\[|\]$/g, "");
  return host || null;
}

/**
 * Extrai o domínio de um endereço de e-mail (aceita "Nome <a@b.com>").
 *
 * @param {string} email O endereço ou header completo.
 * @returns {string} O domínio em minúsculas, ou "N/A".
 */
function getDomainFromEmail(email) {
  if (!email) return "N/A";

  const withAngles = String(email).match(/<[^>]*@([^>\s]+)>/);
  if (withAngles && withAngles[1]) {
    return withAngles[1].toLowerCase().replace(/[.,;]+$/, "");
  }

  const plain = String(email).match(/@([^\s>,;]+)/);
  if (plain && plain[1]) {
    return plain[1].toLowerCase().replace(/[.,;]+$/, "");
  }

  const hostLike = String(email).match(/([a-z0-9\-._]+\.[a-z]{2,})/i);
  return hostLike ? hostLike[1].toLowerCase() : "N/A";
}

/**
 * Reduz um hostname ao domínio registrável (eTLD+1), com heurística de
 * sufixos compostos. Não é a Public Suffix List completa, mas cobre os casos
 * relevantes sem embutir uma tabela de milhares de entradas.
 *
 * @param {string} host O hostname.
 * @returns {string|null} O domínio registrável, ou null.
 */
function registrableDomain(host) {
  if (!host) return null;
  const normalized = String(host).toLowerCase().replace(/\.+$/, "");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(normalized)) return normalized; // literal IPv4

  const labels = normalized.split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".") || null;

  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_PART_TLDS.indexOf(lastTwo) !== -1) {
    return labels.slice(-3).join(".");
  }
  return lastTwo;
}

/**
 * Verifica se dois domínios pertencem à mesma organização (mesmo eTLD+1).
 *
 * @param {string} a Primeiro domínio.
 * @param {string} b Segundo domínio.
 * @returns {boolean} True se alinhados.
 */
function domainsAligned(a, b) {
  if (!a || !b || a === "N/A" || b === "N/A") return false;
  const ra = registrableDomain(a);
  const rb = registrableDomain(b);
  return !!ra && !!rb && ra === rb;
}

/**
 * Neutraliza uma URL para que não seja clicável nem auto-linkada pelo cliente
 * de e-mail. Segue a convenção de SOC: hxxp e [.] nos pontos.
 *
 * @param {string} url A URL original.
 * @param {boolean} [domainOnly] Se true, devolve só protocolo + domínio.
 * @returns {string} A URL neutralizada.
 */
function defangUrl(url, domainOnly) {
  if (!url) return "";

  const value = String(url);
  const match = value.match(/^(https?)(:\/\/)([^/\s?#]+)(.*)$/i);

  if (match) {
    const scheme = match[1].toLowerCase() === "https" ? "hxxps" : "hxxp";
    const domain = match[3].replace(/\./g, "[.]");
    return scheme + match[2] + domain + (domainOnly ? "" : match[4]);
  }

  if (domainOnly) {
    const hostOnly = value.match(/^([^/\s?#]+)/);
    if (hostOnly) return hostOnly[1].replace(/\./g, "[.]");
  }
  return value.replace(/\./g, "[.]");
}

/**
 * Neutraliza um endereço de e-mail para exibição.
 *
 * @param {string} email O endereço.
 * @returns {string} O endereço neutralizado.
 */
function defangEmail(email) {
  if (!email) return "";
  return String(email).replace(/@/g, "[at]").replace(/\./g, "[.]");
}

/**
 * Converte uma string byte-transparente (lida como ISO-8859-1) em bytes.
 *
 * @param {string} text A string.
 * @returns {number[]} Bytes sem sinal (0-255).
 */
function latin1Bytes(text) {
  const bytes = [];
  const value = String(text || "");
  for (let i = 0; i < value.length; i++) {
    bytes.push(value.charCodeAt(i) & 0xff);
  }
  return bytes;
}

/**
 * Converte bytes sem sinal em bytes com sinal, formato usado pelas APIs de
 * Utilities do Apps Script.
 *
 * @param {number[]} bytes Bytes 0-255.
 * @returns {number[]} Bytes -128..127.
 */
function toSignedBytes(bytes) {
  return bytes.map(function (b) {
    return b > 127 ? b - 256 : b;
  });
}

/**
 * SHA-256 em hexadecimal a partir de bytes.
 *
 * Hashear bytes (e não a string re-codificada em UTF-8, como antes) é o que
 * faz o hash bater com o `sha256sum` que o analista roda no .eml anexado.
 *
 * @param {number[]} bytes Bytes com ou sem sinal.
 * @returns {string} Digest hexadecimal.
 */
function sha256HexFromBytes(bytes) {
  const signed = bytes.map(function (b) {
    return b > 127 ? b - 256 : b;
  });
  const digest = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    signed
  );
  return digest
    .map(function (b) {
      const hex = (b < 0 ? b + 256 : b).toString(16);
      return hex.length === 1 ? "0" + hex : hex;
    })
    .join("");
}

/**
 * Remove acentos de um texto.
 *
 * Necessário na comparação de nomes de exibição: a lista de marcas é escrita
 * sem acento, mas o atacante assina como "Segurança Itaú".
 *
 * @param {string} text O texto.
 * @returns {string} O texto sem diacríticos.
 */
function stripDiacritics(text) {
  if (!text) return "";
  try {
    // Remove a faixa de marcas combinantes U+0300..U+036F deixada pelo NFD.
    return String(text)
      .normalize("NFD")
      .split("")
      .filter(function (char) {
        const code = char.charCodeAt(0);
        return code < 0x0300 || code > 0x036f;
      })
      .join("");
  } catch (err) {
    return String(text);
  }
}

/**
 * Distância de Levenshtein, usada na detecção de domínios sósia.
 *
 * @param {string} a Primeira string.
 * @param {string} b Segunda string.
 * @returns {number} Número de edições.
 */
function levenshteinDistance(a, b) {
  const source = String(a || "");
  const target = String(b || "");
  if (source === target) return 0;
  if (!source.length) return target.length;
  if (!target.length) return source.length;

  let previous = [];
  for (let j = 0; j <= target.length; j++) previous[j] = j;

  for (let i = 1; i <= source.length; i++) {
    const current = [i];
    for (let j = 1; j <= target.length; j++) {
      const cost = source.charAt(i - 1) === target.charAt(j - 1) ? 0 : 1;
      current[j] = Math.min(
        current[j - 1] + 1,
        previous[j] + 1,
        previous[j - 1] + cost
      );
    }
    previous = current;
  }
  return previous[target.length];
}

/**
 * Converte uma data em ISO "YYYY-MM-DD HH:mm:ss UTC" sem lançar exceção.
 *
 * Um header Date malformado produzia Invalid Date, e o .toISOString()
 * seguinte derrubava o relatório inteiro.
 *
 * @param {Date} date A data.
 * @param {string} [fallback] Texto usado se a data for inválida.
 * @returns {string} A data formatada.
 */
function formatUtc(date, fallback) {
  const placeholder = fallback || "Data desconhecida";
  if (!isValidDate(date)) return placeholder;
  return date.toISOString().replace("T", " ").split(".")[0] + " UTC";
}

/**
 * Formata uma data no fuso informado, com degradação segura para UTC.
 *
 * @param {Date} date A data.
 * @param {string} timeZone Identificador IANA do fuso.
 * @returns {string} A data formatada.
 */
function formatInTimeZone(date, timeZone) {
  if (!isValidDate(date)) return "Data desconhecida";
  try {
    return date.toLocaleString("pt-BR", {
      timeZone: timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch (err) {
    return formatUtc(date);
  }
}

/**
 * Verifica se o valor é uma data utilizável.
 *
 * @param {*} date Valor a testar.
 * @returns {boolean} True se for um Date válido.
 */
function isValidDate(date) {
  return (
    date instanceof Date && !isNaN(typeof date.getTime === "function" ? date.getTime() : NaN)
  );
}

/**
 * Converte uma data em uma data válida, caindo para "agora" se necessário.
 *
 * @param {*} value Valor de entrada (Date ou string).
 * @returns {Date} Uma data sempre válida.
 */
function coerceDate(value) {
  if (isValidDate(value)) return value;
  if (value) {
    const parsed = new Date(value);
    if (isValidDate(parsed)) return parsed;
  }
  return new Date();
}

/**
 * Monta o link de busca do Gmail por Message-ID.
 *
 * @param {string} messageId O Message-ID RFC822.
 * @returns {string|null} A URL de busca, ou null.
 */
function buildRfc822SearchLink(messageId) {
  if (!messageId) return null;
  try {
    return (
      "https://mail.google.com/mail/u/0/#search/" +
      encodeURIComponent("rfc822msgid:" + messageId)
    );
  } catch (err) {
    return null;
  }
}

/**
 * Lê um valor JSON do cache do usuário.
 *
 * @param {string} key Chave do cache.
 * @returns {Object|null} O valor desserializado, ou null.
 */
function cacheGetJson(key) {
  try {
    const raw = CacheService.getUserCache().get(key);
    return raw ? JSON.parse(raw) : null;
  } catch (err) {
    console.warn("Falha ao ler o cache:", err);
    return null;
  }
}

/**
 * Grava um valor JSON no cache do usuário. Itens acima do limite de 100 KB do
 * CacheService são descartados silenciosamente — o cache é otimização, não
 * fonte de verdade.
 *
 * @param {string} key Chave do cache.
 * @param {Object} value Valor serializável.
 * @param {number} ttlSeconds Tempo de vida em segundos.
 */
function cachePutJson(key, value, ttlSeconds) {
  try {
    const serialized = JSON.stringify(value);
    if (serialized.length > 95000) return;
    CacheService.getUserCache().put(key, serialized, ttlSeconds);
  } catch (err) {
    console.warn("Falha ao gravar no cache:", err);
  }
}

/**
 * Remove uma chave do cache do usuário.
 *
 * @param {string} key Chave do cache.
 */
function cacheRemove(key) {
  try {
    CacheService.getUserCache().remove(key);
  } catch (err) {
    console.warn("Falha ao remover do cache:", err);
  }
}

/**
 * Formata um tamanho em bytes de forma legível.
 *
 * @param {number} bytes O tamanho.
 * @returns {string} Tamanho formatado.
 */
function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return "tamanho desconhecido";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * UrlFetch com retry exponencial em 429 e 5xx.
 *
 * @param {string} url URL de destino.
 * @param {Object} options Opções do UrlFetchApp.
 * @param {number} maxAttempts Número máximo de tentativas.
 * @returns {HTTPResponse} A última resposta obtida.
 */
function fetchWithRetry(url, options, maxAttempts) {
  const attempts = maxAttempts || 3;
  let response = null;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    response = UrlFetchApp.fetch(url, options);
    const code = response.getResponseCode();

    if (code !== 429 && code < 500) return response;

    if (attempt < attempts) {
      const backoff = Math.pow(2, attempt) * 500 + Math.floor(Math.random() * 250);
      console.warn(
        `HTTP ${code}; nova tentativa em ${backoff} ms (${attempt}/${attempts}).`
      );
      Utilities.sleep(backoff);
    }
  }
  return response;
}
