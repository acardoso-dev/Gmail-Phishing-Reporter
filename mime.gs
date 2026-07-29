/**
 * @fileoverview Decodificação MIME e parsing de cabeçalhos RFC 5322 / 2047.
 *
 * Este arquivo substitui as duas implementações duplicadas que existiam em
 * main.gs (parseEmailHeaders e parseEmailHeadersExtended), que reimplementavam
 * os mesmos regexes, ignoravam header folding e apagavam — em vez de
 * decodificar — assuntos codificados em RFC 2047.
 */

/** Profundidade máxima ao descer na árvore MIME (protege contra aninhamento patológico). */
const MAX_MIME_DEPTH = 12;

/** Apelidos de charset para nomes que o Java/Apps Script reconhece. */
const CHARSET_ALIASES = Object.freeze({
  "utf8": "UTF-8",
  "utf-8": "UTF-8",
  "us-ascii": "US-ASCII",
  "ascii": "US-ASCII",
  "iso-8859-1": "ISO-8859-1",
  "latin1": "ISO-8859-1",
  "iso8859-1": "ISO-8859-1",
  "iso-8859-15": "ISO-8859-15",
  "windows-1252": "windows-1252",
  "cp1252": "windows-1252",
  "windows-1250": "windows-1250",
  "iso-2022-jp": "ISO-2022-JP",
  "shift_jis": "Shift_JIS",
  "koi8-r": "KOI8-R",
  "gb2312": "GB2312",
  "gbk": "GBK",
  "big5": "Big5",
});

/**
 * Normaliza o nome de um charset.
 *
 * @param {string} charset Nome bruto vindo do header.
 * @returns {string} Nome normalizado (UTF-8 como padrão).
 */
function normalizeCharset(charset) {
  if (!charset) return "UTF-8";
  const key = String(charset).trim().toLowerCase().replace(/^["']|["']$/g, "");
  return CHARSET_ALIASES[key] || String(charset).trim().replace(/^["']|["']$/g, "") || "UTF-8";
}

/**
 * Converte bytes para string usando o charset indicado, com fallbacks.
 *
 * @param {number[]} bytes Bytes sem sinal.
 * @param {string} charset Charset de origem.
 * @returns {string} A string decodificada.
 */
function bytesToString(bytes, charset) {
  if (!bytes || !bytes.length) return "";
  const signed = toSignedBytes(bytes);

  try {
    return Utilities.newBlob(signed).getDataAsString(normalizeCharset(charset));
  } catch (err) {
    try {
      return Utilities.newBlob(signed).getDataAsString("UTF-8");
    } catch (err2) {
      return bytes
        .map(function (b) {
          return String.fromCharCode(b);
        })
        .join("");
    }
  }
}

/**
 * Decodifica Quoted-Printable para bytes.
 *
 * @param {string} text Conteúdo codificado.
 * @returns {number[]} Bytes sem sinal.
 */
function quotedPrintableToBytes(text) {
  const bytes = [];
  if (!text) return bytes;

  // Soft line breaks: "=" no fim da linha.
  const compact = String(text).replace(/=\r?\n/g, "");

  for (let i = 0; i < compact.length; i++) {
    const code = compact.charCodeAt(i);

    if (code === 61 /* = */ && i + 2 < compact.length) {
      const hex = compact.substr(i + 1, 2);
      if (/^[0-9A-F]{2}$/i.test(hex)) {
        bytes.push(parseInt(hex, 16));
        i += 2;
        continue;
      }
    }

    if (code <= 0xff) {
      // String byte-transparente (lida como ISO-8859-1): o code JÁ é o byte.
      bytes.push(code);
    } else {
      // String já em Unicode: re-serializa o caractere em UTF-8.
      const utf8 = unescape(encodeURIComponent(compact.charAt(i)));
      for (let j = 0; j < utf8.length; j++) bytes.push(utf8.charCodeAt(j) & 0xff);
    }
  }
  return bytes;
}

/**
 * Decodifica um bloco Quoted-Printable em string.
 *
 * @param {string} text Conteúdo codificado.
 * @param {string} [charset] Charset do conteúdo.
 * @returns {string} O texto decodificado.
 */
function decodeQuotedPrintable(text, charset) {
  return bytesToString(quotedPrintableToBytes(text), charset || "UTF-8");
}

/**
 * Decodifica um bloco Base64 em string.
 *
 * @param {string} text Conteúdo codificado.
 * @param {string} [charset] Charset do conteúdo.
 * @returns {string} O texto decodificado, ou o original em caso de falha.
 */
function decodeBase64Text(text, charset) {
  if (!text) return "";
  try {
    const cleaned = String(text).replace(/[^A-Za-z0-9+/=]/g, "");
    if (!cleaned) return "";
    const decoded = Utilities.base64Decode(cleaned);
    return Utilities.newBlob(decoded).getDataAsString(normalizeCharset(charset));
  } catch (err) {
    return String(text);
  }
}

/**
 * Decodifica encoded-words RFC 2047 ("=?UTF-8?B?...?=").
 *
 * A versão anterior APAGAVA esses trechos, então qualquer assunto acentuado
 * — a maioria em pt-BR — chegava vazio ao SOC e virava "Sem Assunto".
 *
 * @param {string} text Texto possivelmente codificado.
 * @returns {string} O texto decodificado.
 */
function decodeMimeEncodedWords(text) {
  if (!text) return "";

  // RFC 2047 §6.2: espaço entre encoded-words adjacentes é ignorado.
  const joined = String(text).replace(
    /(=\?[^?]+\?[BbQq]\?[^?]*\?=)[ \t]+(?==\?[^?]+\?[BbQq]\?)/g,
    "$1"
  );

  return joined.replace(
    /=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g,
    function (whole, charset, encoding, payload) {
      try {
        const bytes =
          encoding.toUpperCase() === "B"
            ? Utilities.base64Decode(payload.replace(/[^A-Za-z0-9+/=]/g, "")).map(
                function (b) {
                  return b < 0 ? b + 256 : b;
                }
              )
            : quotedPrintableToBytes(payload.replace(/_/g, " "));

        const decoded = bytesToString(bytes, charset);
        return decoded || whole;
      } catch (err) {
        return whole;
      }
    }
  );
}

/**
 * Remove o folding de cabeçalhos (RFC 5322 §2.2.3), juntando linhas de
 * continuação. Sem isso, assuntos longos e listas de destinatários chegavam
 * truncados na primeira linha física.
 *
 * @param {string} headerSection Bloco de cabeçalhos.
 * @returns {string} Bloco com um cabeçalho por linha.
 */
function unfoldHeaders(headerSection) {
  return String(headerSection || "").replace(/\r?\n[ \t]+/g, " ");
}

/**
 * Separa cabeçalhos e corpo de uma entidade MIME.
 *
 * @param {string} chunk Entidade completa.
 * @returns {{headers: string, body: string}|null} As duas partes, ou null.
 */
function splitHeadersAndBody(chunk) {
  const value = String(chunk || "");
  const index = value.search(/\r?\n\r?\n/);
  if (index === -1) return { headers: value, body: "" };

  return {
    headers: value.substring(0, index),
    body: value.substring(index).replace(/^\r?\n\r?\n/, ""),
  };
}

/**
 * Lê o valor da primeira ocorrência de um cabeçalho.
 *
 * @param {string} unfolded Bloco de cabeçalhos já sem folding.
 * @param {string} name Nome do cabeçalho.
 * @returns {string|null} O valor bruto, ou null.
 */
function readHeader(unfolded, name) {
  const pattern = new RegExp(
    "^" + name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&") + ":[ \\t]*(.*)$",
    "im"
  );
  const match = String(unfolded || "").match(pattern);
  return match ? match[1].trim() : null;
}

/**
 * Lê todas as ocorrências de um cabeçalho, na ordem em que aparecem
 * (a primeira é a do salto mais recente).
 *
 * @param {string} unfolded Bloco de cabeçalhos já sem folding.
 * @param {string} name Nome do cabeçalho.
 * @returns {string[]} Todos os valores encontrados.
 */
function readAllHeaders(unfolded, name) {
  const pattern = new RegExp(
    "^" + name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&") + ":[ \\t]*(.*)$",
    "gim"
  );
  const values = [];
  let match;
  while ((match = pattern.exec(String(unfolded || "")))) {
    values.push(match[1].trim());
  }
  return values;
}

/**
 * Extrai o nome de exibição de um cabeçalho From/To, decodificando RFC 2047.
 *
 * A versão anterior não decodificava, então nomes acentuados nunca casavam e
 * a checagem de display-name spoofing simplesmente não disparava.
 *
 * @param {string} addressHeader O cabeçalho bruto.
 * @returns {string} O nome de exibição, ou string vazia.
 */
function getDisplayName(addressHeader) {
  if (!addressHeader) return "";

  const value = decodeMimeEncodedWords(String(addressHeader)).trim();
  const withAngles = value.match(/^([\s\S]*?)<[^>]*>/);
  if (!withAngles) return "";

  return withAngles[1]
    .trim()
    .replace(/^["']|["']$/g, "")
    .trim();
}

/**
 * Extrai o endereço de e-mail de um cabeçalho.
 *
 * @param {string} addressHeader O cabeçalho bruto.
 * @returns {string} O endereço em minúsculas, ou string vazia.
 */
function extractEmailAddress(addressHeader) {
  if (!addressHeader) return "";

  const value = String(addressHeader);
  const withAngles = value.match(/<([^>]+)>/);
  const candidate = withAngles ? withAngles[1] : value;

  const address = candidate.match(/[^\s<>,;:"]+@[^\s<>,;:"]+/);
  return address ? address[0].toLowerCase().replace(/[.,;]+$/, "") : "";
}

/**
 * Versão amigável para exibição: endereço quando disponível, senão o texto.
 *
 * @param {string} addressHeader O cabeçalho bruto.
 * @param {string} [fallback] Texto para header ausente.
 * @returns {string} O endereço para exibição.
 */
function cleanEmailAddress(addressHeader, fallback) {
  if (!addressHeader) return fallback || "Remetente desconhecido";
  const address = extractEmailAddress(addressHeader);
  return address || decodeMimeEncodedWords(String(addressHeader)).trim();
}

/**
 * Normaliza o assunto, decodificando RFC 2047 e colapsando espaços.
 *
 * @param {string} subject O assunto bruto.
 * @returns {string} O assunto legível.
 */
function cleanSubject(subject) {
  if (!subject) return "Sem Assunto";
  const decoded = decodeMimeEncodedWords(String(subject))
    .replace(/[\r\n]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return decoded || "Sem Assunto";
}

/**
 * Percorre a árvore MIME e devolve os corpos de texto decodificados.
 *
 * Correções em relação à versão anterior:
 *  - a última parte não é mais descartada quando falta o "--boundary--" final
 *    (MIME malformado é comum em phishing, e a parte perdida era o HTML);
 *  - partes text/* marcadas como anexo não entram no corpo;
 *  - o fallback de decodificar o raw inteiro como Quoted-Printable só roda se
 *    o parse estruturado não achou nada (antes rodava sempre, duplicando o
 *    trabalho e injetando ruído de blobs base64).
 *
 * @param {string} rawContent Conteúdo bruto do .eml.
 * @returns {{text: string[], html: string[]}} Corpos decodificados.
 */
function walkMimeParts(rawContent) {
  const collected = { text: [], html: [] };
  if (!rawContent) return collected;

  const root = splitHeadersAndBody(rawContent);
  processMimePart(root.headers, root.body, collected, 0);

  if (!collected.text.length && !collected.html.length) {
    // Fallback: mensagem sem estrutura MIME reconhecível.
    collected.text.push(decodeQuotedPrintable(root.body || rawContent, "UTF-8"));
  }
  return collected;
}

/**
 * Processa recursivamente uma entidade MIME.
 *
 * @param {string} headers Cabeçalhos da parte.
 * @param {string} body Corpo da parte.
 * @param {{text: string[], html: string[]}} collected Acumulador.
 * @param {number} depth Profundidade atual.
 */
function processMimePart(headers, body, collected, depth) {
  if (depth > MAX_MIME_DEPTH) return;

  const unfolded = unfoldHeaders(headers);
  // O valor original precisa ser preservado: boundaries MIME diferenciam
  // maiúsculas de minúsculas, então comparar sobre a versão em minúsculas
  // faz o split nunca casar e a mensagem inteira virar uma parte só.
  const rawContentType = readHeader(unfolded, "Content-Type") || "text/plain";
  const contentType = rawContentType.toLowerCase();
  const mediaType = contentType.split(";")[0].trim();

  if (mediaType.indexOf("multipart/") === 0) {
    const boundaryMatch = rawContentType.match(
      /boundary\s*=\s*"([^"]+)"|boundary\s*=\s*([^;\s]+)/i
    );
    const boundary = boundaryMatch ? boundaryMatch[1] || boundaryMatch[2] : null;
    if (!boundary) return;

    const chunks = String(body).split("--" + boundary);
    // chunks[0] é o preâmbulo. Um chunk iniciado por "--" é o terminador,
    // e o que vem depois é epílogo: paramos ali.
    for (let i = 1; i < chunks.length; i++) {
      if (/^--/.test(chunks[i])) break;
      const part = splitHeadersAndBody(chunks[i]);
      processMimePart(part.headers, part.body, collected, depth + 1);
    }
    return;
  }

  if (mediaType === "message/rfc822") {
    const nested = splitHeadersAndBody(body);
    processMimePart(nested.headers, nested.body, collected, depth + 1);
    return;
  }

  if (mediaType !== "text/plain" && mediaType !== "text/html") return;

  // Um .txt ou .html anexado é anexo, não corpo da mensagem.
  const disposition = (readHeader(unfolded, "Content-Disposition") || "").toLowerCase();
  if (disposition.indexOf("attachment") === 0) return;

  const encoding = (readHeader(unfolded, "Content-Transfer-Encoding") || "")
    .toLowerCase()
    .trim();
  const charsetMatch = rawContentType.match(/charset\s*=\s*"?([^"';\s]+)"?/i);
  const charset = charsetMatch ? charsetMatch[1] : "UTF-8";

  let decoded;
  if (encoding === "quoted-printable") {
    decoded = decodeQuotedPrintable(body, charset);
  } else if (encoding === "base64") {
    decoded = decodeBase64Text(body, charset);
  } else {
    decoded = bytesToString(latin1Bytes(body), charset);
  }

  if (!decoded) return;
  if (mediaType === "text/html") collected.html.push(decoded);
  else collected.text.push(decoded);
}

/**
 * Converte HTML em texto aproximado, preservando o alvo dos links.
 *
 * @param {string} html O HTML.
 * @returns {string} Texto simples.
 */
function htmlToText(html) {
  if (!html) return "";
  return String(html)
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|tr|li|h[1-6])>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/[ \t]{2,}/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/**
 * Faz o parsing completo dos cabeçalhos de um .eml.
 *
 * Substitui parseEmailHeaders + parseEmailHeadersExtended, que duplicavam
 * regexes e rodavam ambos sobre o mesmo conteúdo a cada chamada.
 *
 * @param {string} rawContent Conteúdo bruto do .eml.
 * @returns {Object} Cabeçalhos normalizados.
 */
function parseEmailHeaders(rawContent) {
  const headerSection = String(rawContent || "").split(/\r?\n\r?\n/)[0] || "";
  const unfolded = unfoldHeaders(headerSection);

  const headers = {
    headerSection: headerSection,
    unfoldedHeaders: unfolded,
    subjectRaw: readHeader(unfolded, "Subject"),
    fromRaw: readHeader(unfolded, "From"),
    toRaw: readHeader(unfolded, "To"),
    ccRaw: readHeader(unfolded, "Cc"),
    replyToRaw: readHeader(unfolded, "Reply-To"),
    returnPathRaw: readHeader(unfolded, "Return-Path"),
    xOriginalFromRaw: readHeader(unfolded, "X-Original-From"),
    dateRaw: readHeader(unfolded, "Date"),
    messageId: null,
    userAgent: readHeader(unfolded, "User-Agent") || readHeader(unfolded, "X-Mailer"),
    contentType: readHeader(unfolded, "Content-Type"),
    listId: readHeader(unfolded, "List-ID") || readHeader(unfolded, "List-Id"),
    listUnsubscribe: readHeader(unfolded, "List-Unsubscribe"),
    xGoogleGroupId: readHeader(unfolded, "X-Google-Group-Id"),
    xForwardedEncrypted: readHeader(unfolded, "X-Forwarded-Encrypted"),
    precedence: readHeader(unfolded, "Precedence"),
  };

  const messageId = readHeader(unfolded, "Message-ID") || readHeader(unfolded, "Message-Id");
  headers.messageId = messageId ? messageId.replace(/^<|>$/g, "").trim() : null;

  // Campos derivados, já decodificados e normalizados.
  headers.subject = cleanSubject(headers.subjectRaw);
  headers.from = cleanEmailAddress(headers.fromRaw, "Remetente Desconhecido");
  headers.to = cleanEmailAddress(headers.toRaw, "Destinatário Desconhecido");
  headers.replyTo = headers.replyToRaw ? cleanEmailAddress(headers.replyToRaw) : null;
  headers.returnPath = headers.returnPathRaw
    ? cleanEmailAddress(headers.returnPathRaw)
    : null;
  headers.xOriginalFrom = headers.xOriginalFromRaw
    ? cleanEmailAddress(headers.xOriginalFromRaw)
    : null;
  headers.displayName = getDisplayName(headers.fromRaw);

  headers.date = headers.dateRaw ? parseEmailDate(headers.dateRaw) : null;

  headers.receivedHeaders = readAllHeaders(unfolded, "Received");
  headers.authenticationResults = parseAuthenticationResults(unfolded);
  headers.authenticationResultsRaw = readHeader(unfolded, "Authentication-Results");
  headers.arcResults = readAllHeaders(unfolded, "ARC-Authentication-Results");
  headers.dkimSignatures = parseDkimSignatures(unfolded);

  return headers;
}

/**
 * Interpreta um header Date RFC 5322 sem lançar exceção.
 *
 * @param {string} value O valor bruto.
 * @returns {Date|null} A data, ou null se não for interpretável.
 */
function parseEmailDate(value) {
  if (!value) return null;

  // Remove comentários entre parênteses, ex.: "+0000 (UTC)".
  const cleaned = String(value).replace(/\s*\([^)]*\)\s*$/, "").trim();

  let parsed = new Date(cleaned);
  if (isValidDate(parsed)) return parsed;

  parsed = new Date(String(value).trim());
  return isValidDate(parsed) ? parsed : null;
}

/**
 * Extrai spf/dkim/dmarc/compauth do Authentication-Results.
 *
 * Usa a PRIMEIRA ocorrência, que é a do receptor mais recente (o Gmail
 * prefixa a sua). Cabeçalhos forjados pelo atacante ficam abaixo e são
 * ignorados.
 *
 * @param {string} unfolded Bloco de cabeçalhos sem folding.
 * @returns {Object|null} Resultados de autenticação, ou null.
 */
function parseAuthenticationResults(unfolded) {
  const all = readAllHeaders(unfolded, "Authentication-Results");
  if (!all.length) return null;

  const primary = all[0];
  const readMethod = function (method) {
    const match = primary.match(new RegExp("\\b" + method + "=([a-z]+)", "i"));
    return match ? match[1].toLowerCase() : null;
  };

  return {
    authservId: (primary.match(/^([^;\s]+)/) || [])[1] || null,
    spf: readMethod("spf"),
    dkim: readMethod("dkim"),
    dmarc: readMethod("dmarc"),
    compauth: readMethod("compauth"),
    raw: primary,
  };
}

/**
 * Extrai as assinaturas DKIM presentes.
 *
 * @param {string} unfolded Bloco de cabeçalhos sem folding.
 * @returns {Array<Object>} Assinaturas com domínio (d), seletor (s) e hash (b).
 */
function parseDkimSignatures(unfolded) {
  return readAllHeaders(unfolded, "DKIM-Signature").map(function (block) {
    return {
      d: (block.match(/\bd=([^;\s]+)/i) || [])[1] || null,
      s: (block.match(/\bs=([^;\s]+)/i) || [])[1] || null,
      b: (block.match(/\bb=([^;\s]+)/i) || [])[1] || null,
      raw: truncateText(block, 500),
    };
  });
}

/**
 * Lista os anexos declarados no raw, com nome e tipo declarados.
 *
 * @param {string} rawContent Conteúdo bruto do .eml.
 * @returns {Array<{name: string, type: string}>} Anexos encontrados.
 */
function parseAttachments(rawContent) {
  const attachments = [];
  const seen = Object.create(null);
  if (!rawContent) return attachments;

  const unfolded = unfoldHeaders(rawContent);
  const pattern =
    /Content-Disposition:\s*(?:attachment|inline)[^\r\n]*?filename\*?=([^;\r\n]+)/gi;

  let match;
  while ((match = pattern.exec(unfolded))) {
    let filename = match[1].trim().replace(/^["']|["']$/g, "");

    // RFC 2231: filename*=UTF-8''nome%20com%20espaco
    const rfc2231 = filename.match(/^([\w-]+)'([\w-]*)'(.*)$/);
    if (rfc2231) {
      try {
        filename = decodeURIComponent(rfc2231[3]);
      } catch (err) {
        filename = rfc2231[3];
      }
    } else {
      filename = decodeMimeEncodedWords(filename);
    }

    filename = filename.trim();
    if (filename && !seen[filename]) {
      seen[filename] = true;
      attachments.push({ name: filename, type: "application/octet-stream" });
    }
  }
  return attachments;
}
