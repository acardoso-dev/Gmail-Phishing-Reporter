# Gmail Phishing Reporter

<img alt="Logo" src="logo.png" width="100" align="right">

Um Add-on para Gmail que permite aos usuários reportarem facilmente e-mails suspeitos para uma equipe de segurança designada com apenas um clique. Ao reportar um e-mail, ele é encaminhado como um anexo `.eml`, preservando todos os cabeçalhos originais para análise forense, além de gerar um relatório detalhado de Indicadores de Comprometimento (IoC) e análise via IA (Gemini).

<img alt="" src="assets\infografico.png">

Este add-on oferece duas ações principais:

- **Reportar Phishing**: Encaminha o e-mail para um endereço predefinido para análise de rotina. Ideal para tentativas comuns de phishing onde não houve interação do usuário.
- **Solicitar Investigação por IA**: Encaminha o e-mail para análise urgente e aciona uma análise automática por Inteligência Artificial (Gemini) para validar a ameaça. Use em casos onde o usuário pode ter interagido (clicado em link, baixado anexo).

## Recursos Principais

- **Reporte em Um Clique**: Interface simples integrada diretamente à barra lateral do Gmail.
- **Preservação de Cabeçalhos**: Encaminha o e-mail original como anexo `.eml`, garantindo que todos os dados técnicos estejam disponíveis.
- **Análise de IA (Gemini)**: Integração com **Google Gemini 1.5 Flash** para analisar o conteúdo e dar um veredito preliminar (apenas na opção "Solicitar Investigação").

  <img alt="" src="assets\reporte-ia.png">

- **Relatório de IoCs**: Extrai automaticamente IPs, domínios, URLs e verifica autenticações (SPF, DKIM, DMARC) gerando um JSON pronto para ingestão em SIEM.

  <img alt="" src="assets\reporte-ioc.png">

- **Score de Risco**: Calcula uma pontuação de risco (0-100) baseada em falhas de autenticação e incompatibilidades de domínio, com mitigação inteligente para listas de distribuição (Google Groups).

  <img alt="" src="assets\reporte-risco.png">

## Estrutura do Projeto

- `main.gs`: Lógica principal do add-on, criação da UI e processamento de e-mails.
- `gemini.gs`: Integração com a API do Google Gemini para análise de phishing.
- `config.gs`: Arquivo de configuração (e-mails de destino, prefixos). **Atualize antes de implantar.**
- `setup.gs`: Funções de validação e instalação.
- `appsscript.json`: Manifesto do projeto Apps Script.

## Instalação e Configuração

### Pré-requisitos

- Uma conta Google Workspace com permissão para criar scripts.
- Projeto Google Cloud Platform (GCP) associado (para APIs avançadas se necessário).
- **Chave de API do Gemini** (Google AI Studio).

### 1. Criar o Projeto Apps Script

1.  Acesse [script.google.com](https://script.google.com) e crie um novo projeto.
2.  Copie o código dos arquivos deste repositório (`main.gs`, `config.gs`, `gemini.gs`, `setup.gs`) para o seu projeto.
3.  Atualize o `appsscript.json` (View > Show manifest file) com o conteúdo do repositório.

### 2. Configurar o Add-on

Abra o arquivo `config.gs` e atualize as variáveis:

- `PHISHING_EMAIL`: E-mail para onde enviar os reportes padrão.
- `INVESTIGATION_EMAIL`: E-mail para onde enviar as solicitações de investigação.

### 3. Configurar a Chave de API do Gemini

Para que a análise de IA funcione:

1.  Obtenha uma chave em [Google AI Studio](https://aistudio.google.com/).
2.  No Apps Script, vá em **Configurações do Projeto** (ícone de engrenagem).
3.  Role até **Propriedades do Script**.
4.  Adicione uma propriedade:
    - **Propriedade**: `GEMINI_API_KEY`
    - **Valor**: `Sua-Chave-De-API-Aqui`

### 4. Ativar Serviços e Escopos

Verifique se o serviço **Gmail API** está ativado na aba "Serviços". Se necessário, adicione-o.

### 5. Implantar

1.  Clique em **Implantar** > **Nova implantação**.
2.  Tipo: **Add-on do Google Workspace**.
3.  Instale para sua conta ou domínio.

## Como Usar

1.  Abra qualquer e-mail no Gmail.
2.  Clique no ícone do **Gmail Phishing Reporter** na barra lateral direita.
3.  Você verá um resumo do remetente e análise de risco preliminar.
4.  Escolha uma ação:
    - **Reportar Phishing**: Para spam/phishing óbvio sem interação.
    - **Solicitar Investigação por IA**: Para análise aprofundada com feedback da IA.
5.  Após o envio, você pode clicar em **Mover para Spam** para limpar sua caixa de entrada.
