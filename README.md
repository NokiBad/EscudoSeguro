# EscudoSeguro

Plugin experimental para Vencord que procura indícios de golpes e de exposição
de dados em mensagens do Discord. Ele combina verificações locais com consultas
opcionais a serviços externos. Os resultados são heurísticos: ausência de alerta
não comprova que uma mensagem ou link seja seguro.

## Recursos

- Detecta padrões que podem corresponder a tokens e chaves de API, chaves
  privadas, CPF, senhas em texto e números de cartão que passam pela validação
  de Luhn. Os valores encontrados são parcialmente mascarados no aviso.
- Analisa links HTTP(S), incluindo links mascarados, para apontar sinais como
  HTTP sem criptografia, endereços IP, encurtadores, extensões executáveis,
  domínios visualmente parecidos com marcas e caracteres de outros alfabetos.
- Examina nomes de anexos, sem baixar nem inspecionar o conteúdo dos arquivos,
  em busca de extensões executáveis, extensões duplas e arquivos compactados
  com nomes que parecem iscas.
- Pode verificar mensagens antes do envio, avisar sobre mensagens recebidas e
  editadas e oferecer a opção **Verificar segurança** no menu de contexto.
- Pode seguir redirecionamentos de links encurtados, consultar URLs no URLhaus
  e consultar a data de registro do domínio via RDAP.
- Permite manter uma lista de domínios confiáveis e escolher o risco mínimo
  para os avisos automáticos de mensagens recebidas.

## Arquivos e instalação

Este repositório contém os dois arquivos-fonte do plugin:

- `src/plugins/escudoseguro/index.tsx`: interface, configurações e análise das
  mensagens.
- `src/plugins/escudoseguro/native.ts`: consultas de rede executadas pelo
  processo nativo do Vencord.

Para testar em uma instalação própria, use um checkout de desenvolvimento do
Vencord compatível com as APIs importadas pelo plugin e copie a pasta
`src/plugins/escudoseguro` para o diretório `src/plugins/escudoseguro` desse
checkout. Em seguida, siga as instruções oficiais do Vencord para registrar,
compilar e carregar plugins locais. Este repositório não inclui o código do
Vencord, configuração de build ou instalador independente; a cópia dos arquivos,
por si só, não garante que o plugin será carregado. Não há garantia de
compatibilidade com versões específicas do Vencord.

## Configurações

As opções abaixo são definidas no código do plugin:

| Opção | Padrão | Efeito |
| --- | --- | --- |
| `verificarAoEnviar` | Ativada | Analisa o texto antes do envio e permite cancelar ou confirmar o envio quando há achados. |
| `verificarSensiveis` | Ativada | Procura os padrões de dados sensíveis descritos acima. |
| `verificarLinks` | Ativada | Ativa a análise local e o enriquecimento externo dos links. |
| `verificarAnexos` | Ativada | Verifica nomes de anexos por extensões e nomes suspeitos. |
| `recebidas` | Ativada | Analisa mensagens recebidas e publica avisos no canal quando atingem o risco mínimo. |
| `verificarEditadas` | Ativada | Reanalisa mensagens recebidas que foram editadas. |
| `desencurtar` | Ativada | Segue redirecionamentos de encurtadores conhecidos para identificar o destino. |
| `consultarIdade` | Ativada | Consulta no RDAP a data de registro do domínio. |
| `consultarUrlhaus` | Ativada | Consulta o URLhaus, desde que `urlhausChave` esteja preenchida. |
| `urlhausChave` | Vazia | Chave `Auth-Key` do URLhaus necessária para essa consulta. |
| `riscoMinimo` | Médio ou mais | Limite de risco dos avisos automáticos: baixo (1), médio (3) ou alto (5). |
| `dominiosConfiaveis` | `github.com, google.com, youtube.com, wikipedia.org, wikimedia.org` | Domínios separados por vírgula cujos links não geram análise/aviso. |

O nível exibido é calculado pela soma dos pesos dos achados: baixo abaixo de 3,
médio a partir de 3 e alto a partir de 5. O comportamento e a disponibilidade
das opções dependem das APIs fornecidas pelo Vencord.

## Rede e privacidade

- As verificações de padrões de texto, links e nomes de anexos são feitas no
  plugin. O código não envia o conteúdo completo das mensagens nem baixa os
  anexos como parte dessas verificações locais.
- Com `desencurtar` ativado, o plugin faz uma requisição GET para o encurtador
  conhecido, seguindo manualmente até seis redirecionamentos e cancelando o
  corpo da resposta. O serviço visitado pode receber o endereço IP da conexão.
- Com `consultarUrlhaus` ativado e uma chave configurada, a URL analisada é
  enviada por POST a `urlhaus-api.abuse.ch`, junto com a chave de autenticação.
- Com `consultarIdade` ativado, o domínio registrável é consultado em
  `rdap.org`. O domínio, portanto, é informado ao serviço RDAP.
- O código limita cada URL de consulta a 6 segundos, pode enriquecer no máximo
  três URLs distintas por texto e usa um limite de espera para concluir os
  relatórios. Consultas com falha podem resultar em ausência de achados
  externos, não em confirmação de segurança.
- `native.ts` rejeita alguns hosts locais e endereços privados ao resolver
  redirecionamentos. Essa checagem é uma proteção limitada do código, não uma
  garantia geral contra destinos de rede indesejados.

Antes de ativar consultas externas, considere quais dados de URL e domínio
serão compartilhados com os respectivos serviços. Revise também os termos e a
política de privacidade desses serviços.

## Limitações

As verificações são baseadas em padrões e regras simples e podem gerar falsos
positivos ou deixar passar ameaças. A checagem de anexos considera somente o
nome informado pelo Discord; não examina o arquivo. A detecção de domínio
registrável é aproximada e não substitui uma lista completa de sufixos
públicos. Domínios confiáveis ignoram as verificações de links e consultas
externas para o domínio correspondente. Use os avisos como auxílio, não como
garantia de segurança.
