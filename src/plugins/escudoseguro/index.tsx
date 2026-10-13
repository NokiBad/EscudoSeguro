import { sendBotMessage } from "@api/Commands";
import { addMessagePreSendListener, removeMessagePreSendListener } from "@api/MessageEvents";
import { definePluginSettings } from "@api/Settings";
import definePlugin, { OptionType, PluginNative } from "@utils/types";
import { Alerts, Menu, MessageStore, UserStore } from "@webpack/common";

const Native = VencordNative.pluginHelpers.EscudoSeguro as PluginNative<typeof import("./native")>;

// ---------- Configurações ----------
const settings = definePluginSettings({
    verificarAoEnviar: {
        type: OptionType.BOOLEAN,
        description: "Verificar mensagens antes de enviar",
        default: true
    },
    verificarSensiveis: {
        type: OptionType.BOOLEAN,
        description: "Procurar dados sensíveis (tokens, chaves, CPF, cartão)",
        default: true
    },
    verificarLinks: {
        type: OptionType.BOOLEAN,
        description: "Analisar links",
        default: true
    },
    verificarAnexos: {
        type: OptionType.BOOLEAN,
        description: "Analisar anexos perigosos (.exe, .scr, .bat, .apk...)",
        default: true
    },
    recebidas: {
        type: OptionType.BOOLEAN,
        description: "Avisar automaticamente sobre mensagens recebidas",
        default: true
    },
    verificarEditadas: {
        type: OptionType.BOOLEAN,
        description: "Reanalisar mensagens recebidas quando forem editadas",
        default: true
    },
    desencurtar: {
        type: OptionType.BOOLEAN,
        description: "Seguir links encurtados (bit.ly etc.) para mostrar o destino real. O encurtador vê seu IP.",
        default: true
    },
    consultarIdade: {
        type: OptionType.BOOLEAN,
        description: "Consultar a idade do domínio (RDAP). Domínio muito novo é sinal de golpe.",
        default: true
    },
    consultarUrlhaus: {
        type: OptionType.BOOLEAN,
        description: "Consultar o URLhaus (abuse.ch). A URL é enviada a esse serviço.",
        default: true
    },
    urlhausChave: {
        type: OptionType.STRING,
        description: "Chave (Auth-Key) gratuita do URLhaus, criada em auth.abuse.ch",
        default: ""
    },
    riscoMinimo: {
        type: OptionType.SELECT,
        description: "Risco mínimo para avisar em mensagens recebidas",
        options: [
            { label: "Baixo ou mais", value: 1 },
            { label: "Médio ou mais", value: 3, default: true },
            { label: "Só alto", value: 5 }
        ]
    },
    dominiosConfiaveis: {
        type: OptionType.STRING,
        description: "Domínios confiáveis, separados por vírgula (links deles não geram aviso)",
        default: "github.com, google.com, youtube.com, wikipedia.org, wikimedia.org"
    }
});

// Guarda o que já foi avisado por mensagem, para não repetir
const avisados = new Map<string, Set<string>>();

// ---------- Tipos ----------
type Achado = { peso: number; texto: string; };

// ---------- Dados sensíveis ----------
const SENSIVEIS = [
    { nome: "Token do Discord", re: /[\w-]{24,26}\.[\w-]{6}\.[\w-]{27,38}/ },
    { nome: "Token do GitHub", re: /\bghp_[A-Za-z0-9]{36}\b/ },
    { nome: "Chave da AWS", re: /\bAKIA[0-9A-Z]{16}\b/ },
    { nome: "Chave de API do Google", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
    { nome: "Token do Slack", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
    { nome: "Chave de API (sk-...)", re: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
    { nome: "JWT", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
    { nome: "Chave privada", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
    { nome: "CPF", re: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/ },
    { nome: "Senha em texto", re: /\b(senha|password|passwd)\s*[:=]\s*\S+/i }
];

function luhn(num: string) {
    let soma = 0;
    let dobrar = false;
    for (let i = num.length - 1; i >= 0; i--) {
        let d = Number(num[i]);
        if (dobrar) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        soma += d;
        dobrar = !dobrar;
    }
    return soma % 10 === 0;
}

function mascarar(valor: string) {
    return valor.length <= 6 ? "***" : valor.slice(0, 4) + "…";
}

function acharSensiveis(texto: string): Achado[] {
    const achados: Achado[] = [];

    for (const s of SENSIVEIS) {
        const m = texto.match(s.re);
        if (m) achados.push({ peso: 5, texto: `🔑 ${s.nome} (${mascarar(m[0])})` });
    }

    for (const m of texto.matchAll(/\b(?:\d[ -]?){13,19}\b/g)) {
        const so = m[0].replace(/\D/g, "");
        if (so.length >= 13 && so.length <= 19 && luhn(so)) {
            achados.push({ peso: 5, texto: `💳 Possível número de cartão (${so.slice(0, 4)}…)` });
            break;
        }
    }

    return achados;
}

// ---------- Links ----------
const ENCURTADORES = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at"];
const TLDS_RUINS = [".zip", ".mov", ".tk", ".gq", ".ml", ".cf", ".xyz", ".top"];
const EXTENSOES_PERIGOSAS = /\.(exe|scr|bat|cmd|msi|apk|jar|vbs|ps1|lnk|hta)(\?|$)/i;

const MARCAS: Record<string, string[]> = {
    discord: ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"],
    steam: ["steampowered.com", "steamcommunity.com"],
    google: ["google.com"],
    github: ["github.com"],
    paypal: ["paypal.com"],
    nubank: ["nubank.com.br"],
    instagram: ["instagram.com"],
    facebook: ["facebook.com"],
    whatsapp: ["whatsapp.com"],
    roblox: ["roblox.com"],
    microsoft: ["microsoft.com"],
    amazon: ["amazon.com", "amazon.com.br"]
};

// Distância de edição, contando troca de letras vizinhas como 1 erro
function distancia(a: string, b: string) {
    const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
    for (let j = 1; j <= b.length; j++) dp[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
        for (let j = 1; j <= b.length; j++) {
            dp[i][j] = Math.min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
            );
            if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
                dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
            }
        }
    }
    return dp[a.length][b.length];
}

// Desfaz trocas comuns de letras: rn→m, vv→w, 0→o, 5→s, 1→l ou i
function variantes(rotulo: string) {
    const base = rotulo.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/5/g, "s");
    return [base.replace(/1/g, "l"), base.replace(/1/g, "i")];
}

function dominioCombina(host: string, dominio: string) {
    return host === dominio || host.endsWith("." + dominio);
}

function confiavel(host: string) {
    const lista = settings.store.dominiosConfiaveis
        .split(",")
        .map(d => d.trim().toLowerCase())
        .filter(Boolean);
    return lista.some(d => dominioCombina(host, d));
}

function ehExecutavel(caminho: string) {
    return EXTENSOES_PERIGOSAS.test(caminho);
}

function analisarLink(bruto: string): Achado[] {
    let url: URL;
    try { url = new URL(bruto); } catch { return [{ peso: 1, texto: "URL inválida" }]; }

    const host = url.hostname.toLowerCase();
    if (confiavel(host)) return [];

    const achados: Achado[] = [];
    const add = (peso: number, texto: string) => achados.push({ peso, texto });

    if (url.protocol === "http:") add(1, "Sem HTTPS");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add(3, "Usa IP em vez de domínio");
    if (url.username) add(3, "Tem usuário ou '@' na URL");
    if (ENCURTADORES.includes(host)) add(2, "Link encurtado: destino escondido");
    if (TLDS_RUINS.some(t => host.endsWith(t))) add(2, "Terminação muito usada em golpes");
    if (host.split(".").length > 4) add(1, "Subdomínios demais");
    if ((host.match(/-/g) ?? []).length >= 3) add(1, "Muitos hífens no domínio");
    if (host.length > 40) add(1, "Domínio muito longo");
    if (ehExecutavel(url.pathname)) add(3, "Aponta para um arquivo executável");
    if (/[?&][^=]+=https?(:|%3A)/i.test(url.search)) add(2, "Contém outra URL como parâmetro (possível redirecionamento)");

    // Letras disfarçadas no domínio (homóglifos)
    const hostBruto = bruto.match(/^https?:\/\/(?:[^@\/?#]*@)?([^\/?#:]+)/i)?.[1] ?? "";
    if (/[\u0370-\u03FF\u0400-\u04FF]/.test(hostBruto)) {
        add(5, "Domínio com letras cirílicas ou gregas que imitam letras latinas");
    } else if (/[^\x00-\x7F]/.test(hostBruto) || host.includes("xn--")) {
        add(3, "Domínio com caracteres especiais (punycode)");
    }

    // Imitação de marcas
    const partes = host.split(".");
    const rotulo = partes.length >= 2 ? partes[partes.length - 2] : host;
    const alternativas = variantes(rotulo);

    for (const [marca, oficiais] of Object.entries(MARCAS)) {
        if (oficiais.some(d => dominioCombina(host, d))) continue;

        if (host.includes(marca)) {
            add(4, `Parece imitar ${marca}, mas não é o domínio oficial`);
            break;
        }
        if (rotulo !== marca && alternativas.includes(marca)) {
            add(4, `Letras trocadas para imitar "${marca}" (rn→m, 0→o, 1→l...)`);
            break;
        }
        if (marca.length >= 5 && rotulo !== marca && distancia(rotulo, marca) === 1) {
            add(4, `Nome quase igual a "${marca}" (possível typosquatting)`);
            break;
        }
    }

    return achados;
}

// ---------- Links mascarados ----------
const MASCARADO = /\[([^\]]{1,200})\]\(\s*<?(https?:\/\/[^\s)>]+)>?(?:\s+"[^"]*")?\s*\)/gi;
const PARECE_DOMINIO = /^(https?:\/\/|www\.)\S+$|^[a-z0-9-]+(\.[a-z0-9-]+)*\.(com|net|org|gg|io|me|app|dev|co|br|xyz|gift|link|ru|info)(\/\S*)?$/i;

function hostDe(valor: string) {
    try {
        const v = /^https?:\/\//i.test(valor) ? valor : "https://" + valor;
        return new URL(v).hostname.toLowerCase().replace(/^www\./, "");
    } catch {
        return null;
    }
}

function analisarMascarados(texto: string): Achado[] {
    const achados: Achado[] = [];
    const vistos = new Set<string>();

    for (const m of texto.matchAll(MASCARADO)) {
        const mostrado = m[1].trim();
        const destino = m[2];
        const chave = mostrado + "|" + destino;
        if (vistos.has(chave)) continue;
        vistos.add(chave);

        const hostReal = hostDe(destino);
        if (!hostReal || confiavel(hostReal)) continue;

        const motivos: Achado[] = [];

        if (PARECE_DOMINIO.test(mostrado)) {
            const hostMostrado = hostDe(mostrado);
            if (hostMostrado && hostMostrado !== hostReal && !hostReal.endsWith("." + hostMostrado)) {
                motivos.push({ peso: 4, texto: `texto mostra ${hostMostrado}, mas leva a ${hostReal}` });
            }
        } else {
            motivos.push({ peso: 1, texto: `link mascarado, leva a ${hostReal}` });
        }

        motivos.push(...analisarLink(destino));
        if (!motivos.length) continue;

        const peso = motivos.reduce((s, x) => s + x.peso, 0);
        const rotulo = mostrado.slice(0, 40).replace(/`/g, "");
        achados.push({
            peso,
            texto: `🎭 \`${rotulo}\` → ${motivos.map(x => x.texto).join("; ")}`
        });
    }

    return achados;
}

function extrairUrls(texto: string): string[] {
    const urls: string[] = [];
    for (const m of texto.matchAll(MASCARADO)) urls.push(m[2]);
    for (const l of texto.replace(MASCARADO, " ").match(/https?:\/\/[^\s<>]+/gi) ?? []) {
        urls.push(l.replace(/[.,;!?)\]]+$/, ""));
    }
    return urls;
}

function extrairHosts(texto: string): string[] {
    return extrairUrls(texto).map(u => hostDe(u)).filter((h): h is string => !!h);
}

// ---------- Anexos ----------
const EXEC_ANEXO = /\.(exe|scr|bat|cmd|msi|apk|jar|vbs|ps1|lnk|hta|js)$/i;
const DUPLA_EXTENSAO = /\.(jpe?g|png|gif|pdf|docx?|xlsx?|txt|mp4|mp3)\.(exe|scr|bat|cmd|msi|apk|jar|vbs|ps1|lnk|hta|js)$/i;
const ARQUIVO_COMPACTADO = /\.(zip|rar|7z|iso)$/i;
const NOME_ISCA = /(nitro|comprovante|boleto|gift|free|gratis|grátis|premio|prêmio|fatura|pix|senha|crack|cheat|hack)/i;

function analisarAnexos(anexos: any[]): Achado[] {
    const achados: Achado[] = [];

    for (const a of anexos ?? []) {
        const nome: string = a.filename ?? a.name ?? "";
        if (!nome) continue;
        const exibido = nome.slice(0, 40).replace(/`/g, "");

        if (DUPLA_EXTENSAO.test(nome)) {
            achados.push({ peso: 6, texto: `📎 \`${exibido}\` → extensão dupla, finge ser outro tipo de arquivo` });
        } else if (EXEC_ANEXO.test(nome)) {
            achados.push({ peso: 4, texto: `📎 \`${exibido}\` → arquivo executável` });
        } else if (ARQUIVO_COMPACTADO.test(nome) && NOME_ISCA.test(nome)) {
            achados.push({ peso: 3, texto: `📎 \`${exibido}\` → arquivo compactado com nome de isca` });
        }
    }

    return achados;
}

function textoCompleto(message: any): string {
    const partes: string[] = [message.content ?? ""];
    for (const e of message.embeds ?? []) {
        partes.push(e.rawDescription ?? e.description ?? "");
        for (const f of e.fields ?? []) partes.push(f.rawValue ?? f.value ?? "");
    }
    return partes.join("\n");
}

// ---------- Consultas externas (native.ts) ----------
const cacheConsultas = new Map<string, Promise<Achado[]>>();

function curto(valor: string, n = 60) {
    return valor.slice(0, n).replace(/`/g, "") + (valor.length > n ? "…" : "");
}

function dominioRegistravel(host: string) {
    const p = host.split(".");
    if (p.length <= 2) return host;
    const sld = ["com", "net", "org", "gov", "edu"];
    const n = p[p.length - 1].length === 2 && sld.includes(p[p.length - 2]) ? 3 : 2;
    return p.slice(-n).join(".");
}

async function consultarUrl(original: string): Promise<Achado[]> {
    const achados: Achado[] = [];

    let host: string;
    try { host = new URL(original).hostname.toLowerCase(); } catch { return []; }
    if (confiavel(host)) return [];

    let alvo = original;

    // 1. Desencurtar
    if (settings.store.desencurtar && ENCURTADORES.includes(host)) {
        const r: any = await Native.resolverLink(original);
        if (r?.destino && r.destino !== original) {
            alvo = r.destino;
            achados.push({ peso: 0, texto: `↪️ \`${curto(original, 40)}\` leva a \`${curto(alvo, 70)}\`` });

            const motivos = analisarLink(alvo);
            if (motivos.length) {
                const peso = motivos.reduce((s, m) => s + m.peso, 0);
                achados.push({
                    peso,
                    texto: `⚠️ Destino final \`${curto(alvo, 40)}\` → ${motivos.map(m => m.texto).join("; ")}`
                });
            }
        }
    }

    let hostAlvo: string;
    try { hostAlvo = new URL(alvo).hostname.toLowerCase(); } catch { return achados; }
    if (confiavel(hostAlvo)) return achados;

    // 2. URLhaus
    if (settings.store.consultarUrlhaus && settings.store.urlhausChave) {
        const r: any = await Native.consultarUrlhaus(alvo, settings.store.urlhausChave);
        if (r?.malicioso) {
            const detalhe = [r.ameaca, ...(r.tags ?? [])].filter(Boolean).slice(0, 3).join(", ");
            const ativo = r.status === "online" ? "ainda ativa" : `status: ${r.status}`;
            achados.push({
                peso: 8,
                texto: `☠️ \`${curto(alvo, 40)}\` está na lista do URLhaus (${ativo}${detalhe ? "; " + detalhe : ""})`
            });
        }
    }

    // 3. Idade do domínio
    const ehIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostAlvo);
    if (settings.store.consultarIdade && !ehIp) {
        const dominio = dominioRegistravel(hostAlvo);
        const r: any = await Native.idadeDominio(dominio);
        if (r?.criadoEm) {
            const dias = Math.floor((Date.now() - new Date(r.criadoEm).getTime()) / 86400000);
            if (dias >= 0 && dias < 7) {
                achados.push({ peso: 4, texto: `🆕 \`${dominio}\` foi registrado há ${dias} dia(s)` });
            } else if (dias >= 7 && dias < 30) {
                achados.push({ peso: 2, texto: `🆕 \`${dominio}\` foi registrado há ${dias} dias` });
            }
        }
    }

    return achados;
}

function consultarComCache(url: string): Promise<Achado[]> {
    let p = cacheConsultas.get(url);
    if (!p) {
        p = consultarUrl(url).catch(e => {
            console.warn("[EscudoSeguro] consulta falhou:", e);
            return [];
        });
        cacheConsultas.set(url, p);
        if (cacheConsultas.size > 300) cacheConsultas.clear();
    }
    return p;
}

async function enriquecer(texto: string): Promise<Achado[]> {
    if (!settings.store.verificarLinks) return [];
    const urls = [...new Set(extrairUrls(texto))].slice(0, 3);
    const resultados = await Promise.all(urls.map(consultarComCache));
    return resultados.flat();
}

function comLimite<T>(promessa: Promise<T>, ms: number, padrao: T): Promise<T> {
    return Promise.race([promessa, new Promise<T>(res => setTimeout(() => res(padrao), ms))]);
}

// ---------- Relatório ----------
function nivelDe(achados: Achado[]) {
    const total = achados.reduce((s, a) => s + a.peso, 0);
    const nivel = total >= 5 ? "🔴 Alto" : total >= 3 ? "🟠 Médio" : "🟡 Baixo";
    return { total, nivel };
}

function relatorio(texto: string, anexos: any[] = []) {
    const achados: Achado[] = [];

    if (settings.store.verificarSensiveis) achados.push(...acharSensiveis(texto));

    if (settings.store.verificarLinks) {
        achados.push(...analisarMascarados(texto));

        const semMascarados = texto.replace(MASCARADO, " ");
        const links = semMascarados.match(/https?:\/\/[^\s<>]+/gi) ?? [];
        const vistos = new Set<string>();

        for (const bruto of links) {
            const link = bruto.replace(/[.,;!?)\]]+$/, "");
            if (vistos.has(link)) continue;
            vistos.add(link);

            const motivos = analisarLink(link);
            if (!motivos.length) continue;

            const peso = motivos.reduce((s, m) => s + m.peso, 0);
            achados.push({
                peso,
                texto: `⚠️ \`${link.slice(0, 50).replace(/`/g, "")}${link.length > 50 ? "…" : ""}\` → ${motivos.map(m => m.texto).join("; ")}`
            });
        }
    }

    if (settings.store.verificarAnexos) achados.push(...analisarAnexos(anexos));

    return { achados, ...nivelDe(achados) };
}

// Análise local + consultas externas
async function relatorioCompleto(texto: string, anexos: any[] = [], limiteMs = 7000) {
    const local = relatorio(texto, anexos);
    const extras = await comLimite(enriquecer(texto), limiteMs, [] as Achado[]);
    const achados = [...local.achados, ...extras];
    return { achados, ...nivelDe(achados) };
}

// ---------- Confirmação antes de enviar ----------
function confirmar(nivel: string, linhas: string[]): Promise<boolean> {
    return new Promise(resolve => {
        Alerts.show({
            title: `Verificar antes de enviar — risco ${nivel}`,
            body: (
                <div>
                    {linhas.map((l, i) => <div key={i} style={{ marginBottom: 6 }}>{l}</div>)}
                </div>
            ),
            confirmText: "Enviar mesmo assim",
            cancelText: "Cancelar",
            onConfirm: () => resolve(true),
            onCancel: () => resolve(false),
            onCloseCallback: () => resolve(false)
        });
    });
}

const aoEnviar = async (_canal: string, msg: { content: string; }) => {
    if (!settings.store.verificarAoEnviar) return;

    // Limite menor para não atrasar muito o envio
    const { achados, nivel } = await relatorioCompleto(msg.content, [], 4000);
    if (!achados.length) return;

    const ok = await confirmar(nivel, achados.map(a => a.texto));
    if (!ok) return { cancel: true };
};

// ---------- Confiar em domínio ----------
function confiarEm(host: string, canal: string) {
    const lista = settings.store.dominiosConfiaveis
        .split(",")
        .map(d => d.trim().toLowerCase())
        .filter(Boolean);

    if (!lista.includes(host)) {
        lista.push(host);
        settings.store.dominiosConfiaveis = lista.join(", ");
    }

    sendBotMessage(canal, { content: `✅ \`${host}\` adicionado aos domínios confiáveis.` });
}

// ---------- Mensagens recebidas e editadas ----------
async function analisarRecebida(message: any, editada: boolean) {
    try {
        if (!message?.id || !message.channel_id) return;
        if (message.author?.id === "1") return; // aviso local do próprio plugin

        // Em edições, o Discord manda só parte da mensagem: completa com o cache
        const guardada: any = editada ? MessageStore.getMessage(message.channel_id, message.id) : null;
        const completa: any = {
            ...guardada,
            ...message,
            content: message.content ?? guardada?.content,
            embeds: message.embeds ?? guardada?.embeds,
            attachments: message.attachments ?? guardada?.attachments,
            author: message.author ?? guardada?.author
        };

        if (!completa.author) return;
        if (completa.author.id === UserStore.getCurrentUser()?.id) return;

        const texto = textoCompleto(completa);
        const anexos = completa.attachments ?? [];
        if (!texto.trim() && !anexos.length) return;

        const { achados } = await relatorioCompleto(texto, anexos);
        if (!achados.length) return;

        // Só avisa o que ainda não foi avisado nesta mensagem
        const ja = avisados.get(completa.id) ?? new Set<string>();
        const novos = achados.filter(a => !ja.has(a.texto));
        if (!novos.length) return;

        for (const a of novos) ja.add(a.texto);
        avisados.set(completa.id, ja);
        if (avisados.size > 500) avisados.clear();

        const { total, nivel } = nivelDe(novos);
        if (total < Number(settings.store.riscoMinimo)) return;

        sendBotMessage(completa.channel_id, {
            content:
                `🛡️ **Mensagem de ${completa.author.username ?? "alguém"}${editada ? " (editada)" : ""}, risco ${nivel}**\n` +
                novos.map(a => a.texto).join("\n")
        });
    } catch (e) {
        console.warn("[EscudoSeguro] erro ao analisar mensagem:", e);
    }
}

export default definePlugin({
    name: "EscudoSeguro",
    description: "Avisa sobre dados sensíveis, links e anexos suspeitos ao enviar e ao receber, e consulta URLhaus, redirecionamentos e idade do domínio",
    authors: [{ name: "Noki", id: 0n }],
    settings,

    contextMenus: {
        message(children, { message }) {
            const texto = textoCompleto(message);
            const anexos = message.attachments ?? [];
            if (!texto.trim() && !anexos.length) return;

            children.push(
                <Menu.MenuItem
                    id="escudo-seguro"
                    label="Verificar segurança"
                    action={async () => {
                        const { achados, nivel } = await relatorioCompleto(texto, anexos);
                        sendBotMessage(message.channel_id, {
                            content: achados.length
                                ? `🛡️ **Risco ${nivel}**\n` + achados.map(a => a.texto).join("\n")
                                : "✅ Nada suspeito encontrado (isso não garante que seja seguro)."
                        });
                    }}
                />
            );

            const hosts = [...new Set(extrairHosts(texto))].filter(h => !confiavel(h)).slice(0, 3);
            for (const h of hosts) {
                children.push(
                    <Menu.MenuItem
                        id={`escudo-confiar-${h}`}
                        label={`Confiar em ${h}`}
                        action={() => confiarEm(h, message.channel_id)}
                    />
                );
            }
        }
    },

    flux: {
        MESSAGE_CREATE({ message, optimistic }: any) {
            if (optimistic || !settings.store.recebidas) return;
            analisarRecebida(message, false);
        },
        MESSAGE_UPDATE({ message }: any) {
            if (!settings.store.recebidas || !settings.store.verificarEditadas) return;
            analisarRecebida(message, true);
        }
    },

    start() {
        addMessagePreSendListener(aoEnviar);
    },
    stop() {
        removeMessagePreSendListener(aoEnviar);
    }
});