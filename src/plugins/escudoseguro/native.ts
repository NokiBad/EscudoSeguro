import { IpcMainInvokeEvent } from "electron";

const TIMEOUT = 6000;

// Evita que o plugin acesse rede local
function ehPrivado(host: string) {
    const h = host.toLowerCase();
    return (
        h === "localhost" ||
        h.endsWith(".local") ||
        h.endsWith(".internal") ||
        h === "::1" ||
        /^127\./.test(h) ||
        /^10\./.test(h) ||
        /^192\.168\./.test(h) ||
        /^169\.254\./.test(h) ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(h) ||
        h === "0.0.0.0"
    );
}

function urlSegura(valor: string): URL | null {
    try {
        const u = new URL(valor);
        if (u.protocol !== "http:" && u.protocol !== "https:") return null;
        if (ehPrivado(u.hostname)) return null;
        return u;
    } catch {
        return null;
    }
}

// Segue os redirecionamentos sem baixar a página
export async function resolverLink(_: IpcMainInvokeEvent, url: string) {
    let atual = urlSegura(url);
    if (!atual) return { erro: "URL inválida" };

    try {
        for (let i = 0; i < 6; i++) {
            const res = await fetch(atual.href, {
                method: "GET",
                redirect: "manual",
                signal: AbortSignal.timeout(TIMEOUT),
                headers: { "User-Agent": "Mozilla/5.0" }
            });
            res.body?.cancel().catch(() => { });

            const local = res.headers.get("location");
            if (res.status >= 300 && res.status < 400 && local) {
                const proxima = urlSegura(new URL(local, atual).href);
                if (!proxima) return { destino: atual.href };
                atual = proxima;
                continue;
            }
            return { destino: atual.href };
        }
        return { destino: atual.href };
    } catch (e: any) {
        return { erro: String(e?.message ?? e) };
    }
}

// Consulta se a URL já foi denunciada no URLhaus (abuse.ch)
export async function consultarUrlhaus(_: IpcMainInvokeEvent, url: string, chave: string) {
    if (!chave) return { erro: "sem chave" };

    try {
        const res = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
            method: "POST",
            headers: {
                "Auth-Key": chave,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({ url }).toString(),
            signal: AbortSignal.timeout(TIMEOUT)
        });
        if (!res.ok) return { erro: `HTTP ${res.status}` };

        const j: any = await res.json();
        if (j.query_status === "ok") {
            return {
                malicioso: true,
                status: j.url_status as string,
                ameaca: (j.threat ?? "") as string,
                tags: (j.tags ?? []) as string[]
            };
        }
        return { malicioso: false };
    } catch (e: any) {
        return { erro: String(e?.message ?? e) };
    }
}

// Pergunta ao RDAP quando o domínio foi registrado
export async function idadeDominio(_: IpcMainInvokeEvent, dominio: string) {
    try {
        const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(dominio)}`, {
            headers: { Accept: "application/rdap+json" },
            signal: AbortSignal.timeout(TIMEOUT)
        });
        if (!res.ok) return { erro: `HTTP ${res.status}` };

        const j: any = await res.json();
        const evento = (j.events ?? []).find((e: any) => e.eventAction === "registration");
        if (!evento?.eventDate) return { erro: "sem data de registro" };

        return { criadoEm: evento.eventDate as string };
    } catch (e: any) {
        return { erro: String(e?.message ?? e) };
    }
}