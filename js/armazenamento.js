// Leitura e gravação no GitHub.
//
// - data/*.json (branch main): pela API de conteúdo (um commit por gravação).
// - Fotos e vídeos (branch "arquivos"): pela API do git. Cada parte cifrada vira
//   um blob; um lote de envios vira um único commit. O índice guarda o sha de
//   cada blob, então a leitura é direta pelo sha.

import { paraB64, deB64 } from "./cripto.js";
import { CONFIG } from "./config.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

export class ErroConflito extends Error {}
export class ErroAcesso extends Error {}

const repo = () => `/repos/${CONFIG.owner}/${CONFIG.repo}`;
const urlConteudo = (caminho) => `${repo()}/contents/${caminho}`;
const esperar = (ms) => new Promise((ok) => setTimeout(ok, ms));

// Base64 de muitos megabytes: o FileReader é bem mais rápido que btoa.
function bytesParaB64(bytes) {
  return new Promise((ok, falha) => {
    const leitor = new FileReader();
    leitor.onload = () => ok(String(leitor.result).slice(String(leitor.result).indexOf(",") + 1));
    leitor.onerror = () => falha(leitor.error);
    leitor.readAsDataURL(new Blob([bytes]));
  });
}

// Lê um arquivo sem token (antes do login). Usa a API pública do GitHub, que
// já traz a versão mais nova (o GitHub Pages demora ~1 min para atualizar);
// se a API falhar (ex.: limite de 60 consultas/hora), usa o arquivo publicado
// junto com o site. null = o arquivo ainda não existe.
export async function lerPublico(caminho) {
  let r;
  try {
    r = await fetch(`https://api.github.com${urlConteudo(caminho)}?ref=${encodeURIComponent(CONFIG.branch)}`, {
      cache: "no-store",
      headers: { Accept: "application/vnd.github+json" },
    });
  } catch { r = null; }
  if (r?.status === 404) return null;
  if (r?.ok) {
    const meta = await r.json();
    return JSON.parse(dec.decode(deB64(meta.content.replace(/\s/g, ""))));
  }
  const local = await fetch(caminho, { cache: "no-store" });
  if (local.status === 404) return null;
  if (!local.ok) throw new Error(`Não consegui ler ${caminho} (HTTP ${local.status}).`);
  return local.json();
}

export class GitHub {
  constructor(token) {
    this.token = token;
  }

  // Requisição autenticada, com novas tentativas em falha de rede, erro 5xx
  // e limite de requisições (o GitHub limita criações seguidas de conteúdo).
  async api(caminho, opcoes = {}) {
    for (let tentativa = 0; ; tentativa++) {
      let r;
      try {
        r = await fetch(`https://api.github.com${caminho}`, {
          ...opcoes,
          cache: "no-store",
          headers: {
            Accept: "application/vnd.github+json",
            Authorization: `Bearer ${this.token}`,
            "X-GitHub-Api-Version": "2022-11-28",
            ...(opcoes.headers || {}),
          },
        });
      } catch (e) {
        if (tentativa >= 3) throw new Error("Sem conexão com o GitHub.");
        await esperar(2000 * 2 ** tentativa);
        continue;
      }
      if (r.status === 401) throw new ErroAcesso("O GitHub recusou o token (inválido, expirado ou revogado).");
      if ((r.status === 403 || r.status === 429) && tentativa < 3) {
        const espera = Number(r.headers.get("retry-after")) || 0;
        let limite = r.status === 429 || espera > 0 || r.headers.get("x-ratelimit-remaining") === "0";
        if (!limite) { try { limite = /rate limit/i.test(await r.clone().text()); } catch {} }
        if (limite) { await esperar((espera || 60) * 1000); continue; }
      }
      if (r.status >= 500 && tentativa < 3) { await esperar(2000 * 2 ** tentativa); continue; }
      return r;
    }
  }

  async json(caminho, opcoes, oQue) {
    const r = await this.api(caminho, opcoes);
    if (!r.ok) {
      let detalhe = "";
      try { detalhe = (await r.json()).message || ""; } catch {}
      const erro = new Error(`Erro do GitHub ao ${oQue} (HTTP ${r.status}) ${detalhe}`.trim());
      erro.status = r.status;
      throw erro;
    }
    return r.json();
  }

  // Confere se o token enxerga o repositório e pode gravar nele.
  async validar() {
    const r = await this.api(repo());
    if (r.status === 404) throw new Error(`O token não tem acesso ao repositório ${CONFIG.owner}/${CONFIG.repo}.`);
    if (!r.ok) throw new Error(`Erro do GitHub ao validar o token (HTTP ${r.status}).`);
    const info = await r.json();
    if (info.permissions && !info.permissions.push) {
      throw new Error("O token não tem permissão de escrita. Use “Contents: Read and write”.");
    }
  }

  // ---------- data/*.json ----------

  // Devolve { json, sha } ou null se o arquivo não existir.
  async ler(caminho) {
    const r = await this.api(`${urlConteudo(caminho)}?ref=${encodeURIComponent(CONFIG.branch)}`);
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`Erro do GitHub ao ler ${caminho} (HTTP ${r.status}).`);
    const meta = await r.json();
    let b64 = meta.content;
    if (!b64) {
      // Arquivos acima de 1 MB vêm sem conteúdo: busca pelo blob.
      b64 = (await this.json(`${repo()}/git/blobs/${meta.sha}`, {}, `ler ${caminho}`)).content;
    }
    return { json: JSON.parse(dec.decode(deB64(b64.replace(/\s/g, "")))), sha: meta.sha };
  }

  // Grava e devolve o novo sha. Lança ErroConflito se o arquivo mudou desde `sha`.
  async gravar(caminho, objeto, sha, mensagem) {
    const corpo = {
      message: mensagem,
      content: paraB64(enc.encode(JSON.stringify(objeto, null, 1) + "\n")),
      branch: CONFIG.branch,
    };
    if (sha) corpo.sha = sha;
    const r = await this.api(urlConteudo(caminho), { method: "PUT", body: JSON.stringify(corpo) });
    if (r.status === 409 || (r.status === 422 && !sha)) throw new ErroConflito(`${caminho} foi alterado em outro lugar.`);
    if (!r.ok) {
      let detalhe = "";
      try { detalhe = (await r.json()).message || ""; } catch {}
      throw new Error(`Erro do GitHub ao salvar (HTTP ${r.status}) ${detalhe}`.trim());
    }
    return (await r.json()).content.sha;
  }

  // ---------- Fotos e vídeos ----------

  // Envia bytes (já cifrados) e devolve o sha do blob.
  async criarBlob(bytes) {
    const content = await bytesParaB64(bytes);
    const r = await this.json(`${repo()}/git/blobs`, {
      method: "POST",
      body: JSON.stringify({ content, encoding: "base64" }),
    }, "enviar o arquivo");
    return r.sha;
  }

  // Baixa um blob pelo sha. aoProgresso(bytesRecebidos) é opcional.
  async lerBlob(sha, aoProgresso) {
    const r = await this.api(`${repo()}/git/blobs/${sha}`, { headers: { Accept: "application/vnd.github.raw+json" } });
    if (!r.ok) throw new Error(`Erro do GitHub ao baixar o arquivo (HTTP ${r.status}).`);
    if (!aoProgresso || !r.body) return new Uint8Array(await r.arrayBuffer());
    const leitor = r.body.getReader();
    const pedacos = [];
    let total = 0;
    for (;;) {
      const { done, value } = await leitor.read();
      if (done) break;
      pedacos.push(value);
      total += value.byteLength;
      aoProgresso(total);
    }
    const saida = new Uint8Array(total);
    let pos = 0;
    for (const p of pedacos) { saida.set(p, pos); pos += p.byteLength; }
    return saida;
  }

  // Um commit no branch de arquivos. entradas: [{ path, sha }] (sha null = apagar).
  // Cria o branch (sem histórico em comum com o site) se ele ainda não existir.
  async commitArquivos(entradas, mensagem) {
    const branch = CONFIG.branchArquivos;
    const arvore = entradas.map((e) => ({ path: e.path, mode: "100644", type: "blob", sha: e.sha }));
    for (let tentativa = 0; tentativa < 5; tentativa++) {
      const rRef = await this.api(`${repo()}/git/ref/heads/${branch}`);
      if (rRef.status === 404) {
        const novos = arvore.filter((e) => e.sha);
        if (!novos.length) return;
        const tree = await this.json(`${repo()}/git/trees`, { method: "POST", body: JSON.stringify({ tree: novos }) }, "montar o commit");
        const commit = await this.json(`${repo()}/git/commits`, {
          method: "POST", body: JSON.stringify({ message: mensagem, tree: tree.sha, parents: [] }),
        }, "criar o commit");
        const r = await this.api(`${repo()}/git/refs`, {
          method: "POST", body: JSON.stringify({ ref: `refs/heads/${branch}`, sha: commit.sha }),
        });
        if (r.ok) return;
        if (r.status === 422) continue; // outro aparelho criou o branch ao mesmo tempo
        throw new Error(`Erro do GitHub ao criar o branch ${branch} (HTTP ${r.status}).`);
      }
      if (!rRef.ok) throw new Error(`Erro do GitHub ao ler o branch ${branch} (HTTP ${rRef.status}).`);
      const cabeca = (await rRef.json()).object.sha;
      const atual = await this.json(`${repo()}/git/commits/${cabeca}`, {}, "ler o último commit");
      const tree = await this.json(`${repo()}/git/trees`, {
        method: "POST", body: JSON.stringify({ base_tree: atual.tree.sha, tree: arvore }),
      }, "montar o commit");
      const commit = await this.json(`${repo()}/git/commits`, {
        method: "POST", body: JSON.stringify({ message: mensagem, tree: tree.sha, parents: [cabeca] }),
      }, "criar o commit");
      const r = await this.api(`${repo()}/git/refs/heads/${branch}`, {
        method: "PATCH", body: JSON.stringify({ sha: commit.sha, force: false }),
      });
      if (r.ok) return;
      if (r.status === 422 || r.status === 409) { await esperar(500 + Math.random() * 1500); continue; } // alguém gravou antes
      throw new Error(`Erro do GitHub ao gravar os arquivos (HTTP ${r.status}).`);
    }
    throw new Error("Não consegui gravar os arquivos: o branch mudou várias vezes seguidas. Tente de novo.");
  }
}
