import {
  novaChaveMestra, criarFechadura, abrirFechadura, cifrar, decifrar,
  novoCodigoRecuperacao, normalizarCodigo, cifrarBytes, decifrarBytes,
} from "./cripto.js";
import { lerPublico, GitHub, ErroConflito, ErroAcesso } from "./armazenamento.js";
import { mesclarDados } from "./mesclar.js";
import { analisarArquivo } from "./midia.js";
import { Zip, LIMITE_ZIP } from "./zip.js";
import { CONFIG } from "./config.js";

// ---------------------------------------------------------------------------
// Estado
// ---------------------------------------------------------------------------
//
// branch main:
//   data/auth.json      → { fechaduras: [senha, recuperacao], token: {iv, dados} }
//   data/memorias.json  → { formato, versao, iv, dados }: pastas e memórias
//                         (nome, data, descrição, sha das partes), cifrados.
// branch arquivos:
//   arquivos/<id>/0.bin, 1.bin…  → conteúdo cifrado, em partes de 16 MB
//   arquivos/<id>/mini.bin       → miniatura JPEG cifrada

const estado = {
  auth: null,           // conteúdo de data/auth.json
  shaAuth: null,        // versão de data/auth.json no GitHub
  shaIndice: null,      // versão de data/memorias.json no GitHub (para detectar conflito)
  chave: null,          // chave mestra decifrada (só em memória)
  github: null,         // cliente da API com o token decifrado
  dados: null,          // índice decifrado: { pastas, itens, removidos }
  pendente: false,
  salvando: false,
  salvarDeNovo: false,
  erro: "",
  vista: "raiz",        // "raiz" | "todas" | "favoritas" | id de uma pasta
  busca: "",
  selecionados: new Set(),
  visiveis: [],         // ids na ordem da galeria (para o visualizador)
  abertoId: null,       // memória aberta no visualizador
  envios: [],           // fila de envio
};

const AUTOSALVAR_MS = 4000;
let timerAutosalvar = null;

const $ = (sel) => document.querySelector(sel);
const agora = () => new Date().toISOString();
const novoId = (prefixo) => `${prefixo}-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 7)}`;

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function hojeISO() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

function dataDe(iso) {
  const [a, m, d] = (iso || hojeISO()).split("-").map(Number);
  return new Date(a, (m || 1) - 1, d || 1);
}

const dataLonga = (iso) => dataDe(iso).toLocaleDateString("pt-BR", { day: "numeric", month: "long", year: "numeric" });
const mesAno = (iso) => dataDe(iso).toLocaleDateString("pt-BR", { month: "long", year: "numeric" });

function quando(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const hoje = new Date();
  if (d.toDateString() === hoje.toDateString()) return `hoje, ${d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" })}`;
  return d.toLocaleDateString("pt-BR", { day: "numeric", month: "short", year: d.getFullYear() === hoje.getFullYear() ? undefined : "numeric" });
}

function tamanhoLegivel(bytes) {
  if (!bytes) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / 1024 ** i).toLocaleString("pt-BR", { maximumFractionDigits: i >= 2 ? 1 : 0 })} ${u[i]}`;
}

function duracaoLegivel(s) {
  if (!s && s !== 0) return "";
  s = Math.round(s);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const seg = String(s % 60).padStart(2, "0");
  return h ? `${h}:${String(m).padStart(2, "0")}:${seg}` : `${m}:${seg}`;
}

function semAcento(s) {
  return String(s || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
}

function mostrarTela(id) {
  document.querySelectorAll(".tela").forEach((t) => { t.hidden = t.id !== id; });
}

function mostrarErro(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg || "";
  el.hidden = !msg;
}

async function ocupado(botao, fn) {
  const texto = botao.textContent;
  botao.disabled = true;
  botao.textContent = "Aguarde…";
  try { return await fn(); } finally { botao.disabled = false; botao.textContent = texto; }
}

let timerAviso = null;
function aviso(texto, ms = 0) {
  const el = $("#aviso");
  clearTimeout(timerAviso);
  el.textContent = texto || "";
  el.hidden = !texto;
  if (texto && ms) timerAviso = setTimeout(() => { el.hidden = true; }, ms);
}

function baixarArquivo(nome, conteudo, tipo) {
  const blob = conteudo instanceof Blob ? conteudo : new Blob([conteudo], { type: tipo });
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement("a"), { href: url, download: nome });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

// ---------------------------------------------------------------------------
// Índice: abrir e salvar
// ---------------------------------------------------------------------------

function dadosIniciais() {
  return { pastas: [], itens: [], removidos: {} };
}

// Grava data/auth.json (troca de senha, código ou token). Em conflito, a versão
// desta aba prevalece: ela acabou de ser confirmada por quem está usando.
async function gravarAuth(mensagem) {
  try {
    estado.shaAuth = await estado.github.gravar(CONFIG.authPath, estado.auth, estado.shaAuth, mensagem);
  } catch (e) {
    if (!(e instanceof ErroConflito)) throw e;
    const atual = await estado.github.ler(CONFIG.authPath);
    estado.shaAuth = await estado.github.gravar(CONFIG.authPath, estado.auth, atual?.sha, mensagem);
  }
}

async function gravarIndice(mensagem) {
  const arquivo = { formato: "memorias", versao: 1, ...(await cifrar(estado.chave, estado.dados)) };
  estado.shaIndice = await estado.github.gravar(CONFIG.indicePath, arquivo, estado.shaIndice, mensagem);
}

function marcarAlterado() {
  estado.pendente = true;
  estado.erro = "";
  atualizarStatus();
  clearTimeout(timerAutosalvar);
  timerAutosalvar = setTimeout(() => salvar(), AUTOSALVAR_MS);
}

async function salvar() {
  clearTimeout(timerAutosalvar);
  if (!estado.pendente) return;
  if (estado.salvando) { estado.salvarDeNovo = true; return; }
  estado.salvando = true;
  estado.pendente = false;
  atualizarStatus();
  try {
    try {
      await gravarIndice(`Memórias: índice ${agora()}`);
    } catch (e) {
      if (!(e instanceof ErroConflito)) throw e;
      // Outro aparelho salvou antes: junta as duas versões e tenta de novo.
      const remoto = await estado.github.ler(CONFIG.indicePath);
      if (remoto) {
        estado.dados = mesclarDados(estado.dados, await decifrar(estado.chave, remoto.json));
        estado.shaIndice = remoto.sha;
      }
      await gravarIndice(`Memórias: índice (mesclado) ${agora()}`);
      renderizarTudo();
    }
  } catch (e) {
    estado.pendente = true;
    estado.erro = (e.message || String(e)) + (e instanceof ErroAcesso ? " Cole um novo em ⚙ Configurações." : "");
    if (!(e instanceof ErroAcesso)) timerAutosalvar = setTimeout(() => salvar(), 30000);
  } finally {
    estado.salvando = false;
    atualizarStatus();
    if (estado.salvarDeNovo) { estado.salvarDeNovo = false; salvar(); }
  }
}

function atualizarStatus() {
  const el = $("#status");
  const botao = $("#salvar");
  el.className = "status";
  if (estado.erro) {
    el.textContent = `⚠ ${estado.erro}`;
    el.classList.add("erro");
  } else if (estado.salvando) {
    el.textContent = "Salvando…";
  } else if (estado.pendente) {
    el.textContent = "Alterações não salvas";
    el.classList.add("pendente");
  } else {
    el.textContent = "Tudo salvo";
    el.classList.add("ok");
  }
  botao.disabled = estado.salvando || !estado.pendente;
}

// Com a chave mestra em mãos: decifra o token e conecta ao GitHub.
async function conectar(chave) {
  estado.chave = chave;
  const { token } = await decifrar(chave, estado.auth.token);
  estado.github = new GitHub(token);
  const auth = await estado.github.ler(CONFIG.authPath);
  estado.shaAuth = auth?.sha ?? null;
}

// Busca o índice mais recente no GitHub e abre o aplicativo.
async function abrirBau() {
  const arquivo = await estado.github.ler(CONFIG.indicePath);
  if (arquivo) {
    estado.dados = await decifrar(estado.chave, arquivo.json);
    estado.shaIndice = arquivo.sha;
  } else {
    estado.dados = dadosIniciais();
    estado.shaIndice = null;
    estado.pendente = true;
  }
  estado.dados.pastas ||= [];
  estado.dados.itens ||= [];
  estado.dados.removidos ||= {};
  mostrarTela("app");
  renderizarTudo();
  atualizarStatus();
  if (estado.pendente) salvar();
}

// ---------------------------------------------------------------------------
// Telas de entrada
// ---------------------------------------------------------------------------

let acaoCodigo = null;

function mostrarCodigo(codigo, aoContinuar) {
  $("#codigo-valor").textContent = codigo;
  $("#codigo-ok").checked = false;
  $("#codigo-continuar").disabled = true;
  mostrarErro("erro-codigo", "");
  acaoCodigo = aoContinuar;
  mostrarTela("tela-codigo");
}

function irParaLogin(avisoLogin = "") {
  mostrarErro("erro-login", avisoLogin);
  mostrarTela("tela-login");
  $("#form-login").senha.focus();
}

function configurarTelasDeEntrada() {
  // Primeiro acesso: token + senha
  $("#form-config").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    mostrarErro("erro-config", "");
    await ocupado(form.querySelector("button[type=submit]"), async () => {
      try {
        const token = form.token.value.trim();
        const github = new GitHub(token);
        await github.validar();
        const existente = await github.ler(CONFIG.authPath);
        if (existente?.json?.fechaduras?.length) {
          // Já há acesso cadastrado (o site ainda não tinha atualizado): vai para a senha.
          estado.auth = existente.json;
          form.reset();
          return irParaLogin("Já existe um acesso cadastrado. Digite a senha.");
        }
        const chave = novaChaveMestra();
        const codigo = novoCodigoRecuperacao();
        const auth = {
          fechaduras: [
            await criarFechadura("senha", form.senha.value, chave),
            await criarFechadura("recuperacao", normalizarCodigo(codigo), chave),
          ],
          token: await cifrar(chave, { token }),
        };
        mostrarCodigo(codigo, async () => {
          estado.auth = auth;
          estado.chave = chave;
          estado.github = github;
          estado.shaAuth = await github.gravar(CONFIG.authPath, auth, existente?.sha, "Memórias: primeiro acesso");
          form.reset();
          await abrirBau();
        });
      } catch (err) {
        mostrarErro("erro-config", err.message);
      }
    });
  });

  // Código de recuperação
  $("#codigo-ok").addEventListener("change", (e) => { $("#codigo-continuar").disabled = !e.target.checked; });
  $("#codigo-copiar").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("#codigo-valor").textContent); $("#codigo-copiar").textContent = "Copiado ✓"; } catch {}
  });
  $("#codigo-baixar").addEventListener("click", () => {
    const texto = `Código de recuperação do Baú de memórias (gerado em ${new Date().toLocaleString("pt-BR")}):\n\n${$("#codigo-valor").textContent}\n\nUse em "Esqueci a senha" para definir uma nova senha.\n`;
    baixarArquivo("bau-memorias-codigo-recuperacao.txt", texto, "text/plain");
  });
  $("#codigo-continuar").addEventListener("click", async (e) => {
    mostrarErro("erro-codigo", "");
    await ocupado(e.target, async () => {
      try { await acaoCodigo(); } catch (err) { mostrarErro("erro-codigo", err.message); }
    });
  });

  // Login: só a senha
  $("#form-login").addEventListener("submit", async (e) => {
    e.preventDefault();
    mostrarErro("erro-login", "");
    const senha = e.target.senha.value;
    await ocupado(e.target.querySelector("button[type=submit]"), async () => {
      let chave = null;
      for (const f of estado.auth.fechaduras.filter((c) => c.tipo === "senha")) {
        try { chave = await abrirFechadura(f, senha); break; } catch { /* não é esta */ }
      }
      if (!chave) return mostrarErro("erro-login", "Senha incorreta.");
      try {
        await conectar(chave);
        await abrirBau();
        e.target.reset();
      } catch (err) {
        mostrarErro("erro-login", err.message);
      }
    });
  });
  $("#ir-recuperar").addEventListener("click", () => mostrarTela("tela-recuperar"));
  $("#voltar-login").addEventListener("click", () => mostrarTela("tela-login"));

  // Recuperação: código → nova senha
  $("#form-recuperar").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    mostrarErro("erro-recuperar", "");
    if (f.senha.value !== f.senha2.value) return mostrarErro("erro-recuperar", "As senhas não são iguais.");
    await ocupado(f.querySelector("button[type=submit]"), async () => {
      const fechadura = estado.auth.fechaduras.find((c) => c.tipo === "recuperacao");
      let chave;
      try {
        chave = await abrirFechadura(fechadura, normalizarCodigo(f.codigo.value));
      } catch {
        return mostrarErro("erro-recuperar", "Código de recuperação incorreto.");
      }
      try {
        const novaFechadura = await criarFechadura("senha", f.senha.value, chave);
        await conectar(chave);
        estado.auth.fechaduras = [...estado.auth.fechaduras.filter((c) => c.tipo !== "senha"), novaFechadura];
        await gravarAuth("Memórias: nova senha (recuperação)");
        f.reset();
        await abrirBau();
      } catch (err) {
        mostrarErro("erro-recuperar", err.message);
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Pastas e memórias (consultas)
// ---------------------------------------------------------------------------

const pastaPorId = (id) => (id ? estado.dados.pastas.find((p) => p.id === id) : null);
const itemPorId = (id) => estado.dados.itens.find((t) => t.id === id);
// Pasta-mãe/pasta efetiva: se a pasta sumiu (excluída em outro aparelho), vale a raiz.
const paiDe = (p) => (pastaPorId(p.paiId) ? p.paiId : null);
const pastaDoItem = (it) => (pastaPorId(it.pastaId) ? it.pastaId : null);
const ehPasta = (vista) => vista !== "raiz" && vista !== "todas" && vista !== "favoritas";

function subpastas(paiId) {
  return estado.dados.pastas
    .filter((p) => paiDe(p) === paiId)
    .sort((a, b) => a.nome.localeCompare(b.nome, "pt-BR", { numeric: true }));
}

function ancestrais(id) {
  const lista = [];
  const vistos = new Set();
  let p = pastaPorId(id);
  while (p && !vistos.has(p.id)) {
    vistos.add(p.id);
    lista.unshift(p);
    p = pastaPorId(p.paiId);
  }
  return lista;
}

function descendentes(id) {
  const ids = new Set([id]);
  for (let mudou = true; mudou;) {
    mudou = false;
    for (const p of estado.dados.pastas) {
      if (!ids.has(p.id) && ids.has(paiDe(p))) { ids.add(p.id); mudou = true; }
    }
  }
  return ids;
}

const caminhoTexto = (id) => ancestrais(id).map((p) => p.nome).join(" / ");

function itensEm(pastaId, recursivo = false) {
  if (!recursivo) return estado.dados.itens.filter((it) => pastaDoItem(it) === pastaId);
  if (pastaId === null) return [...estado.dados.itens];
  const ids = descendentes(pastaId);
  return estado.dados.itens.filter((it) => ids.has(pastaDoItem(it)));
}

// Pasta onde caem os envios e as pastas novas na vista atual.
const pastaDaVista = () => (ehPasta(estado.vista) ? estado.vista : null);

const ordemData = (a, b) => (b.data || "").localeCompare(a.data || "") || (b.criadoEm || "").localeCompare(a.criadoEm || "");

function itensDaVista() {
  let lista;
  if (estado.busca) {
    const q = semAcento(estado.busca);
    lista = estado.dados.itens.filter((it) =>
      semAcento(`${it.nome} ${it.descricao || ""} ${caminhoTexto(pastaDoItem(it))} ${dataLonga(it.data)}`).includes(q));
  } else if (estado.vista === "todas") {
    lista = estado.dados.itens;
  } else if (estado.vista === "favoritas") {
    lista = estado.dados.itens.filter((it) => it.favorito);
  } else {
    lista = itensEm(pastaDaVista());
  }
  return [...lista].sort(ordemData);
}

function pastasDaVista() {
  if (estado.busca) {
    const q = semAcento(estado.busca);
    return estado.dados.pastas.filter((p) => semAcento(p.nome).includes(q));
  }
  if (estado.vista === "raiz" || ehPasta(estado.vista)) return subpastas(pastaDaVista());
  return [];
}

function opcoesPastas(selecionada, excluir = new Set()) {
  const linhas = [`<option value="" ${!selecionada ? "selected" : ""}>🏠 Início</option>`];
  const percorrer = (pai, nivel) => {
    for (const p of subpastas(pai)) {
      if (excluir.has(p.id)) continue;
      linhas.push(`<option value="${esc(p.id)}" ${p.id === selecionada ? "selected" : ""}>${"   ".repeat(nivel)}📁 ${esc(p.nome)}</option>`);
      percorrer(p.id, nivel + 1);
    }
  };
  percorrer(null, 1);
  return linhas.join("");
}

// ---------------------------------------------------------------------------
// Miniaturas e arquivos (download + decifração)
// ---------------------------------------------------------------------------

const CACHE_MINI = "bau-miniaturas-v1";
const miniProntas = new Map();   // sha → objectURL
const miniPromessas = new Map(); // sha → Promise<objectURL>
const filaMini = [];
let miniAtivas = 0;

// As miniaturas cifradas ficam no cache do navegador (são imutáveis: o sha
// identifica o conteúdo), para a galeria abrir rápido da segunda vez.
async function lerCacheMini(sha) {
  try {
    const r = await (await caches.open(CACHE_MINI)).match(`./__mini/${sha}`);
    return r ? new Uint8Array(await r.arrayBuffer()) : null;
  } catch { return null; }
}

async function gravarCacheMini(sha, bytes) {
  try { await (await caches.open(CACHE_MINI)).put(`./__mini/${sha}`, new Response(bytes)); } catch {}
}

function carregarMini(sha) {
  if (miniPromessas.has(sha)) return miniPromessas.get(sha);
  const p = (async () => {
    let cifrada = await lerCacheMini(sha);
    if (!cifrada) {
      cifrada = await estado.github.lerBlob(sha);
      gravarCacheMini(sha, cifrada);
    }
    const url = URL.createObjectURL(new Blob([await decifrarBytes(estado.chave, cifrada)], { type: "image/jpeg" }));
    miniProntas.set(sha, url);
    return url;
  })();
  miniPromessas.set(sha, p);
  p.catch(() => miniPromessas.delete(sha));
  return p;
}

function bombearMini() {
  while (miniAtivas < 6 && filaMini.length) {
    const img = filaMini.shift();
    if (!img.isConnected) continue;
    const sha = img.dataset.mini;
    miniAtivas++;
    carregarMini(sha)
      .then((url) => document.querySelectorAll(`img[data-mini="${sha}"]`).forEach((i) => { i.src = url; }))
      .catch(() => img.closest(".ladrilho")?.classList.add("sem-mini"))
      .finally(() => { miniAtivas--; bombearMini(); });
  }
}

const observadorMini = new IntersectionObserver((entradas) => {
  for (const e of entradas) {
    if (!e.isIntersecting) continue;
    observadorMini.unobserve(e.target);
    filaMini.push(e.target);
  }
  bombearMini();
}, { rootMargin: "600px" });

// Conteúdo completo (lista de ArrayBuffer decifrados).
async function baixarPedacos(it, aoProgresso) {
  const total = it.partes.reduce((s, p) => s + p.tamanho, 0) || 1;
  let feito = 0;
  const pedacos = [];
  for (const parte of it.partes) {
    const cifrada = await estado.github.lerBlob(parte.sha, aoProgresso && ((n) => aoProgresso((feito + n) / total)));
    feito += parte.tamanho;
    pedacos.push(await decifrarBytes(estado.chave, cifrada));
  }
  return pedacos;
}

// Guarda os últimos arquivos abertos para navegar no visualizador sem baixar de novo.
const urlsArquivo = new Map(); // id → objectURL
async function urlDoArquivo(it, aoProgresso) {
  if (urlsArquivo.has(it.id)) {
    const url = urlsArquivo.get(it.id);
    urlsArquivo.delete(it.id);
    urlsArquivo.set(it.id, url);
    return url;
  }
  const blob = new Blob(await baixarPedacos(it, aoProgresso), { type: it.mime || "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  urlsArquivo.set(it.id, url);
  for (const [id, u] of urlsArquivo) {
    if (urlsArquivo.size <= 5) break;
    if (id === estado.abertoId || id === it.id) continue;
    URL.revokeObjectURL(u);
    urlsArquivo.delete(id);
  }
  return url;
}

async function baixarItem(it) {
  try {
    aviso(`Baixando “${it.nome}”…`);
    const url = await urlDoArquivo(it, (f) => aviso(`Baixando “${it.nome}”… ${Math.round(f * 100)}%`));
    const a = Object.assign(document.createElement("a"), { href: url, download: it.nome });
    document.body.appendChild(a);
    a.click();
    a.remove();
    aviso("");
  } catch (e) {
    aviso(`Não consegui baixar: ${e.message}`, 6000);
  }
}

async function baixarZip(nomeZip, entradas) {
  if (!entradas.length) return alert("Não há memórias aqui para baixar.");
  const total = entradas.reduce((s, e) => s + (e.it.tamanho || 0), 0);
  if (total > LIMITE_ZIP) return alert(`São ${tamanhoLegivel(total)}: passa do limite de 4 GB de um .zip. Baixe pasta por pasta.`);
  if (total > 500 * 1024 ** 2 && !confirm(`Vou baixar ${tamanhoLegivel(total)} e montar o .zip no navegador. Pode demorar e usar bastante memória. Continuar?`)) return;
  const zip = new Zip();
  try {
    for (const [i, { it, pasta }] of entradas.entries()) {
      aviso(`Preparando ${nomeZip}: ${i + 1} de ${entradas.length}…`);
      zip.adicionar(`${pasta}${it.nome}`, await baixarPedacos(it), dataDe(it.data));
    }
    baixarArquivo(nomeZip, zip.gerar());
    aviso(`${nomeZip} pronto.`, 4000);
  } catch (e) {
    aviso(`Não consegui montar o .zip: ${e.message}`, 8000);
  }
}

function nomeSeguro(s) {
  return String(s || "sem nome").replace(/[\\/:*?"<>|]+/g, "_").trim() || "sem nome";
}

function zipDaVista() {
  const base = pastaDaVista();
  const raizNomes = new Set(ancestrais(base).map((p) => p.id));
  const entradas = itensEm(base, true).sort(ordemData).map((it) => {
    const caminho = ancestrais(pastaDoItem(it)).filter((p) => !raizNomes.has(p.id)).map((p) => nomeSeguro(p.nome) + "/").join("");
    return { it, pasta: caminho };
  });
  const nome = base ? nomeSeguro(pastaPorId(base).nome) : "bau-de-memorias";
  baixarZip(`${nome}-${hojeISO()}.zip`, entradas);
}

// ---------------------------------------------------------------------------
// Envio de arquivos
// ---------------------------------------------------------------------------

const ICONES = { foto: "🖼️", video: "🎞️", arquivo: "📄" };
let processandoFila = false;

function enviarArquivos(lista) {
  const arquivos = [...lista].filter((f) => f && f.size >= 0);
  if (!arquivos.length || !estado.chave) return;
  const pastaId = pastaDaVista();
  for (const arquivo of arquivos) {
    estado.envios.push({ id: novoId("item"), arquivo, pastaId, favorito: estado.vista === "favoritas", situacao: "fila", progresso: 0, erro: "" });
  }
  renderizarEnvios();
  processarFila();
}

async function prepararEnvio(envio) {
  const { arquivo, id } = envio;
  envio.situacao = "preparando";
  renderizarEnvios();
  const info = await analisarArquivo(arquivo);
  envio.situacao = "enviando";
  const n = Math.max(1, Math.ceil(arquivo.size / CONFIG.tamanhoParte));
  const partes = [];
  const entradas = [];
  for (let i = 0; i < n; i++) {
    const bytes = new Uint8Array(await arquivo.slice(i * CONFIG.tamanhoParte, (i + 1) * CONFIG.tamanhoParte).arrayBuffer());
    const cifrada = await cifrarBytes(estado.chave, bytes);
    const sha = await estado.github.criarBlob(cifrada);
    partes.push({ sha, tamanho: cifrada.byteLength });
    entradas.push({ path: `arquivos/${id}/${i}.bin`, sha });
    envio.progresso = (i + 1) / n;
    renderizarEnvios();
  }
  let miniatura = null;
  if (info.miniatura) {
    const claro = new Uint8Array(await info.miniatura.arrayBuffer());
    const cifrada = await cifrarBytes(estado.chave, claro);
    const sha = await estado.github.criarBlob(cifrada);
    gravarCacheMini(sha, cifrada);
    miniProntas.set(sha, URL.createObjectURL(info.miniatura));
    miniPromessas.set(sha, Promise.resolve(miniProntas.get(sha)));
    miniatura = { sha };
    entradas.push({ path: `arquivos/${id}/mini.bin`, sha });
  }
  const t = agora();
  const item = {
    id, pastaId: envio.pastaId, tipo: info.tipo,
    nome: arquivo.name || `memoria-${hojeISO()}`, mime: arquivo.type || "application/octet-stream",
    tamanho: arquivo.size, largura: info.largura, altura: info.altura, duracao: info.duracao,
    data: info.data, descricao: "", favorito: envio.favorito,
    partes, miniatura, criadoEm: t, atualizadoEm: t,
  };
  return { envio, item, entradas };
}

// Envia em lotes: cada arquivo vira blobs; cada lote vira um commit no branch
// de arquivos e, em seguida, o índice é salvo com as novas memórias.
async function processarFila() {
  if (processandoFila) return;
  processandoFila = true;
  try {
    for (;;) {
      const lote = estado.envios.filter((e) => e.situacao === "fila").slice(0, 8);
      if (!lote.length) break;
      const prontos = [];
      let bytesLote = 0;
      for (const envio of lote) {
        try {
          prontos.push(await prepararEnvio(envio));
          envio.situacao = "gravando";
        } catch (e) {
          envio.situacao = "erro";
          envio.erro = e.message || String(e);
        }
        renderizarEnvios();
        bytesLote += envio.arquivo.size;
        if (bytesLote > 200 * 1024 ** 2) break; // lotes de no máximo ~200 MB
      }
      if (!prontos.length) continue;
      try {
        await estado.github.commitArquivos(prontos.flatMap((p) => p.entradas), `Memórias: ${prontos.length} arquivo(s)`);
        for (const p of prontos) {
          estado.dados.itens.push(p.item);
          p.envio.situacao = "pronto";
          p.envio.arquivo = null;
        }
        marcarAlterado();
        renderizarTudo();
        await salvar();
      } catch (e) {
        for (const p of prontos) { p.envio.situacao = "erro"; p.envio.erro = e.message || String(e); }
      }
      renderizarEnvios();
    }
  } finally {
    processandoFila = false;
    renderizarEnvios();
  }
}

function renderizarEnvios() {
  const painel = $("#envios");
  if (!estado.envios.length) { painel.hidden = true; return; }
  painel.hidden = false;
  const prontos = estado.envios.filter((e) => e.situacao === "pronto").length;
  const erros = estado.envios.filter((e) => e.situacao === "erro").length;
  const andamento = estado.envios.length - prontos - erros;
  $("#envios-resumo").textContent = andamento
    ? `Enviando ${prontos + erros + 1} de ${estado.envios.length}…`
    : `${prontos} enviado(s)${erros ? ` · ${erros} com erro` : ""}`;
  $("#envios-fechar").hidden = andamento > 0;
  const rotulo = {
    fila: "Na fila", preparando: "Preparando…", gravando: "Gravando…", pronto: "✓",
  };
  $("#envios-lista").innerHTML = estado.envios.map((e) => {
    const nome = e.arquivo?.name ?? e.nome ?? "";
    e.nome = nome;
    const situacao = e.situacao === "enviando" ? `${Math.round(e.progresso * 100)}%` : e.situacao === "erro" ? "Erro" : rotulo[e.situacao];
    return `
      <li class="envio ${e.situacao}" title="${esc(e.erro || nome)}">
        <span class="envio-nome">${esc(nome)}</span>
        <span class="envio-situacao">${esc(situacao)}</span>
        ${e.situacao === "enviando" ? `<span class="barra"><span style="width:${Math.round(e.progresso * 100)}%"></span></span>` : ""}
        ${e.situacao === "erro" ? `<span class="envio-erro">${esc(e.erro)} <button class="link" data-repetir="${esc(e.id)}">Tentar de novo</button></span>` : ""}
      </li>`;
  }).join("");
}

// ---------------------------------------------------------------------------
// Renderização
// ---------------------------------------------------------------------------

function renderizarTudo() {
  if (ehPasta(estado.vista) && !pastaPorId(estado.vista)) estado.vista = "raiz";
  for (const id of estado.selecionados) if (!itemPorId(id)) estado.selecionados.delete(id);
  renderizarLateral();
  renderizarGaleria();
}

function renderizarLateral() {
  const ativa = (v) => (!estado.busca && estado.vista === v ? "ativa" : "");
  const contar = (id) => itensEm(id, true).length;
  const item = (v, rotulo, n, nivel = 0) => `
    <button class="pasta ${ativa(v)}" data-vista="${esc(v)}" style="--nivel:${nivel}">
      <span>${rotulo}</span><span class="contagem">${n || ""}</span>
    </button>`;
  const arvore = (pai, nivel) => subpastas(pai).map((p) => item(p.id, `📁 ${esc(p.nome)}`, contar(p.id), nivel) + arvore(p.id, nivel + 1)).join("");
  const itens = estado.dados.itens;
  $("#navegacao").innerHTML =
    item("raiz", "🏠 Início", itensEm(null).length) +
    item("todas", "🕘 Todas as memórias", itens.length) +
    item("favoritas", "★ Favoritas", itens.filter((i) => i.favorito).length) +
    (estado.dados.pastas.length ? `<p class="rotulo-secao">Pastas</p>` : "") +
    arvore(null, 0);
  const total = itens.reduce((s, i) => s + (i.tamanho || 0), 0);
  $("#uso").textContent = `${itens.length} memória(s) · ${tamanhoLegivel(total)}`;
}

function renderizarMigalhas() {
  let html;
  if (estado.busca) html = `<span>Busca: “${esc(estado.busca)}”</span>`;
  else if (estado.vista === "todas") html = `<span>Todas as memórias</span>`;
  else if (estado.vista === "favoritas") html = `<span>Favoritas</span>`;
  else {
    const cadeia = ancestrais(pastaDaVista());
    html = `<button class="migalha" data-vista="raiz">Início</button>` +
      cadeia.map((p, i) => `<span class="sep">›</span>${i === cadeia.length - 1
        ? `<span>${esc(p.nome)}</span>`
        : `<button class="migalha" data-vista="${esc(p.id)}">${esc(p.nome)}</button>`}`).join("");
  }
  $("#migalhas").innerHTML = html;
}

function htmlLadrilho(it) {
  const sel = estado.selecionados.has(it.id);
  const mini = it.miniatura?.sha;
  const url = mini && miniProntas.get(mini);
  const proporcao = it.largura && it.altura ? `--proporcao:${(it.largura / it.altura).toFixed(3)}` : "";
  return `
    <div class="ladrilho ${sel ? "selecionado" : ""} ${mini ? "" : "sem-mini"}" data-item="${esc(it.id)}" tabindex="0" style="${proporcao}" title="${esc(it.nome)}">
      ${mini ? `<img alt="" data-mini="${esc(mini)}" ${url ? `src="${url}"` : ""} draggable="false">` : ""}
      <span class="tipo-icone">${ICONES[it.tipo] || ICONES.arquivo}<small>${esc(it.nome)}</small></span>
      ${it.tipo === "video" ? `<span class="selo">▶ ${esc(duracaoLegivel(it.duracao))}</span>` : ""}
      ${it.favorito ? `<span class="estrela">★</span>` : ""}
      <button class="marcar" data-marcar title="Selecionar" aria-pressed="${sel}">✓</button>
    </div>`;
}

function renderizarGaleria() {
  renderizarMigalhas();
  const naPasta = ehPasta(estado.vista) && !estado.busca;
  const navegavel = (estado.vista === "raiz" || ehPasta(estado.vista)) && !estado.busca;
  $("#menu-pasta").hidden = !naPasta;
  $("#nova-pasta").hidden = !navegavel;
  $("#baixar-zip").hidden = !navegavel;
  $("#baixar-zip").title = naPasta ? "Baixar esta pasta (.zip)" : "Baixar tudo (.zip)";

  const n = estado.selecionados.size;
  $("#barra-selecao").hidden = !n;
  $("#galeria-topo").hidden = !!n;
  $("#sel-contagem").textContent = `${n} selecionada(s)`;
  $("#galeria").classList.toggle("selecionando", n > 0);

  const pastas = pastasDaVista();
  const itens = itensDaVista();
  estado.visiveis = itens.map((i) => i.id);

  let html = "";
  if (pastas.length) {
    html += `<div class="subpastas">${pastas.map((p) => {
      const qtd = itensEm(p.id, true).length;
      const capa = itensEm(p.id, true).sort(ordemData).find((i) => i.miniatura)?.miniatura.sha;
      return `
        <button class="cartao-pasta" data-vista="${esc(p.id)}">
          <span class="capa">${capa ? `<img alt="" data-mini="${esc(capa)}" ${miniProntas.get(capa) ? `src="${miniProntas.get(capa)}"` : ""}>` : ""}<span>📁</span></span>
          <span class="cartao-pasta-texto"><strong>${esc(p.nome)}</strong><small>${estado.busca ? esc(caminhoTexto(paiDe(p)) || "Início") + " · " : ""}${qtd} memória(s)</small></span>
        </button>`;
    }).join("")}</div>`;
  }

  if (itens.length) {
    const grupos = [];
    for (const it of itens) {
      const chave = (it.data || "").slice(0, 7);
      if (grupos.at(-1)?.chave !== chave) grupos.push({ chave, rotulo: mesAno(it.data), itens: [] });
      grupos.at(-1).itens.push(it);
    }
    html += grupos.map((g) => `
      <section class="grupo">
        <h3 class="mes">${esc(g.rotulo)} <small>${g.itens.length}</small></h3>
        <div class="grade">${g.itens.map(htmlLadrilho).join("")}</div>
      </section>`).join("");
  } else if (!pastas.length) {
    html += estado.busca
      ? `<div class="vazio-grande"><p>Nada encontrado para “${esc(estado.busca)}”.</p></div>`
      : estado.vista === "favoritas"
        ? `<div class="vazio-grande"><p>★</p><p>Nenhuma favorita ainda. Abra uma memória e marque a estrela.</p></div>`
        : `<div class="vazio-grande soltavel"><p class="grande">📷</p><p><strong>Arraste fotos e vídeos para cá</strong></p><p class="suave">ou use o botão “⬆ Enviar”. Tudo é criptografado antes de sair do seu aparelho.</p></div>`;
  } else if (navegavel) {
    html += `<p class="suave dica">Nenhuma memória solta aqui. Arraste arquivos para esta janela para guardar nesta pasta.</p>`;
  }

  $("#conteudo").innerHTML = html;
  document.querySelectorAll("#conteudo img[data-mini]:not([src])").forEach((img) => observadorMini.observe(img));
}

// ---------------------------------------------------------------------------
// Visualizador
// ---------------------------------------------------------------------------

function abrirVisualizador(id) {
  estado.abertoId = id;
  const dlg = $("#visualizador");
  if (!dlg.open) dlg.showModal();
  renderizarVisualizador();
}

function navegar(delta) {
  const i = estado.visiveis.indexOf(estado.abertoId);
  const novo = estado.visiveis[i + delta];
  if (novo) { estado.abertoId = novo; renderizarVisualizador(); }
}

function tocarItem(it) {
  it.atualizadoEm = agora();
  marcarAlterado();
}

async function renderizarVisualizador() {
  const it = itemPorId(estado.abertoId);
  if (!it) { $("#visualizador").close(); return; }
  const i = estado.visiveis.indexOf(it.id);
  $("#vis-anterior").disabled = i <= 0;
  $("#vis-proxima").disabled = i < 0 || i >= estado.visiveis.length - 1;

  const info = $("#vis-info");
  const detalhes = [
    tamanhoLegivel(it.tamanho),
    it.largura && it.altura ? `${it.largura} × ${it.altura}` : "",
    it.duracao ? duracaoLegivel(it.duracao) : "",
    `enviado ${quando(it.criadoEm)}`,
  ].filter(Boolean).join(" · ");
  info.innerHTML = `
    <label>Nome<input id="vis-nome" value="${esc(it.nome)}"></label>
    <label>Data da memória<input id="vis-data" type="date" value="${esc(it.data || "")}"></label>
    <label>Descrição<textarea id="vis-descricao" rows="4" placeholder="Quem aparece, onde foi, por que importa…">${esc(it.descricao || "")}</textarea></label>
    <label>Pasta<select id="vis-pasta">${opcoesPastas(pastaDoItem(it))}</select></label>
    <p class="suave pequeno">${esc(detalhes)}</p>
    <div class="acoes">
      <button class="botao ${it.favorito ? "favorito" : ""}" id="vis-favorito">${it.favorito ? "★ Favorita" : "☆ Favoritar"}</button>
      <button class="botao" id="vis-baixar">⬇ Baixar</button>
      <button class="botao perigo" id="vis-excluir">Excluir</button>
    </div>
    <p class="suave pequeno">${i + 1} de ${estado.visiveis.length} · ← → para navegar</p>`;

  $("#vis-nome").addEventListener("input", (e) => { it.nome = e.target.value; tocarItem(it); });
  $("#vis-data").addEventListener("change", (e) => { if (e.target.value) { it.data = e.target.value; tocarItem(it); } });
  $("#vis-descricao").addEventListener("input", (e) => { it.descricao = e.target.value; tocarItem(it); });
  $("#vis-pasta").addEventListener("change", (e) => { it.pastaId = e.target.value || null; tocarItem(it); });
  $("#vis-favorito").addEventListener("click", (e) => {
    it.favorito = !it.favorito;
    tocarItem(it);
    e.target.textContent = it.favorito ? "★ Favorita" : "☆ Favoritar";
    e.target.classList.toggle("favorito", it.favorito);
  });
  $("#vis-baixar").addEventListener("click", () => baixarItem(it));
  $("#vis-excluir").addEventListener("click", () => {
    const proximo = estado.visiveis[i + 1] || estado.visiveis[i - 1];
    if (!excluirItens([it.id])) return;
    estado.visiveis = estado.visiveis.filter((x) => x !== it.id);
    if (proximo) { estado.abertoId = proximo; renderizarVisualizador(); } else $("#visualizador").close();
  });

  // Palco: miniatura enquanto o original é baixado e decifrado.
  const palco = $("#vis-palco");
  const mini = it.miniatura?.sha && miniProntas.get(it.miniatura.sha);
  if (it.tipo === "arquivo") {
    palco.innerHTML = `<div class="vis-arquivo"><p class="grande">📄</p><p>${esc(it.nome)}</p><button class="botao primario" id="vis-baixar2">⬇ Baixar</button></div>`;
    $("#vis-baixar2").addEventListener("click", () => baixarItem(it));
    return;
  }
  palco.innerHTML = `
    ${mini ? `<img class="vis-previa" src="${mini}" alt="">` : ""}
    <div class="vis-carregando"><span>Abrindo…</span><span class="barra"><span id="vis-progresso"></span></span></div>`;
  const meuId = it.id;
  try {
    const url = await urlDoArquivo(it, (f) => {
      const barra = $("#vis-progresso");
      if (barra && estado.abertoId === meuId) barra.style.width = `${Math.round(f * 100)}%`;
    });
    if (estado.abertoId !== meuId || !$("#visualizador").open) return;
    palco.innerHTML = it.tipo === "video"
      ? `<video src="${url}" controls autoplay playsinline></video>`
      : `<img src="${url}" alt="${esc(it.nome)}">`;
    const midia = palco.firstElementChild;
    midia.addEventListener("error", () => {
      if (estado.abertoId !== meuId) return;
      palco.innerHTML = `<div class="vis-arquivo"><p>O navegador não consegue exibir este formato (${esc(it.mime)}).</p><button class="botao primario" id="vis-baixar2">⬇ Baixar e abrir no aparelho</button></div>`;
      $("#vis-baixar2").addEventListener("click", () => baixarItem(it));
    });
  } catch (e) {
    if (estado.abertoId !== meuId) return;
    palco.innerHTML = `<div class="vis-arquivo"><p class="erro">Não consegui abrir: ${esc(e.message)}</p><button class="botao" id="vis-repetir">Tentar de novo</button></div>`;
    $("#vis-repetir").addEventListener("click", renderizarVisualizador);
  }
}

function configurarVisualizador() {
  const dlg = $("#visualizador");
  $("#vis-anterior").addEventListener("click", () => navegar(-1));
  $("#vis-proxima").addEventListener("click", () => navegar(1));
  $("#vis-fechar").addEventListener("click", () => dlg.close());
  dlg.addEventListener("close", () => {
    $("#vis-palco").innerHTML = "";
    estado.abertoId = null;
    renderizarTudo();
  });
  dlg.addEventListener("keydown", (e) => {
    if (e.target.matches("input, textarea, select")) return;
    if (e.key === "ArrowLeft") navegar(-1);
    if (e.key === "ArrowRight") navegar(1);
  });
  // Deslizar para os lados no celular.
  let x0 = null;
  $("#vis-palco").addEventListener("touchstart", (e) => { x0 = e.touches.length === 1 ? e.touches[0].clientX : null; }, { passive: true });
  $("#vis-palco").addEventListener("touchend", (e) => {
    if (x0 === null) return;
    const dx = e.changedTouches[0].clientX - x0;
    x0 = null;
    if (Math.abs(dx) > 60) navegar(dx < 0 ? 1 : -1);
  });
}

// ---------------------------------------------------------------------------
// Ações: pastas, mover, excluir
// ---------------------------------------------------------------------------

function irPara(vista) {
  estado.vista = vista;
  estado.busca = "";
  $("#busca").value = "";
  estado.selecionados.clear();
  renderizarTudo();
  $("#app").classList.remove("lateral-aberta");
  $("#galeria").scrollTop = 0;
}

function criarPasta(paiId) {
  const nome = prompt(paiId ? `Nova pasta dentro de “${pastaPorId(paiId).nome}”:` : "Nome da nova pasta:");
  if (!nome?.trim()) return;
  const t = agora();
  const p = { id: novoId("pasta"), nome: nome.trim(), paiId, criadoEm: t, atualizadoEm: t };
  estado.dados.pastas.push(p);
  marcarAlterado();
  irPara(p.id);
}

// Apaga os arquivos do branch (o histórico do git continua com eles, cifrados).
function apagarArquivos(itens) {
  const entradas = itens.flatMap((it) => [
    ...(it.partes || []).map((_, i) => ({ path: `arquivos/${it.id}/${i}.bin`, sha: null })),
    ...(it.miniatura ? [{ path: `arquivos/${it.id}/mini.bin`, sha: null }] : []),
  ]);
  if (entradas.length) estado.github.commitArquivos(entradas, `Memórias: ${itens.length} removida(s)`).catch(() => {});
}

function excluirItens(ids) {
  const itens = ids.map(itemPorId).filter(Boolean);
  if (!itens.length) return false;
  const texto = itens.length === 1 ? `Excluir “${itens[0].nome}”?` : `Excluir ${itens.length} memórias?`;
  if (!confirm(`${texto} Isso não pode ser desfeito pelo site.`)) return false;
  const t = agora();
  const remover = new Set(itens.map((i) => i.id));
  estado.dados.itens = estado.dados.itens.filter((i) => !remover.has(i.id));
  for (const id of remover) { estado.dados.removidos[id] = t; estado.selecionados.delete(id); }
  marcarAlterado();
  renderizarTudo();
  salvar().then(() => { if (!estado.pendente) apagarArquivos(itens); });
  return true;
}

function escolherPasta(titulo, selecionada, excluir) {
  return new Promise((ok) => {
    const dlg = $("#dialogo-mover");
    $("#mover-titulo").textContent = titulo;
    $("#mover-destino").innerHTML = opcoesPastas(selecionada, excluir);
    dlg.returnValue = "";
    dlg.addEventListener("close", () => ok(dlg.returnValue === "ok" ? ($("#mover-destino").value || null) : undefined), { once: true });
    dlg.showModal();
  });
}

function configurarApp() {
  // Navegação (lateral, migalhas e cartões de pasta)
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-vista]");
    if (b && b.closest("#app")) irPara(b.dataset.vista);
  });

  // Galeria: abrir, selecionar
  $("#conteudo").addEventListener("click", (e) => {
    const lad = e.target.closest(".ladrilho");
    if (!lad) return;
    const id = lad.dataset.item;
    if (e.target.closest("[data-marcar]") || estado.selecionados.size || e.ctrlKey || e.metaKey) {
      if (estado.selecionados.has(id)) estado.selecionados.delete(id); else estado.selecionados.add(id);
      renderizarGaleria();
      return;
    }
    abrirVisualizador(id);
  });
  $("#conteudo").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.classList.contains("ladrilho")) abrirVisualizador(e.target.dataset.item);
  });

  // Seleção
  $("#sel-cancelar").addEventListener("click", () => { estado.selecionados.clear(); renderizarGaleria(); });
  $("#sel-tudo").addEventListener("click", () => { estado.visiveis.forEach((id) => estado.selecionados.add(id)); renderizarGaleria(); });
  $("#sel-favoritar").addEventListener("click", () => {
    const itens = [...estado.selecionados].map(itemPorId).filter(Boolean);
    const valor = !itens.every((i) => i.favorito);
    itens.forEach((i) => { i.favorito = valor; i.atualizadoEm = agora(); });
    marcarAlterado();
    renderizarTudo();
  });
  $("#sel-mover").addEventListener("click", async () => {
    const destino = await escolherPasta(`Mover ${estado.selecionados.size} memória(s) para…`, pastaDaVista());
    if (destino === undefined) return;
    for (const id of estado.selecionados) {
      const it = itemPorId(id);
      if (it) { it.pastaId = destino; it.atualizadoEm = agora(); }
    }
    estado.selecionados.clear();
    marcarAlterado();
    renderizarTudo();
  });
  $("#sel-baixar").addEventListener("click", () => {
    const itens = [...estado.selecionados].map(itemPorId).filter(Boolean);
    if (itens.length === 1) return baixarItem(itens[0]);
    baixarZip(`memorias-${hojeISO()}.zip`, itens.map((it) => ({ it, pasta: "" })));
  });
  $("#sel-excluir").addEventListener("click", () => excluirItens([...estado.selecionados]));

  // Pastas
  $("#nova-pasta").addEventListener("click", () => criarPasta(pastaDaVista()));
  $("#nova-pasta-raiz").addEventListener("click", () => criarPasta(null));
  $("#renomear-pasta").addEventListener("click", () => {
    const p = pastaPorId(estado.vista);
    const nome = prompt("Novo nome da pasta:", p.nome);
    if (!nome?.trim()) return;
    p.nome = nome.trim();
    p.atualizadoEm = agora();
    marcarAlterado();
    renderizarTudo();
  });
  $("#mover-pasta").addEventListener("click", async () => {
    const p = pastaPorId(estado.vista);
    const destino = await escolherPasta(`Mover a pasta “${p.nome}” para…`, paiDe(p), descendentes(p.id));
    if (destino === undefined) return;
    p.paiId = destino;
    p.atualizadoEm = agora();
    marcarAlterado();
    renderizarTudo();
  });
  $("#excluir-pasta").addEventListener("click", () => {
    const p = pastaPorId(estado.vista);
    const ids = descendentes(p.id);
    const itens = itensEm(p.id, true);
    const subs = ids.size - 1;
    const partes = [itens.length && `${itens.length} memória(s)`, subs && `${subs} subpasta(s)`].filter(Boolean);
    if (!confirm(`Excluir a pasta “${p.nome}”${partes.length ? ` com ${partes.join(" e ")}` : ""}? Isso não pode ser desfeito pelo site.`)) return;
    const t = agora();
    estado.dados.pastas = estado.dados.pastas.filter((x) => !ids.has(x.id));
    estado.dados.itens = estado.dados.itens.filter((x) => !itens.includes(x));
    ids.forEach((id) => { estado.dados.removidos[id] = t; });
    itens.forEach((x) => { estado.dados.removidos[x.id] = t; });
    estado.vista = paiDe(p) ?? "raiz";
    marcarAlterado();
    renderizarTudo();
    salvar().then(() => { if (!estado.pendente) apagarArquivos(itens); });
  });
  $("#baixar-zip").addEventListener("click", zipDaVista);

  // Envio: botão, arrastar e soltar, colar
  $("#arquivo").addEventListener("change", (e) => { enviarArquivos(e.target.files); e.target.value = ""; });
  let arrastando = 0;
  const temArquivos = (e) => estado.chave && !$("#app").hidden && [...(e.dataTransfer?.types || [])].includes("Files");
  document.addEventListener("dragenter", (e) => {
    if (!temArquivos(e)) return;
    e.preventDefault();
    arrastando++;
    const p = pastaPorId(pastaDaVista());
    $("#soltar-destino").textContent = p ? `na pasta “${p.nome}”` : "em Início";
    $("#soltar").hidden = false;
  });
  document.addEventListener("dragover", (e) => { if (temArquivos(e)) e.preventDefault(); });
  document.addEventListener("dragleave", (e) => {
    if (!temArquivos(e)) return;
    arrastando = Math.max(0, arrastando - 1);
    if (!arrastando) $("#soltar").hidden = true;
  });
  document.addEventListener("drop", (e) => {
    if (!temArquivos(e)) return;
    e.preventDefault();
    arrastando = 0;
    $("#soltar").hidden = true;
    enviarArquivos(e.dataTransfer.files);
  });
  document.addEventListener("paste", (e) => {
    if (!estado.chave || $("#app").hidden || e.target.matches?.("input, textarea")) return;
    if (e.clipboardData?.files?.length) enviarArquivos(e.clipboardData.files);
  });
  $("#envios-fechar").addEventListener("click", () => {
    estado.envios = estado.envios.filter((e) => e.situacao !== "pronto" && e.situacao !== "erro");
    renderizarEnvios();
  });
  $("#envios-lista").addEventListener("click", (e) => {
    const b = e.target.closest("[data-repetir]");
    const envio = b && estado.envios.find((x) => x.id === b.dataset.repetir);
    if (!envio?.arquivo) return;
    envio.situacao = "fila";
    envio.erro = "";
    envio.progresso = 0;
    renderizarEnvios();
    processarFila();
  });

  // Busca
  let tBusca = null;
  $("#busca").addEventListener("input", (e) => {
    clearTimeout(tBusca);
    tBusca = setTimeout(() => {
      estado.busca = e.target.value.trim();
      estado.selecionados.clear();
      renderizarTudo();
    }, 200);
  });

  $("#salvar").addEventListener("click", () => salvar());
  $("#abrir-lateral").addEventListener("click", () => $("#app").classList.toggle("lateral-aberta"));
  // Toque no fundo escurecido (o ::after do #app) fecha a lateral no celular.
  $("#app").addEventListener("click", (e) => { if (e.target === e.currentTarget) e.currentTarget.classList.remove("lateral-aberta"); });

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s" && estado.chave) {
      e.preventDefault();
      salvar();
    }
    if (e.key === "Escape" && estado.selecionados.size && !document.querySelector("dialog[open]")) {
      estado.selecionados.clear();
      renderizarGaleria();
    }
  });

  window.addEventListener("beforeunload", (e) => {
    const enviando = estado.envios.some((x) => !["pronto", "erro"].includes(x.situacao));
    if (estado.pendente || estado.salvando || enviando) { e.preventDefault(); e.returnValue = ""; }
  });

  configurarVisualizador();
  configurarDialogoConfig();
}

// ---------------------------------------------------------------------------
// Configurações
// ---------------------------------------------------------------------------

function msgConfig(texto, erro = false) {
  const el = $("#msg-config");
  el.textContent = texto;
  el.className = `msg ${erro ? "erro" : "ok"}`;
  el.hidden = !texto;
}

function configurarDialogoConfig() {
  const dlg = $("#dialogo-config");

  $("#abrir-config").addEventListener("click", () => {
    const itens = estado.dados.itens;
    const total = itens.reduce((s, i) => s + (i.tamanho || 0), 0);
    const fotos = itens.filter((i) => i.tipo === "foto").length;
    const videos = itens.filter((i) => i.tipo === "video").length;
    $("#info-uso").textContent = `${fotos} foto(s), ${videos} vídeo(s), ${itens.length - fotos - videos} outro(s): ${tamanhoLegivel(total)}. ` +
      "O GitHub recomenda repositórios de até 1 GB e pede para ficar abaixo de 5 GB. Itens excluídos continuam ocupando espaço no histórico do git.";
    $("#info-repo").textContent = `Salvando em ${CONFIG.owner}/${CONFIG.repo} (índice no branch ${CONFIG.branch}, arquivos no branch ${CONFIG.branchArquivos}).`;
    msgConfig("");
    dlg.showModal();
  });

  $("#form-trocar-senha").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    if (f.senha.value !== f.senha2.value) return msgConfig("As senhas novas não são iguais.", true);
    await ocupado(f.querySelector("button"), async () => {
      let confere = false;
      for (const fe of estado.auth.fechaduras.filter((c) => c.tipo === "senha")) {
        try { await abrirFechadura(fe, f.atual.value); confere = true; break; } catch {}
      }
      if (!confere) return msgConfig("Senha atual incorreta.", true);
      try {
        const nova = await criarFechadura("senha", f.senha.value, estado.chave);
        estado.auth.fechaduras = [...estado.auth.fechaduras.filter((c) => c.tipo !== "senha"), nova];
        await gravarAuth("Memórias: troca de senha");
        f.reset();
        msgConfig("Senha trocada.");
      } catch (err) {
        msgConfig(`Não salvou: ${err.message}`, true);
      }
    });
  });

  $("#novo-codigo").addEventListener("click", async (e) => {
    if (!confirm("Gerar um novo código de recuperação? O código antigo deixará de funcionar.")) return;
    await ocupado(e.target, async () => {
      const codigo = novoCodigoRecuperacao();
      const fechadura = await criarFechadura("recuperacao", normalizarCodigo(codigo), estado.chave);
      dlg.close();
      mostrarCodigo(codigo, async () => {
        estado.auth.fechaduras = [...estado.auth.fechaduras.filter((c) => c.tipo !== "recuperacao"), fechadura];
        await gravarAuth("Memórias: novo código de recuperação");
        mostrarTela("app");
      });
    });
  });

  $("#form-token").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    await ocupado(f.querySelector("button"), async () => {
      try {
        const token = f.token.value.trim();
        const github = new GitHub(token);
        await github.validar();
        estado.github = github;
        estado.auth.token = await cifrar(estado.chave, { token });
        await gravarAuth("Memórias: token atualizado");
        f.reset();
        estado.erro = "";
        atualizarStatus();
        msgConfig("Token atualizado.");
        if (estado.pendente) salvar();
      } catch (err) {
        msgConfig(err.message, true);
      }
    });
  });

  $("#exportar").addEventListener("click", () => {
    baixarArquivo(`memorias-indice-${hojeISO()}.json`, JSON.stringify({ formato: "memorias-indice", exportadoEm: agora(), ...estado.dados }, null, 2), "application/json");
  });

  $("#importar").addEventListener("change", async (e) => {
    const arquivo = e.target.files[0];
    e.target.value = "";
    if (!arquivo) return;
    try {
      const b = JSON.parse(await arquivo.text());
      if (b.formato !== "memorias-indice" || !Array.isArray(b.pastas) || !Array.isArray(b.itens)) throw new Error("Este arquivo não é um índice do Baú de memórias.");
      if (!confirm(`Juntar o índice (${b.pastas.length} pastas, ${b.itens.length} memórias) ao atual? Em itens repetidos, vale a versão editada por último. As mídias precisam continuar no branch “${CONFIG.branchArquivos}”.`)) return;
      estado.dados = mesclarDados(estado.dados, { pastas: b.pastas, itens: b.itens, removidos: {} });
      marcarAlterado();
      renderizarTudo();
      msgConfig("Índice importado.");
    } catch (err) {
      msgConfig(err.message, true);
    }
  });

  $("#sair").addEventListener("click", async () => {
    if (estado.envios.some((x) => !["pronto", "erro"].includes(x.situacao)) && !confirm("Ainda há envios em andamento. Sair mesmo assim?")) return;
    if (estado.pendente) await salvar();
    if (estado.pendente && !confirm("Há alterações que não foram salvas. Sair mesmo assim?")) return;
    estado.pendente = false;
    estado.envios = [];
    location.reload();
  });
}

// ---------------------------------------------------------------------------
// Início: sem acesso cadastrado → primeiro acesso; com acesso → senha.
// ---------------------------------------------------------------------------

async function iniciar() {
  if (!window.crypto?.subtle) {
    document.body.innerHTML = `<p style="padding:2rem">Este site precisa de https:// ou localhost para funcionar (criptografia do navegador).</p>`;
    return;
  }
  $("#nome-repo").textContent = `${CONFIG.owner}/${CONFIG.repo}`;
  configurarTelasDeEntrada();
  configurarApp();
  try {
    estado.auth = await lerPublico(CONFIG.authPath);
  } catch (e) {
    mostrarTela("tela-config");
    mostrarErro("erro-config", e.message);
    return;
  }
  if (estado.auth?.fechaduras?.length) irParaLogin();
  else mostrarTela("tela-config");
}

iniciar();
