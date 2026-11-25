// Análise dos arquivos antes do envio: tipo, dimensões, duração, data da
// memória (EXIF das fotos JPEG, ou a data de modificação do arquivo) e uma
// miniatura JPEG pequena para a galeria.

const LADO_MINIATURA = 400;

export function tipoDe(arquivo) {
  const mime = arquivo.type || "";
  if (mime.startsWith("image/")) return "foto";
  if (mime.startsWith("video/")) return "video";
  if (/\.(jpe?g|png|gif|webp|heic|heif|avif|bmp)$/i.test(arquivo.name)) return "foto";
  if (/\.(mp4|mov|m4v|webm|mkv|avi|3gp)$/i.test(arquivo.name)) return "video";
  return "arquivo";
}

function dataLocal(ms) {
  const d = new Date(ms || Date.now());
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

export async function analisarArquivo(arquivo) {
  const tipo = tipoDe(arquivo);
  const r = { tipo, largura: null, altura: null, duracao: null, data: dataLocal(arquivo.lastModified), miniatura: null };
  try {
    if (tipo === "foto") {
      const exif = await dataExif(arquivo).catch(() => null);
      if (exif) r.data = exif;
      Object.assign(r, await miniaturaImagem(arquivo));
    } else if (tipo === "video") {
      Object.assign(r, await miniaturaVideo(arquivo));
    }
  } catch { /* sem miniatura (ex.: HEIC fora do Safari) */ }
  return r;
}

function desenhar(fonte, largura, altura) {
  const escala = Math.min(1, LADO_MINIATURA / Math.max(largura, altura));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(largura * escala));
  canvas.height = Math.max(1, Math.round(altura * escala));
  canvas.getContext("2d").drawImage(fonte, 0, 0, canvas.width, canvas.height);
  return new Promise((ok) => canvas.toBlob(ok, "image/jpeg", 0.78));
}

async function carregarImagem(arquivo) {
  if (window.createImageBitmap) {
    try { return await createImageBitmap(arquivo, { imageOrientation: "from-image" }); } catch {}
  }
  return new Promise((ok, falha) => {
    const img = new Image();
    const url = URL.createObjectURL(arquivo);
    img.onload = () => { ok(img); setTimeout(() => URL.revokeObjectURL(url), 1000); };
    img.onerror = () => { URL.revokeObjectURL(url); falha(new Error("Imagem ilegível")); };
    img.src = url;
  });
}

async function miniaturaImagem(arquivo) {
  const fonte = await carregarImagem(arquivo);
  const largura = fonte.naturalWidth || fonte.width;
  const altura = fonte.naturalHeight || fonte.height;
  const miniatura = await desenhar(fonte, largura, altura);
  fonte.close?.();
  return { largura, altura, miniatura };
}

function miniaturaVideo(arquivo) {
  return new Promise((ok) => {
    const v = document.createElement("video");
    const url = URL.createObjectURL(arquivo);
    let terminou = false;
    const fim = (r) => {
      if (terminou) return;
      terminou = true;
      clearTimeout(limite);
      v.removeAttribute("src");
      v.load();
      URL.revokeObjectURL(url);
      ok(r);
    };
    const limite = setTimeout(() => fim({}), 15000);
    v.muted = true;
    v.playsInline = true;
    v.preload = "auto";
    v.onloadedmetadata = () => {
      const d = Number.isFinite(v.duration) ? v.duration : 0;
      v.currentTime = Math.max(0.1, Math.min(1, d / 10));
    };
    v.onseeked = async () => {
      const r = { duracao: Number.isFinite(v.duration) ? v.duration : null };
      if (v.videoWidth) {
        r.largura = v.videoWidth;
        r.altura = v.videoHeight;
        try { r.miniatura = await desenhar(v, v.videoWidth, v.videoHeight); } catch {}
      }
      fim(r);
    };
    v.onerror = () => fim({});
    v.src = url;
  });
}

// Data em que a foto foi tirada (DateTimeOriginal do EXIF), só para JPEG.
async function dataExif(arquivo) {
  if (!/jpe?g/i.test(arquivo.type) && !/\.jpe?g$/i.test(arquivo.name)) return null;
  const v = new DataView(await arquivo.slice(0, 256 * 1024).arrayBuffer());
  if (v.byteLength < 4 || v.getUint16(0) !== 0xffd8) return null;
  let p = 2;
  while (p + 10 < v.byteLength) {
    const marca = v.getUint16(p);
    if ((marca & 0xff00) !== 0xff00) break;
    const tamanho = v.getUint16(p + 2);
    if (marca === 0xffe1 && v.getUint32(p + 4) === 0x45786966) return lerTiff(v, p + 10);
    p += 2 + tamanho;
  }
  return null;
}

function lerTiff(v, base) {
  const le = v.getUint16(base) === 0x4949;
  const u16 = (o) => v.getUint16(base + o, le);
  const u32 = (o) => v.getUint32(base + o, le);
  const lerIfd = (off) => {
    const tags = {};
    const n = u16(off);
    for (let i = 0; i < n; i++) {
      const e = off + 2 + i * 12;
      tags[u16(e)] = { tipo: u16(e + 2), n: u32(e + 4), valor: e + 8 };
    }
    return tags;
  };
  const texto = (t) => {
    if (!t || t.tipo !== 2) return null;
    const off = t.n > 4 ? u32(t.valor) : t.valor;
    let s = "";
    for (let i = 0; i < t.n - 1; i++) s += String.fromCharCode(v.getUint8(base + off + i));
    return s;
  };
  const ifd0 = lerIfd(u32(4));
  let data = null;
  if (ifd0[0x8769]) {
    const exif = lerIfd(u32(ifd0[0x8769].valor));
    data = texto(exif[0x9003]) || texto(exif[0x9004]);
  }
  data ||= texto(ifd0[0x0132]);
  const m = data && data.match(/^(\d{4}):(\d{2}):(\d{2})/);
  return m && m[1] !== "0000" ? `${m[1]}-${m[2]}-${m[3]}` : null;
}
