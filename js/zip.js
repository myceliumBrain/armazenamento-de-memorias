// Gera um .zip sem compressão (fotos e vídeos já são comprimidos), para
// baixar uma pasta inteira de uma vez. Limite do formato: 4 GB e 65.535 arquivos.

const enc = new TextEncoder();

const TABELA = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(crc, bytes) {
  let c = crc ^ 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = TABELA[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function dataDos(d) {
  const ano = Math.max(1980, d.getFullYear());
  return {
    hora: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
    dia: ((ano - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

export const LIMITE_ZIP = 0xffffffff;

export class Zip {
  constructor() {
    this.partes = [];
    this.central = [];
    this.offset = 0;
    this.nomes = new Set();
  }

  unico(nome) {
    if (!this.nomes.has(nome)) { this.nomes.add(nome); return nome; }
    const ponto = nome.lastIndexOf(".");
    const [base, ext] = ponto > nome.lastIndexOf("/") ? [nome.slice(0, ponto), nome.slice(ponto)] : [nome, ""];
    for (let i = 2; ; i++) {
      const novo = `${base} (${i})${ext}`;
      if (!this.nomes.has(novo)) { this.nomes.add(novo); return novo; }
    }
  }

  // pedacos: lista de ArrayBuffer/Uint8Array com o conteúdo do arquivo.
  adicionar(nome, pedacos, data = new Date()) {
    const bytesNome = enc.encode(this.unico(nome));
    let crc = 0;
    let tamanho = 0;
    for (const p of pedacos) {
      const b = new Uint8Array(p);
      crc = crc32(crc, b);
      tamanho += b.byteLength;
    }
    if (this.offset + tamanho + 30 + bytesNome.length > LIMITE_ZIP) throw new Error("O .zip passaria de 4 GB. Baixe em partes menores.");
    const { hora, dia } = dataDos(data);

    const local = new DataView(new ArrayBuffer(30 + bytesNome.length));
    local.setUint32(0, 0x04034b50, true);
    local.setUint16(4, 20, true);
    local.setUint16(6, 0x0800, true); // nomes em UTF-8
    local.setUint16(8, 0, true);      // sem compressão
    local.setUint16(10, hora, true);
    local.setUint16(12, dia, true);
    local.setUint32(14, crc, true);
    local.setUint32(18, tamanho, true);
    local.setUint32(22, tamanho, true);
    local.setUint16(26, bytesNome.length, true);
    new Uint8Array(local.buffer).set(bytesNome, 30);

    const central = new DataView(new ArrayBuffer(46 + bytesNome.length));
    central.setUint32(0, 0x02014b50, true);
    central.setUint16(4, 20, true);
    central.setUint16(6, 20, true);
    central.setUint16(8, 0x0800, true);
    central.setUint16(10, 0, true);
    central.setUint16(12, hora, true);
    central.setUint16(14, dia, true);
    central.setUint32(16, crc, true);
    central.setUint32(20, tamanho, true);
    central.setUint32(24, tamanho, true);
    central.setUint16(28, bytesNome.length, true);
    central.setUint32(42, this.offset, true);
    new Uint8Array(central.buffer).set(bytesNome, 46);

    this.partes.push(local.buffer, new Blob(pedacos));
    this.central.push(central.buffer);
    this.offset += 30 + bytesNome.length + tamanho;
  }

  gerar() {
    const tamanhoCentral = this.central.reduce((s, c) => s + c.byteLength, 0);
    const fim = new DataView(new ArrayBuffer(22));
    fim.setUint32(0, 0x06054b50, true);
    fim.setUint16(8, this.central.length, true);
    fim.setUint16(10, this.central.length, true);
    fim.setUint32(12, tamanhoCentral, true);
    fim.setUint32(16, this.offset, true);
    return new Blob([...this.partes, ...this.central, fim.buffer], { type: "application/zip" });
  }
}
