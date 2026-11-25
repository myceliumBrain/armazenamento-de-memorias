// Repositório onde o baú é salvo (mesmo esquema do Caderno).
export const CONFIG = {
  owner: "myceliumBrain",
  repo: "armazenamento-de-memorias",
  branch: "main",                    // site + data/auth.json + data/memorias.json
  branchArquivos: "arquivos",        // fotos e vídeos cifrados (fora do GitHub Pages)
  authPath: "data/auth.json",        // token do GitHub, cifrado (senha + código de recuperação)
  indicePath: "data/memorias.json",  // pastas e descrição de cada memória, cifrados
  tamanhoParte: 16 * 1024 * 1024,    // arquivos grandes são divididos em partes de 16 MB
};
