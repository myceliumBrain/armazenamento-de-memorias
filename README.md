# Baú de memórias: fotos e vídeos criptografados

Site estático (HTML + CSS + JavaScript, sem build) para guardar as recordações
que se perdem na internet (fotos, vídeos e outros arquivos) organizadas em
pastas. Funciona igual ao Caderno: o repositório é fixo em `js/config.js`
(`myceliumBrain/armazenamento-de-memorias`), o primeiro acesso pede só o
**token do GitHub e uma senha**, e depois disso o site pede só a senha.

Tudo é cifrado **no navegador, antes de sair do aparelho**. O repositório e o
site podem ser públicos: sem a senha (ou o código de recuperação), ninguém vê
nem os arquivos nem os nomes, datas e descrições.

## Onde fica cada coisa

| Branch      | Arquivo                       | Conteúdo                                                  |
|-------------|-------------------------------|-----------------------------------------------------------|
| `main`      | `data/auth.json`              | token do GitHub, cifrado (senha + código de recuperação)  |
| `main`      | `data/memorias.json`          | índice: pastas e memórias (nome, data, descrição…), cifrado |
| `arquivos`  | `arquivos/<id>/0.bin`, `1.bin`… | conteúdo cifrado de cada arquivo, em partes de 16 MB    |
| `arquivos`  | `arquivos/<id>/mini.bin`      | miniatura JPEG cifrada (para a galeria)                   |

As mídias ficam num branch separado (`arquivos`, criado sozinho no primeiro
envio) para não entrarem no GitHub Pages, que publica só o `main` e tem
limite de 1 GB.

## Como funciona

- **Pastas e subpastas** na barra lateral, como num drive. “Início” é a raiz;
  “Todas as memórias” mostra tudo numa linha do tempo; “Favoritas” junta as
  marcadas com ★.
- **Enviar**: botão “⬆ Enviar”, **arrastar arquivos para a janela** ou colar
  (Ctrl+V) uma imagem. Vai para a pasta aberta. Um painel mostra o progresso.
- **Galeria** agrupada por mês, com miniaturas no formato original da foto.
  A data vem do EXIF da foto (quando foi tirada) ou da data do arquivo, e
  pode ser corrigida.
- **Visualizador**: clique numa memória para ver em tamanho real ou assistir
  ao vídeo. ← → (ou deslizar no celular) navega. Ao lado: nome, data,
  descrição, pasta, favorita, baixar e excluir.
- **Seleção**: o círculo no canto da miniatura (ou Ctrl+clique) seleciona
  várias para mover, favoritar, baixar (.zip) ou excluir.
- **Baixar pasta**: ⬇ baixa a pasta aberta, com as subpastas, num `.zip`. Em
  “Início”, baixa o baú inteiro (até 4 GB por .zip).
- **Busca** por nome, descrição, pasta e data (ignora acentos).
- **Salvamento**: envios são gravados na hora; edições de nome, descrição etc.
  são salvas 4 s depois da última alteração (ou com Salvar / `Ctrl+S`).
- **Dois aparelhos ao mesmo tempo**: se o índice mudou em outro lugar, o site
  junta as versões (por item, vale a edição mais recente).

## Limites do GitHub (importante)

- O GitHub recomenda repositórios **de até 1 GB** e pede para ficar **abaixo
  de 5 GB**. Para alguns GB de fotos e vídeos curtos dá certo; para um acervo
  grande de vídeos, não é o lugar certo.
- **Excluir não libera espaço**: o arquivo sai do branch, mas continua (cifrado)
  no histórico do git.
- Arquivos grandes são divididos em partes de 16 MB, então não há limite por
  arquivo, mas vídeos longos demoram para enviar e para abrir (o vídeo é
  baixado inteiro antes de tocar).
- Fotos HEIC (iPhone) são guardadas normalmente, mas só o Safari mostra a
  miniatura e a imagem. Nos outros navegadores aparecem como arquivo para baixar.

## Segurança e recuperação

- Uma chave mestra aleatória cifra o token, o índice e cada arquivo (AES-GCM
  256). Essa chave fica guardada duas vezes em `data/auth.json`: uma trancada
  pela **senha** e outra pelo **código de recuperação** (PBKDF2-SHA256,
  600.000 iterações).
- O **código de recuperação** aparece uma única vez, na criação. Guarde-o fora
  do computador. Em “Esqueci a senha”, ele permite definir uma senha nova.
  Em Configurações dá para gerar outro código (o antigo deixa de valer).
- **Sem a senha e sem o código, não há como recuperar nada.** Nem eu,
  nem o GitHub conseguimos.
- O conteúdo cifrado é público, então use uma senha longa (uma frase).
- **Backup**: o ⬇ em “Início” gera um `.zip` com todas as fotos e vídeos,
  nas pastas. Em Configurações, “Exportar índice” gera um `.json` legível com
  nomes, datas e descrições. **Nenhum dos dois é criptografado.**
- As miniaturas ficam guardadas (cifradas) no cache do navegador para a
  galeria abrir rápido. Os originais só ficam na memória enquanto a aba está aberta.

## Publicar e usar

1. Crie o repositório `armazenamento-de-memorias` no GitHub (usuário
   `myceliumBrain`) e envie estes arquivos:
   ```bash
   git add . && git commit -m "Baú de memórias"
   git remote add origin git@github.com:myceliumBrain/armazenamento-de-memorias.git
   git push -u origin main
   ```
2. No repositório: Settings → Pages → Deploy from a branch → `main` / root.
3. Crie um token fine-grained em
   <https://github.com/settings/personal-access-tokens/new> com acesso
   **só a esse repositório** e permissão **Contents: Read and write**.
4. Abra o site, cole o token e escolha a senha. O site faz o commit de
   `data/auth.json` e `data/memorias.json` sozinho. Anote o código de
   recuperação.

Localmente, com `python3 serve.py` (http://localhost:8000), funciona igual:
lê e grava direto no GitHub. Rode `git pull` antes de mexer nos arquivos
locais, para não sobrescrever o que o site gravou.

Os tokens fine-grained expiram. Quando isso acontecer, o status mostra o erro.
Gere um token novo e cole em ⚙ Configurações → Token do GitHub.

Para usar outro repositório, mude `js/config.js`.

## Estrutura

```
index.html            telas (criação, código, login, recuperação, app, visualizador)
css/style.css         visual (claro/escuro automático, celular)
js/config.js          repositório (dono, nome, branches, caminhos, tamanho das partes)
js/app.js             interface: acesso, pastas, galeria, envios, visualizador, configurações
js/cripto.js          criptografia (senha, código de recuperação, índice, arquivos)
js/armazenamento.js   API do GitHub: data/*.json, blobs e commits no branch de arquivos
js/midia.js           miniaturas, dimensões, duração e data do EXIF
js/zip.js             gera .zip para baixar pastas
js/mesclar.js         junta versões do índice vindas de aparelhos diferentes
serve.py              servidor local
```

### Formato de `data/memorias.json` (depois de decifrado)

```json
{
  "pastas": [{ "id": "pasta-…", "nome": "Viagens", "paiId": null, "criadoEm": "…", "atualizadoEm": "…" }],
  "itens": [{
    "id": "item-…", "pastaId": "pasta-…", "tipo": "foto | video | arquivo",
    "nome": "praia.jpg", "mime": "image/jpeg", "tamanho": 2483921,
    "largura": 4032, "altura": 3024, "duracao": null,
    "data": "2015-07-21", "descricao": "Pôr do sol em Ubatuba", "favorito": true,
    "partes": [{ "sha": "…", "tamanho": 2483949 }],
    "miniatura": { "sha": "…" },
    "criadoEm": "…", "atualizadoEm": "…"
  }],
  "removidos": { "item-…": "data da exclusão" }
}
```

Cada `.bin` é `iv (12 bytes) + conteúdo cifrado (AES-GCM)`; o `sha` é o do
blob no git, então o site lê cada parte direto pelo sha.
# armazenamento-de-memorias
