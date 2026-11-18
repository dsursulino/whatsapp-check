# whatsapp-check

Serviço de uma única finalidade: consultar se um número tem WhatsApp.
Fork de [art-hack/whatsapp-cloudflare-workers](https://github.com/art-hack/whatsapp-cloudflare-workers), baseado em Baileys.

```http
GET /check?phone=5511999999999
Authorization: Bearer <API_KEY>
```

Resposta HTTP 200: `true` ou `false`, sem objeto envoltório. Número com DDI, apenas dígitos.
`400`: formato inválido. `401`: chave inválida. `429`: consulta em andamento.
`503`: sessão ausente, conexão indisponível ou resposta inconclusiva. Erros nunca viram `false`.

## Rodar

Node.js 22+ e npm. Cloudflare Worker + um Durable Object SQLite para manter uma conta e suas chaves.
Sem banco externo, R2, interface, envio de mensagens, filas ou consulta em lote.

```sh
npm ci --ignore-scripts
cp .dev.vars.example .dev.vars
# Preencha API_KEY e ADMIN_KEY com valores diferentes: openssl rand -hex 32
npm run dev
```

As duas chaves precisam ter pelo menos 32 caracteres. `.dev.vars` e `.wrangler` não são versionados.
Uma conexão de saída permanece ativa no Durable Object; ela não usa hibernação de WebSocket e pode gerar cobrança por duração.

## Vincular a conta uma vez

Uma conta autenticada é necessária. A consulta não envia mensagens ao número consultado.

```sh
curl -X POST 'http://localhost:8787/pair?phone=SEU_NUMERO_COM_DDI' \
  -H "Authorization: Bearer $ADMIN_KEY"
```

Digite o `code` retornado em WhatsApp → Aparelhos conectados → Conectar com número de telefone.
Não é necessário QR code. A conta fica vinculada até revogação/expiração; pode exigir nova vinculação.
Após confirmar, consulte `GET /session` com `ADMIN_KEY` até retornar `{"connected":true}`.
Então chame `/check` com `API_KEY`. As rotas administrativas não usam a chave dos consumidores.
Não exponha a chave administrativa aos projetos clientes.

## Validar e publicar

```sh
npm test
npm run build
npx wrangler secret put API_KEY
npx wrangler secret put ADMIN_KEY
# Configure uma rota privada/Access no wrangler.toml antes da publicação.
npm run deploy
```

`workers_dev = false`: sem endereço público automático. Nenhum deploy faz parte da preparação local.
Build e testes locais não comprovam consulta real: validar com conta vinculada, um número conhecido com WhatsApp e outro sem WhatsApp, e repetir após reiniciar o serviço.

## Correções neste fork

- Removidos os exemplos com senha fixa, listagem pública e interfaces de envio.
- Credenciais e chaves Signal persistidas no Durable Object; falhas de armazenamento não geram identidade nova.
- Corrigida a aceitação de assinaturas inválidas e removidos logs de credenciais/sessões.
- Conexão externa restrita a `web.whatsapp.com/ws/chat`, sem seguir redirecionamentos.
- Socket por instância e operações de criptografia ordenadas; removido encerramento global em 50 segundos.
- Protobuf vendorizado substituído por dependência atualizada e auditável pelo npm.
- Somente resposta explícita do protocolo produz booleano; retorno desconhecido gera erro.

Logs de aplicação não guardam telefone nem credenciais. Como o telefone está na URL do GET, configure também o proxy/Access para não registrar a query string.
O código de protocolo herdado não passou por auditoria criptográfica completa. O serviço ainda precisa da validação real descrita acima antes de produção.

A licença MIT original foi preservada. O libsignal vendorizado possui licença própria GPL-3.0; consulte seu diretório antes de redistribuir.

A verificação completa de tipos do legado apresenta erros herdados e não foi concluída; os testes executáveis e o build do Worker são os checks desta versão experimental.
