# Revisão de segurança — 18/11/2026

Escopo: branch codex/minimal-checker do whatsapp-check, baseada no fork art-hack. Revisão manual do caminho efetivamente empacotado: HTTP → sessão → WebSocket → Noise → USync; credenciais, pareamento e dependências. Nenhuma conta vinculada, consulta real ou deploy realizado.

## Achados corrigidos

- Alto: handshake aceitava certificado verificando somente issuerSerial. Agora verifica raiz pública fixa do WhatsApp, assinatura do intermediário e da folha, vínculo da chave estática, validade e encadeamento dos números de série. Falha interrompe a conexão antes do envio da identidade de cliente. Referências independentes: Baileys e whatsmeow abaixo.
- Alto: assinatura inválida era aceita pelo wrapper Signal. Corrigida no primeiro commit, mantida e testada nesta revisão. Acordo X25519 agora rejeita segredo inteiramente zero e não possui fallback indefinido.
- Alto: credenciais em texto claro no banco. Agora AES-256-GCM, nonce aleatório de 96 bits e AAD vinculada ao nome do registro. SESSION_KEY deve ser um segredo separado da base; registros legados em texto claro, adulteração e chave incorreta são rejeitados. Isso protege a base isolada, não um runtime comprometido com acesso à chave.
- Médio: operações assíncronas de criptografia e transição de handshake podiam processar dados fora de ordem. Mantidas filas de envio/recepção, await na transição e buffer de transporte até concluir a derivação. Contadores não podem dar a volta e reutilizar nonce.
- Médio: frames, fila de recepção, descompressão e árvore binária sem limites. Aplicados limites de memória, profundidade e número de nós; rejeitados atributos perigosos/duplicados, tamanhos inválidos e dados excedentes.
- Médio: pareamento aberto continuamente e estado me confundido com conta efetivamente vinculada. ENABLE_PAIRING desabilitado por padrão, chaves de administração e consumo distintas, identificação da conta pelo registro concluído. Etapa de conclusão por código extraída para handler específico sem carregar o recebimento de mensagens.
- Mantidas correções anteriores: destino restrito a web.whatsapp.com/ws/chat, sem redirects; remoção de endpoints públicos antigos, logs sensíveis, fallback de identidade em falhas de leitura e socket global. Nenhum endpoint expõe credenciais.
- Dependências fixadas nas versões instaladas com lockfile. npm audit de produção e desenvolvimento sem advisories conhecidos nesta execução. Isso não certifica código vendorizado nem ausência de vulnerabilidades desconhecidas.

## Evidências e limites

17 testes automatizados: assinatura real/falsa; cadeia sintética válida e inválida; raiz diferente, chave trocada, validade, issuer; X25519 de baixa ordem; AES-GCM e HKDF comparados ao Node; adulteração/troca de registro/chave incorreta/texto claro; bomba de descompressão e frame inválido; autenticação, contrato booleano e persistência.

Build wrangler dry-run e smoke no runtime local: 503 sem sessão, 403 com pareamento desabilitado e 401 quando chave de consumo tenta administrar. Inspeção do bundle confirma uma chamada externa fetch, no adaptador WebSocket com destino fixo. Referências a funções de download do legado não entram no bundle atual. Essa inspeção não equivale a captura de tráfego de uma sessão real.

O legado ainda apresenta erros de verificação estática TypeScript. Build e execução de testes passam, mas o projeto não tem typecheck integral limpo. Os testes de certificado usam raiz sintética; nenhum certificado real foi capturado nesta revisão. O pareamento por código e reconexão ainda exigem homologação real.

## Riscos residuais e decisão

Não foi encontrado envio deliberado para servidor do autor nos caminhos revisados. Isso não é prova absoluta de ausência de vazamento.

O número consultado é enviado ao WhatsApp/Meta por necessidade funcional. O Worker/Cloudflare processa esses dados e guarda sessão criptografada. Telefone em GET pode aparecer em logs do cliente, proxy, Access e ferramentas externas; observability está desabilitado no Worker, mas políticas externas precisam ser verificadas no destino de deploy.

Uma sessão vinculada não tem escopo restrito a consultas no WhatsApp. Roubo da sessão junto da chave, comprometimento do runtime ou dependência maliciosa pode comprometer a conta. Protocolo não oficial pode sofrer bloqueio, mudança ou incompatibilidade. Criptografia própria adaptada exige manutenção; esta revisão não é auditoria independente ou formal.

Recomendação: tecnicamente apto para um teste controlado com conta dedicada sem dados sensíveis, em ambiente privado, após configurar segredos e acesso de infraestrutura. Não liberar em produção nem vincular conta corporativa existente ainda. Primeiro teste deve comprovar pareamento, consulta positiva/negativa, reinício e revogação pelo celular, além de captura/observação do tráfego e logs no ambiente escolhido. Nenhuma conta foi vinculada nesta revisão.

## Fontes de comparação

- https://github.com/WhiskeySockets/Baileys/blob/master/src/Utils/noise-handler.ts
- https://github.com/WhiskeySockets/Baileys/blob/master/src/Defaults/index.ts
- https://github.com/tulir/whatsmeow/blob/main/handshake.go
