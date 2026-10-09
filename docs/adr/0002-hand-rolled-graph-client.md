# Hand-rolled Microsoft Graph client, not msgraph-sdk-go

The Entra side talks to Microsoft Graph through a small stdlib `net/http` client, in the same shape as the falcon-mcp and ninjaone-mcp clients. It does not use `msgraph-sdk-go`. Measured against a hand-rolled client, the SDK makes the binary 27.0 MB instead of 6.1 MB and the Nix compile 39 s instead of 4 s. It also needs a 226 MB vendor FOD and pulls 48 modules into the build list instead of 1. Most importantly, its kiota retry handler **replays POST, PATCH and PUT** on 429, 503 and 504. That breaks the house rule that writes are never auto-retried, and it is the same reason gofalcon was rejected in [falcon-mcp ADR 0001](https://github.com/lcleveland/falcon-mcp/blob/main/docs/adr/0001-hand-rolled-client-not-gofalcon.md). Beta would also need a separate v0.x module.

## Consequences

- The client owns everything the SDK would have done:
  - app-only token caching, with refresh before expiry and one re-fetch on a 401. The call is then re-sent once, writes included: the one exception to never retrying a write, safe because Graph rejects a 401 before it processes the call;
  - the certificate-assertion JWT (PS256, `x5t#S256`), built with the stdlib from a PEM key;
  - following `@odata.nextLink` verbatim;
  - re-sending `ConsistencyLevel: eventual` on every page;
  - waiting out `Retry-After`, for reads only.
- Request and response types are written per call, not generated. Only the properties the tools select are modelled.

Facts and measurements: [`docs/research/microsoft-graph.md`](../research/microsoft-graph.md) §8.
