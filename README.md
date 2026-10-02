# RAPE - Rusty AgentRouter Proxy Ehehehehehehehe

The primary goal of this project is to use AgentRouter without client-side restrictions, e.g. by using it from different clients and environments.

A small HTTP proxy for using AgentRouter through a local OpenAI-compatible endpoint.

RAPE listens on `127.0.0.1:7187` by default and forwards requests to `https://agentrouter.org`. It passes through request methods, paths, bodies, and most headers, including the incoming `Authorization` header.

RAPE slightly modifies outgoing requests before forwarding them to AgentRouter. It replaces the client's `User-Agent` with `opencode/0.11.0` and normalizes missing or null `required`/`properties` fields in tool schemas. Literal schema values and message contents are left alone. Hop-by-hop headers and `Content-Length` are handled as required for forwarding.

For Messages and Chat Completions, RAPE requests uncompressed responses and keeps a bounded, in-memory cache of original thinking/reasoning, including signatures. It restores blocks omitted by clients when the credentials, model, conversation history, and assistant message match. Responses still stream unchanged. The cache holds up to 256 messages and 64 MiB of serialized data, with an 8 MiB capture limit per response; it is lost on restart.

If AgentRouter explicitly rejects a request because thinking was not passed back and the cache cannot repair it, RAPE retries once with thinking disabled. It does not fabricate thinking or signatures, and unrelated errors are returned unchanged.

Upstream response status, headers, errors, and streaming/SSE bodies are returned to the local client.

RAPE does not log or store API keys. Configure the client using its normal request `Authorization` header.

## Run

```sh
nix run .
```

Pass a port as the first argument to override the default (which is `7187`):

```sh
nix run . -- 8080
```

## Home Manager

Import `homeModules.rape` and enable the service:

```nix
{
  services.rape = {
    enable = true;
    port = 8080;
  };
}
```

The module runs RAPE as a user `systemd` service and starts it at login.
