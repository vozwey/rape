# RAPE - Rusty AgentRouter Proxy Ehehehehehehehe

The primary goal of this project is to use AgentRouter without client-side restrictions, e.g. by using it from different clients and environments.

A small HTTP proxy for using AgentRouter through a local OpenAI-compatible endpoint.

RAPE listens on `127.0.0.1:7187` by default and forwards requests to `https://agentrouter.org`. It passes through request methods, paths, bodies, and most headers, including the incoming `Authorization` header.

RAPE slightly modifies outgoing requests before forwarding them to AgentRouter. In particular, it replaces the client's `User-Agent` with `opencode/0.11.0`, making AgentRouter treat the request as if it came from OpenCode. Hop-by-hop headers and `Content-Length` are also handled by the proxy as required for forwarding.

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
