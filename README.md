# RAPE - Rusty AgentRouter Proxy Ehehehehehehehe

A small transparent HTTP proxy for using AgentRouter through a local OpenAI-compatible endpoint.

RAPE listens on `127.0.0.1:7187` by default and forwards requests to `https://agentrouter.org`. It passes through request methods, paths, bodies, headers, and the incoming `Authorization` header. Upstream response status, headers, errors, and streaming/SSE bodies are returned to the local client.

RAPE never reads or stores API keys. Configure the client using its normal request `Authorization` header.

## Run

```sh
nix run .
```

Pass a port as the first argument to override the default (default is 7187):

```sh
nix run . -- 8080
```

## Home Manager

Import `homeManagerModules.rape` and enable the service:

```nix
{
  services.rape = {
    enable = true;
    port = 8080;
  };
}
```

The module runs RAPE as a user `systemd` service and starts it at login.
