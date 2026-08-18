{
  description = "RAPE - Rusty AgentRouter Proxy Extreme";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      eachSystem = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      rape = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "rape";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
      };
    in
    {
      packages = eachSystem (pkgs: { default = rape pkgs; });

      devShells = eachSystem (pkgs: {
        default = pkgs.mkShell { packages = with pkgs; [ cargo rustc ]; };
      });

      homeModules.default = { config, lib, pkgs, ... }:
        let cfg = config.services.rape;
        in
        {
          options.services.rape = {
            enable = lib.mkEnableOption "RAPE AgentRouter proxy";
            port = lib.mkOption {
              type = lib.types.port;
              default = 7187;
              description = "Port for the local RAPE proxy.";
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.user.services.rape = {
              Unit = {
                Description = "RAPE AgentRouter proxy";
                After = [ "network-online.target" ];
              };
              Service = {
                ExecStart = "${rape pkgs}/bin/rape ${toString cfg.port}";
                Restart = "on-failure";
              };
              Install.WantedBy = [ "default.target" ];
            };
          };
        };

      homeModules.rape = self.homeModules.default;
    };
}
