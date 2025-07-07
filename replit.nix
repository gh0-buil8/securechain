
{ pkgs }: {
  deps = [
    pkgs.openssl
    pkgs.pkg-config
    pkgs.rustc
    pkgs.cargo
    pkgs.rust-analyzer
  ];
}
