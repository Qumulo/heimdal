{
  description = "Qumulo's Heimdal, built against wolfSSL's OpenSSL compatibility layer";

  # Qumulo's nixpkgs, at the revision the Qumulo product tree pins.
  inputs.nixpkgs.url = "github:Qumulo/nixpkgs/222832122e424889b3a9a6dac2fd10a188c99698";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        # The product builds this against its FIPS wolfSSL; open-source wolfSSL, configured the
        # same way outside the FIPS module, has the same compatibility layer.
        # Open-source wolfSSL configured toward the product's FIPS build, so the compatibility
        # layer heimdal compiles against matches the shipped one.
        wolfssl = pkgs.wolfssl.overrideAttrs (old: {
          # nixpkgs' own flags keep --enable-reproducible-build, without which the library
          # records its dev output's path.
          configureFlags =
            builtins.filter (f: f != "--enable-pkcs11") old.configureFlags
            ++ [
              "--enable-des3"
              "--disable-camellia"
              "--disable-pkcs11"
              # Off in the FIPS build, which --enable-all leaves on here. curve25519.h's ECPoint
              # collides with heimdal's ASN.1 ECPoint.
              "--disable-cryptocb"
              "--disable-curve25519"
              "--disable-curve448"
              "--disable-ech"
              "--disable-chacha"
              "--disable-poly1305"
            ];
          env = (old.env or { }) // {
            NIX_CFLAGS_COMPILE = "-DWOLFSSL_DES_ECB";
          };
          # Its suite reaches for the network; the product's own wolfSSL build runs it.
          doCheck = false;
        });
        heimdal = pkgs.callPackage ./nix/package.nix {
          inherit wolfssl;
          src = self;
        };
        default = heimdal;
      });

      # heimdal's own unit tests for what qfsd relies on: Kerberos crypto through the shim and
      # wolfSSL, keytabs, credential caches and PACs. The rest of its suite needs a KDC.
      checks = forAllSystems (pkgs: {
        unit = self.packages.${pkgs.stdenv.hostPlatform.system}.heimdal.overrideAttrs {
          pname = "heimdal-qumulo-unit-tests";
          doCheck = true;
          checkPhase = ''
            runHook preCheck
            $CC -shared -fPIC ${./nix/tests/wolfssl-init.c} -lwolfssl -o $TMPDIR/wolfssl-init.so
            export LD_PRELOAD=$TMPDIR/wolfssl-init.so
            make -C lib/krb5 check TESTS="${
              toString [
                "aes-test"
                "derived-key-test"
                "n-fold-test"
                "pseudo-random-test"
                "string-to-key-test"
                "test_prf"
                "test_crypto_wrapping"
                "test_fx"
                "test_cc"
                "test_keytab"
                "test_mcache"
                "test_pac"
                "test_princ"
                "test_store"
                "test_time"
              ]
            }" || { cat lib/krb5/test-suite.log; exit 1; }
            make -C lib/gssapi check TESTS="test_oid test_names test_cfx" ||
              { cat lib/gssapi/test-suite.log; exit 1; }
            runHook postCheck
          '';
        };
      });
    };
}
