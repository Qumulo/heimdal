{
  lib,
  stdenv,
  buildPackages,
  runCommandCC,
  autoreconfHook,
  bison,
  flex,
  pkg-config,
  python3,
  ncurses,
  libxcrypt,
  wolfssl,
  src,
}:
let
  # Heimdal consumes OpenSSL 3 as <openssl/*.h> plus -lcrypto. Present wolfSSL's OpenSSL
  # compatibility layer under those names, with nix/ossl3-wolfssl supplying the OpenSSL 3
  # interfaces it lacks.
  # Each <openssl/X.h> is a wrapper that pulls in wolfssl/options.h first, since the compat
  # headers read no build configuration on their own, and the shim's declarations last.
  wolfsslOpensslView = runCommandCC "wolfssl-openssl-view" { } ''
    mkdir -p $out/include/openssl $out/lib
    ln -s ${wolfssl.dev}/include/wolfssl $out/include/wolfssl
    for h in ${wolfssl.dev}/include/wolfssl/openssl/*.h; do
      name=$(basename "$h")
      printf '#include <wolfssl/options.h>\n#include <wolfssl/openssl/%s>\n#include <ossl3-wolfssl.h>\n' \
        "$name" > "$out/include/openssl/$name"
    done
    cp ${src}/nix/ossl3-wolfssl/include/ossl3-wolfssl.h $out/include/
    for h in ${src}/nix/ossl3-wolfssl/include/openssl/*.h; do
      cp -n "$h" $out/include/openssl/
    done

    $CC -c -O2 -fPIC -fvisibility=hidden -Wall -Werror -I$out/include \
      ${src}/nix/ossl3-wolfssl/ossl3-wolfssl.c -o ossl3-wolfssl.o
    $AR rcs $out/lib/libossl3-wolfssl.a ossl3-wolfssl.o

    # The linked SONAME is libwolfssl.so.N, so the runtime lookup needs a RUNPATH entry that
    # holds that name.
    for so in ${wolfssl.lib}/lib/libwolfssl.so*; do
      ln -s "$so" "$out/lib/''${so##*/}"
    done
    # -lcrypto links the shim into each library that uses it, then wolfSSL.
    echo "GROUP ( $out/lib/libossl3-wolfssl.a $out/lib/libwolfssl.so )" > $out/lib/libcrypto.so
  '';
  # asn1_compile, slc and compile_et run during the build, so a cross build takes them from the
  # build machine's own build of this package, which keeps the three.
  crossTools = (buildPackages.callPackage ./package.nix { inherit src; }).overrideAttrs (old: {
    pname = "heimdal-qumulo-cross-tools";
    outputs = [ "out" ];
    postInstall = ''
      mkdir -p $out/cross-tools
      for tool in asn1_compile slc; do
        installed=$(find $out -type f -name $tool | head -1)
        [ -n "$installed" ] || { echo "$tool is not installed" >&2; exit 1; }
        ln -s "$installed" $out/cross-tools/$tool
      done
      # Not installed; the build tree's copy, as nixpkgs' heimdal ships it for cross builds.
      cp lib/com_err/.libs/compile_et $out/cross-tools/
      for tool in $out/cross-tools/*; do
        $tool --version > /dev/null 2>&1 || $tool -h > /dev/null 2>&1 || {
          echo "$tool does not run" >&2
          exit 1
        }
      done
    '';
  });
  librarySubdirs = [
    "include"
    "lib/roken"
    "lib/vers"
    "lib/com_err"
    "lib/base"
    "lib/sl"
    "lib/wind"
    "lib/asn1"
    "lib/sqlite"
    "lib/ipc"
    "lib/krb5"
    "lib/gssapi"
  ];
in
stdenv.mkDerivation {
  pname = "heimdal-qumulo";
  version = "8-pre";

  inherit src;

  nativeBuildInputs = [
    autoreconfHook
    bison
    flex
    pkg-config
    python3
    # JSON's own test suite fails under this perl; the module works.
    (buildPackages.perl.withPackages (p: [ (p.JSON.overrideAttrs { doCheck = false; }) ]))
  ];

  buildInputs = [
    ncurses
    wolfsslOpensslView
  ]
  # glibc stopped shipping libcrypt in 2.38. Where it still does, as on Bionic, -lcrypt has to stay
  # glibc's, since that is the libcrypt the target machines carry.
  ++ lib.optionals (lib.versionAtLeast stdenv.cc.libc.version "2.38") [ libxcrypt ];

  # autogen.sh also deletes the checked-in generated headers so asn1_compile
  # regenerates them; autoreconfHook only runs autoreconf.
  postAutoreconf = ''
    find . \( -name '*-private.h' -o -name '*-protos.h' \) -exec rm -f {} +
  '';

  configureFlags = [
    "--with-openssl-include=${wolfsslOpensslView}/include"
    "--with-openssl-lib=${wolfsslOpensslView}/lib"
    "--disable-heimdal-documentation"
    # qfsd uses none of these, and they need far more of OpenSSL 3 than the shim offers: hx509
    # with PKINIT and kx509, X25519 with SANON.
    "--disable-pk-init"
    "--disable-kx509"
    "--disable-sanon"
    "LIBS=-lcrypt"
    # RPATH, not RUNPATH: qfsd finds transitive deps like libheimsqlite via its
    # own inherited RPATH, and a RUNPATH here would block that inheritance.
    # The version scripts name symbols that only some platforms define; GNU ld ignores those
    # entries and --undefined-version makes lld ignore them too.
    "LDFLAGS=-Wl,--as-needed,--disable-new-dtags,--undefined-version"
  ]
  ++ lib.optionals (!stdenv.buildPlatform.canExecute stdenv.hostPlatform) [
    "--with-cross-tools=${crossTools}/cross-tools"
  ];

  # Fixup's shrink-rpath rewrites DT_RPATH into DT_RUNPATH; keep RPATH.
  dontPatchELF = true;

  enableParallelBuilding = true;

  # Build and install only the libraries qfsd links and what they need; hx509 and everything
  # above lib/ need the OpenSSL 3 interfaces the shim leaves out.
  buildPhase = ''
    runHook preBuild
    for dir in ${toString librarySubdirs}; do
      make -C $dir -j$NIX_BUILD_CORES
    done
    runHook postBuild
  '';
  installPhase = ''
    runHook preInstall
    for dir in ${toString librarySubdirs}; do
      make -C $dir install
    done
    runHook postInstall
  '';

  # Ship only what qfsd links against. The full install also carries
  # KDC/admin libraries and client binaries like kinit (collide with the
  # krb5 KDC package).
  postInstall = ''
    kept=$(mktemp -d)
    rm $out/include/com_err.h $out/include/com_right.h
    mv $out/include $kept/include
    for name in gssapi krb5 heimbase wind heimsqlite asn1 roken com_err; do
      mv $out/lib/lib$name.so* $kept
    done
    rm -rf $out
    mkdir -p $out/lib
    mv $kept/include $out/include
    mv $kept/lib*.so* $out/lib
  '';

  # The test suite drives kinit/kdc end to end and needs network loopback
  # setup the sandbox doesn't provide.
  doCheck = false;

  meta = {
    description = "Qumulo-patched Heimdal built against wolfSSL's OpenSSL compatibility layer";
    homepage = "https://github.com/Qumulo/heimdal";
    license = lib.licenses.bsd3;
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];
  };
}
