"""Repository rule that builds libbpf from source."""

_LIBBPF_VERSION = "1.7.0"
_LIBBPF_URL = "https://github.com/libbpf/libbpf/archive/refs/tags/v{version}.tar.gz"

def _libbpf_repository_impl(repository_ctx):
    # Download source tarball
    repository_ctx.download_and_extract(
        url = _LIBBPF_URL.format(version = _LIBBPF_VERSION),
        stripPrefix = "libbpf-" + _LIBBPF_VERSION,
    )

    # Check build dependencies
    for dep in ["libelf", "zlib"]:
        probe = repository_ctx.execute(["pkg-config", "--exists", dep])
        if probe.return_code != 0:
            fail("{dep} not found. Install with: sudo apt-get install -y libelf-dev zlib1g-dev".format(dep = dep))

    # Check for bpftool (needed by consumers for skeleton generation)
    if not repository_ctx.which("bpftool"):
        fail("bpftool not found. Install with: sudo apt-get install -y bpftool")

    # Detect multiarch include path for kernel headers
    result = repository_ctx.execute(["dpkg-architecture", "-qDEB_HOST_MULTIARCH"])
    if result.return_code == 0:
        multiarch = result.stdout.strip()
    else:
        result = repository_ctx.execute(["gcc", "-dumpmachine"])
        multiarch = result.stdout.strip() if result.return_code == 0 else "x86_64-linux-gnu"

    # Build libbpf
    result = repository_ctx.execute(
        ["make", "-C", "src", "-j", "BUILD_STATIC_ONLY=1", "OBJDIR=build"],
        timeout = 120,
    )
    if result.return_code != 0:
        fail("libbpf build failed:\n" + result.stdout + "\n" + result.stderr)

    # Create bpf/ include directory with symlinks so #include <bpf/libbpf.h> works
    for hdr in repository_ctx.path("src").readdir():
        if str(hdr).endswith(".h"):
            repository_ctx.symlink(hdr, "include/bpf/" + hdr.basename)

    # Export detected system include path for BPF compilation
    repository_ctx.file("defs.bzl", content = (
        'SYSTEM_INCLUDE = "/usr/include/{multiarch}"\n'
    ).format(multiarch = multiarch))

    # Generate BUILD file
    repository_ctx.file("BUILD.bazel", content = """
package(default_visibility = ["//visibility:public"])

cc_library(
    name = "libbpf",
    srcs = ["src/build/libbpf.a"],
    hdrs = glob(["include/bpf/*.h"]),
    includes = ["include"],
    linkopts = ["-lelf", "-lz"],
)

filegroup(
    name = "bpf_headers",
    srcs = glob(["include/bpf/*.h"]),
)
""")

libbpf_repository = repository_rule(
    implementation = _libbpf_repository_impl,
    local = True,
    environ = ["PKG_CONFIG_PATH", "PATH"],
)
