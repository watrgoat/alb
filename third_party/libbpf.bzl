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

    # Build libbpf
    result = repository_ctx.execute(
        ["make", "-C", "src", "-j", "BUILD_STATIC_ONLY=1", "OBJDIR=build"],
        timeout = 120,
    )
    if result.return_code != 0:
        fail("libbpf build failed:\n" + result.stdout + "\n" + result.stderr)

    # Generate BUILD file
    repository_ctx.file("BUILD.bazel", content = """
package(default_visibility = ["//visibility:public"])

cc_library(
    name = "libbpf",
    srcs = ["src/build/libbpf.a"],
    hdrs = glob(["src/*.h"]),
    includes = ["src"],
    linkopts = ["-lelf", "-lz"],
)
""")

    # Export copts (empty since we use includes)
    repository_ctx.file("cflags.bzl", content = "LIBBPF_COPTS = []\n")

libbpf_repository = repository_rule(
    implementation = _libbpf_repository_impl,
)
