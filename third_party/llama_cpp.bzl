"""Repository rule for locating llama.cpp via pkg-config."""

def _llama_cpp_repository_impl(repository_ctx):
    probe = repository_ctx.execute(["pkg-config", "--exists", "llama"])
    if probe.return_code != 0:
        fail("""llama.cpp not found via pkg-config (llama).

Build and install from source:
  ./third_party/install_llama_cpp.sh

Or, if installed to a non-standard prefix:
  PREFIX=/opt/llama ./third_party/install_llama_cpp.sh
  export PKG_CONFIG_PATH=/opt/llama/lib/pkgconfig
""")

    result = repository_ctx.execute(["pkg-config", "--cflags", "llama"])
    if result.return_code != 0:
        fail("pkg-config --cflags llama failed: " + result.stderr)
    cflags = result.stdout.strip()

    result = repository_ctx.execute(["pkg-config", "--libs", "llama"])
    if result.return_code != 0:
        fail("pkg-config --libs llama failed: " + result.stderr)
    linkopts = result.stdout.strip().split(" ") if result.stdout.strip() else []

    repository_ctx.file("cflags.bzl", content = "LLAMA_CPP_COPTS = {}\n".format(
        repr(cflags.split(" ") if cflags else []),
    ))

    # Expose the server binary path so targets can depend on it as a data dep
    result = repository_ctx.execute(["pkg-config", "--variable=prefix", "llama"])
    prefix = result.stdout.strip() if result.return_code == 0 else "/usr/local"

    repository_ctx.file("defs.bzl", content = "LLAMA_CPP_PREFIX = {}\n".format(
        repr(prefix),
    ))

    repository_ctx.file("BUILD.bazel", content = """
package(default_visibility = ["//visibility:public"])

cc_library(
    name = "llama_cpp",
    linkopts = {linkopts},
)
""".format(
        linkopts = repr(linkopts),
    ))

llama_cpp_repository = repository_rule(
    implementation = _llama_cpp_repository_impl,
    local = True,
    environ = ["PKG_CONFIG_PATH"],
)
