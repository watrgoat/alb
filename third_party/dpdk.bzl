def _dpdk_repository_impl(repository_ctx):
    result = repository_ctx.execute(["pkg-config", "--cflags", "libdpdk"])
    if result.return_code != 0:
        fail("pkg-config --cflags libdpdk failed: " + result.stderr)
    cflags = result.stdout.strip()

    result = repository_ctx.execute(["pkg-config", "--libs", "libdpdk"])
    if result.return_code != 0:
        fail("pkg-config --libs libdpdk failed: " + result.stderr)
    linkopts = result.stdout.strip().split(" ") if result.stdout.strip() else []

    # Write cflags to a file so BUILD files can load them
    repository_ctx.file("cflags.bzl", content = 'DPDK_COPTS = {}\n'.format(
        repr(cflags.split(" ") if cflags else []),
    ))

    repository_ctx.file("BUILD.bazel", content = """
package(default_visibility = ["//visibility:public"])

cc_library(
    name = "dpdk",
    linkopts = {linkopts},
)
""".format(
        linkopts = repr(linkopts),
    ))

dpdk_repository = repository_rule(
    implementation = _dpdk_repository_impl,
    local = True,
    environ = ["PKG_CONFIG_PATH"],
)
