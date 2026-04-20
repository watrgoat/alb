"""Repository rule for locating DPDK via pkg-config."""

def _dpdk_repository_impl(repository_ctx):
    probe = repository_ctx.execute(["pkg-config", "--exists", "libdpdk"])
    if probe.return_code != 0:
        fail("""DPDK not found via pkg-config (libdpdk).

Install prerequisites on Ubuntu:
  sudo apt-get update
  sudo apt-get install -y pkg-config dpdk-dev libnuma-dev

If libdpdk.pc is installed in a non-standard location, set PKG_CONFIG_PATH.
""")

    result = repository_ctx.execute(["pkg-config", "--cflags", "libdpdk"])
    if result.return_code != 0:
        fail("pkg-config --cflags libdpdk failed: " + result.stderr)
    cflags = result.stdout.strip()

    # Bazel rejects include paths in copts that reference locations outside
    # the execution root and the toolchain's builtin include directories.
    # Absolute paths under /usr/include are accepted (they're registered as
    # builtins in the default Linux toolchain), but DPDK's pkg-config output
    # also pulls in /usr/lib/x86_64-linux-gnu/dbus-1.0/include (a Debian
    # multiarch quirk that exposes dbus-arch-deps.h). alb doesn't include
    # dbus headers, so drop any -I paths that aren't under /usr/include.
    raw_flags = cflags.split(" ") if cflags else []
    cflag_list = []
    for flag in raw_flags:
        if flag.startswith("-I/") and not flag.startswith("-I/usr/include"):
            continue
        cflag_list.append(flag)

    result = repository_ctx.execute(["pkg-config", "--libs", "libdpdk"])
    if result.return_code != 0:
        fail("pkg-config --libs libdpdk failed: " + result.stderr)
    linkopts = result.stdout.strip().split(" ") if result.stdout.strip() else []

    # Write cflags to a file so BUILD files can load them
    repository_ctx.file("cflags.bzl", content = "DPDK_COPTS = {}\n".format(
        repr(cflag_list),
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
