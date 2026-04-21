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
    raw_cflags = result.stdout.strip().split(" ") if result.stdout.strip() else []

    # pkg-config pulls transitive deps (libnl, dbus) into -I even though
    # dpdk's userland headers don't include any of those directly. bazel's
    # include scanner rejects -I and -isystem paths under /usr/lib/... so
    # we drop those paths entirely. system -I under /usr/include is
    # rewritten to -isystem to avoid sandbox complaints.
    def _skip_path(p):
        return "dbus" in p or "libnl" in p

    cflags_list = []
    skip_next = False
    for idx in range(len(raw_cflags)):
        if skip_next:
            skip_next = False
            continue
        f = raw_cflags[idx]
        if f == "-I" and idx + 1 < len(raw_cflags):
            p = raw_cflags[idx + 1]
            skip_next = True
            if not _skip_path(p):
                cflags_list.append("-isystem")
                cflags_list.append(p)
        elif f.startswith("-I"):
            p = f[2:]
            if not _skip_path(p):
                cflags_list.append("-isystem")
                cflags_list.append(p)
        else:
            cflags_list.append(f)

    result = repository_ctx.execute(["pkg-config", "--libs", "libdpdk"])
    if result.return_code != 0:
        fail("pkg-config --libs libdpdk failed: " + result.stderr)
    linkopts = result.stdout.strip().split(" ") if result.stdout.strip() else []

    # Write cflags to a file so BUILD files can load them
    repository_ctx.file("cflags.bzl", content = "DPDK_COPTS = {}\n".format(
        repr(cflags_list),
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
