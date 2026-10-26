package("dpdk")
    add_urls("https://fast.dpdk.org/rel/dpdk-$(version).tar.xz")
    add_versions("20.11.10", "60d1ccd072102dd032c7915f6664bf4124f50e712045b6a3c55e651cb75cd530")
    add_versions("24.11.2", "bde714a0a86acce6c0ff679804e07275423c5972b13891a1432b5631ab9dd6cf")
    add_deps("meson", "ninja", {binary = true})
    -- add_deps("openssl", {configs = { shared = true }})
    if is_plat("windows") then
        add_deps("pkgconf")
    else
        add_deps("pkg-config")
    end

    add_configs("net/pcap", {description = "Build the libpcap PMD (net/pcap)", default = false, type = "boolean"})
    add_configs("numa", {description = "Build dpdk with libnuma", default = false, type = "boolean"})
    add_configs("kmods", {description = "Enable kernel modules build", default = false, type = "boolean"})
    add_configs("machine", {description = "Target CPU architecture", default = nil, type = "string"})
    add_configs("tests", {description = "Build unittests", default = false, type = "boolean"})
    add_configs("examples", {description = "Comma-seperated list of examples to build by default", default = "", type = "string"})
    add_configs("disable_drivers", {description = "Comma-seperated list of drivers to be excluded from compiling", default = "", type = "string"})

    on_load(function (package)
        if is_plat("linux") then
            if package:config("net/pcap") then
                package:add("deps", "libpcap", {configs = {shared = package:config("shared"), remote = false, libnl = false}})
            end
            if package:config("numa") then
                package:add("deps", "numactl", {configs = {shared = package:config("shared")}})
            end
        end
    end)

    on_install("linux", function (package) 
        local configs = {}
        table.insert(configs, "-Dc_args=-fcommon")
        table.insert(configs, "-Dcpp_args=-fcommon")
        table.insert(configs, "-Denable_kmods=".. tostring(package:config("kmods")))
        if package:config("machine") ~= nil then
            table.insert(configs, "-Dmachine=".. tostring(package:config("machine")))
        end
        table.insert(configs, "-Dtests=".. tostring(package:config("tests")))
        table.insert(configs, "-Dexamples=".. tostring(package:config("examples")))
        -- add this to fix xmake install could find correct library file problem
        table.insert(configs, "-Ddrivers_install_subdir=")

        local disable_drivers = ""
        if package:config("disable_drivers") ~= nil then
            disable_drivers = package:config("disable_drivers")
        end
        if not package:config("net/pcap") then
            disable_drivers = string.format("%s,%s", disable_drivers, "net/pcap")
        end
        if disable_drivers ~= "" then
            table.insert(configs, "-Ddisable_drivers=" .. disable_drivers)
        end

        local meson_deps = {}
        if package:config("net/pcap") then
            table.insert(meson_deps, "libpcap")
        end
        if package:config("numa") then
            table.insert(meson_deps, "numactl")
        end
        import("package.tools.meson")
        local meson_opt = {packagedeps = meson_deps}
        if package:config("numa") then
            local numactl = package:dep("numactl")
            if numactl and not numactl:is_system() then
                -- DPDK probes libnuma with cc.find_library('numa') and
                -- cc.has_header('numaif.h'). Those compiler probes do not see
                -- the -L/-I flags xmake puts in LDFLAGS/CFLAGS for packagedeps,
                -- so expose the package paths through the compiler's own
                -- library/header search environment.
                local envs = meson.buildenvs(package, meson_opt)
                envs = os.joinenvs({
                    LIBRARY_PATH = numactl:installdir("lib"),
                    CPATH = numactl:installdir("include"),
                }, envs)
                meson_opt.envs = envs
            end
        end
        meson.install(package, configs, meson_opt)

        if package:config("numa") then
            local build_config = io.readfile(path.join(package:installdir("include"), "rte_build_config.h")) or ""
            assert(build_config:find("RTE_HAS_LIBNUMA", 1, true),
                "DPDK's meson build did not detect libnuma although numa = true; " ..
                "check numactl's LIBRARY_PATH/CPATH and the meson configure log")
        end

        if package:config("net/pcap") then
            assert(#os.files(path.join(package:installdir("lib"), "librte_net_pcap*")) > 0,
                "libpcap PMD was not built: libpcap was not discoverable by meson/pkg-config")
        end

        io.writefile("xmake.lua", string.format([[
            target("dpdk")
                set_kind("headeronly")
                add_headerfiles("(drivers/net/ixgbe/*.h)")
                add_headerfiles("(drivers/net/ixgbe/base/*.h)")
                add_headerfiles("(drivers/net/i40e/*.h)")
                add_headerfiles("(drivers/net/i40e/base/*.h)")
        ]]))
        import("package.tools.xmake").install(package, {})
    end)
