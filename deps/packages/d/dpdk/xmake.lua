package("dpdk")
    add_urls("https://fast.dpdk.org/rel/dpdk-$(version).tar.xz")
    add_versions("20.11.10", "60d1ccd072102dd032c7915f6664bf4124f50e712045b6a3c55e651cb75cd530")
    add_versions("24.11.2", "bde714a0a86acce6c0ff679804e07275423c5972b13891a1432b5631ab9dd6cf")
    add_deps("meson", "ninja")
    -- add_deps("openssl", {configs = { shared = true }})
    -- add_deps("libpcap", {configs = { shared = true, remote = true }})
    -- add_deps("numactl", {configs = { shared = true }})
    if is_plat("windows") then
        add_deps("pkgconf")
    else
        add_deps("pkg-config")
    end

    add_configs("net/pcap", {description = "libpcap pmd driver"})
    add_configs("kmods", {description = "Enable kernel modules build", default = false, type = "boolean"})
    add_configs("machine", {description = "Target CPU architecture", default = nil, type = "string"})
    add_configs("tests", {description = "Build unittests", default = false, type = "boolean"})
    add_configs("examples", {description = "Comma-seperated list of examples to build by default", default = "", type = "string"})

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
        
        import("package.tools.meson").install(package, configs)

        io.writefile("xmake.lua", string.format([[
            target("dpdk")
                set_kind("headeronly")
                add_headerfiles("(drivers/net/ixgbe/*.h)")
                add_headerfiles("(drivers/net/ixgbe/base/*.h)")
        ]]))
        import("package.tools.xmake").install(package, {})
    end)
