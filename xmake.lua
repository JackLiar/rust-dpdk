add_repositories("localrepo deps")

-- if build on windows, all packages needs to be shared library
if is_os("windows") then
else
    -- add_requires("libpcap", {system = false, configs= {shared = true}})
    -- add_requires("numactl", {system = false, configs = {shared = true}})
    -- add_requires("openssl", {system = false, configs = {shared = true}})
    add_requires("dpdk 20.11.10", {system = false})
    add_requires("dpdk-kmods", {system = false})
end

target("rust-dpdk")
    set_kind("phony")
    -- add_packages("libpcap")
    -- add_packages("numactl")
    -- add_packages("openssl")
    add_packages("dpdk", "dpdk-kmods")

    after_build(function(target)
        local function add_to_table(paths, var)
            if type(var) == "table" then
                for _, path in ipairs(var) do
                    table.insert(paths, path)
                end
            else
                table.insert(paths, var)
            end
        end

        local function merge_envs(target, envs)
            for k, v in pairs(envs) do
                add_to_table(target, v)
            end
            return target
        end

        local pkg_config_dirs = {}
        local include_dirs = {}
        local link_dirs = {}
        local envs = {}

        -- kernel module built by the dpdk-kmods package, installed under the package
        -- directory with the kernel's own layout:
        --   <pkgdir>/lib/modules/$(uname -r)/updates/igb_uio.ko
        local kver = os.iorunv("uname", {"-r"}):trim()
        local kmods_root
        local igb_uio_ko

        for _, pkg in pairs(target:pkgs()) do
            add_to_table(link_dirs, pkg:get("linkdirs"), pkg:name())
            add_to_table(include_dirs, pkg:get("sysincludedirs"), pkg:name())
            for _, dir in ipairs(pkg:get("linkdirs")) do
                table.append(pkg_config_dirs, path.join(dir, "pkgconfig"))
            end
            merge_envs(envs, pkg:get("envs"))
            if pkg:name() == "dpdk-kmods" then
                kmods_root = pkg:installdir()
                -- the kernel installs modules with the compression configured by
                -- CONFIG_MODULE_COMPRESS_*, so look the real file name up
                local updir = path.join(kmods_root, "lib", "modules", kver, "updates")
                for _, name in ipairs({"igb_uio.ko", "igb_uio.ko.xz", "igb_uio.ko.gz", "igb_uio.ko.zst"}) do
                    if os.isfile(path.join(updir, name)) then
                        igb_uio_ko = path.join(updir, name)
                        break
                    end
                end
            end
        end
        if os.is_host("windows") then
            function gen_powershell_env()
                local ps_env = io.open("env.ps1", "w")
                ps_env:write("# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass\n")
                ps_env:write("$env:LIB=\"" .. table.concat(link_dirs, ";") .. ";$env:LIB\"\n")
                local paths = { "C:\\Windows\\System32\\Npcap\\" }
                ps_env:write("$env:PATH=\"" .. table.concat(paths, ";") .. ";$env:PATH\"\n")
                ps_env:close()

                local ps_run = io.open("run.ps1", "w")
                ps_run:write("# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass\n")
                local paths = { "C:\\Windows\\System32\\Npcap\\", "$env:PSScriptRoot" }
                ps_run:write("$env:PATH=\"" .. table.concat(paths, ";") .. ";$env:PATH\"\n")
                ps_run:close()
            end
            gen_powershell_env()
        else
            function gen_bash_env()
                local bash_env = io.open("env.sh", "w")
                bash_env:write("#!/bin/bash\n")
                bash_env:write("export PKG_CONFIG_PATH=\"" .. table.concat(pkg_config_dirs, ":") .. ":$PKG_CONFIG_PATH\"\n")
                bash_env:write("export C_INCLUDE_PATH=\"" .. table.concat(include_dirs, ":") .. ":$C_INCLUDE_PATH\"\n")
                bash_env:write("export CPLUS_INCLUDE_PATH=\"" .. table.concat(include_dirs, ":") .. ":$CPLUS_INCLUDE_PATH\"\n")
                bash_env:write("export LIBRARY_PATH=\"" .. table.concat(link_dirs, ":") .. ":$LIBRARY_PATH\"\n")
                bash_env:write("export LD_LIBRARY_PATH=\"" .. table.concat(link_dirs, ":") .. ":$LD_LIBRARY_PATH\"\n")
                bash_env:write("export DPDK_KMODS_ROOT=\"" .. (kmods_root or "") .. "\"\n")
                bash_env:write("export DPDK_IGB_UIO_KO=\"" .. (igb_uio_ko or "") .. "\"\n")
                bash_env:close()
            end
            gen_bash_env()
            function gen_fish_env()
                local fish_env = io.open("env.fish", "w")
                fish_env:write("set -x PKG_CONFIG_PATH " .. table.concat(pkg_config_dirs, " ") .. " $PKG_CONFIG_PATH\n")
                fish_env:write("set -x C_INCLUDE_PATH " .. table.concat(include_dirs, " ") .. " $C_INCLUDE_PATH\n")
                fish_env:write("set -x CPLUS_INCLUDE_PATH " .. table.concat(include_dirs, " ") .. " $CPLUS_INCLUDE_PATH\n")
                fish_env:write("set -x LIBRARY_PATH " .. table.concat(link_dirs, " ") .. " $LIBRARY_PATH\n")
                fish_env:write("set -x LD_LIBRARY_PATH " .. table.concat(link_dirs, " ") .. " $LD_LIBRARY_PATH\n")
                fish_env:close()
            end
            gen_fish_env()
        end
    end)
