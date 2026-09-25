package("dpdk-kmods")
    set_homepage("https://git.dpdk.org/dpdk-kmods/")
    set_description("Out-of-tree DPDK kernel modules (igb_uio)")
    set_license("GPL-2.0")

    -- git.dpdk.org is not directly reachable here, use the pristine upstream snapshot
    -- repackaged by Debian (see pool/main/d/dpdk-kmods).
    add_urls("https://deb.debian.org/debian/pool/main/d/dpdk-kmods/dpdk-kmods_0~20241120+git.orig.tar.xz")
    add_versions("20241120", "6abecdcba9d61945778c81e389a3282b16e7b409289ee4598a80e46912430ead")

    on_install("linux", function (package)
        import("package.tools.make")

        local kver   = os.iorunv("uname", {"-r"}):trim()
        local kbuild = "/lib/modules/" .. kver .. "/build"
        -- on_install runs inside the extracted source directory
        local srcdir = path.absolute(path.join("linux", "igb_uio"))

        -- kbuild external modules are built and installed by two separate make
        -- invocations, and neither maps onto package.tools.make.install():
        --   * install() hardcodes `make install`, but the install verb of kbuild is
        --     `modules_install`. upstream's Makefile has no `install:` target; its
        --     `%:` rule would forward it to kbuild's *kernel image* target
        --     (arch/x86/Makefile install -> cmd_install -> INSTALL $(INSTALL_PATH),
        --     default /boot).
        --   * install() forwards `configs` only to its build half, so
        --     INSTALL_MOD_PATH could never reach the install step.
        -- same shape as xmake-repo's libselinux package.
        local configs = {"-C", kbuild, "M=" .. srcdir}
        make.build(package, configs)

        -- install with the kernel's own rule, only redirecting the root into the
        -- package directory:
        --   MODLIB = $(INSTALL_MOD_PATH)/lib/modules/$(KERNELRELEASE)
        --   out-of-tree modules default to INSTALL_MOD_DIR=updates
        --   => <pkgdir>/lib/modules/<kver>/updates/igb_uio.ko(.xz)
        -- M= must be kept: Makefile.modinst only wipes $(MODLIB)/kernel for in-tree
        -- installs, and INSTALL_MOD_PATH already points MODLIB into the package dir.
        -- use make.make (not make.build) so modules_install runs serially: with -j the
        -- FORCE dependency can leave both igb_uio.ko and igb_uio.ko.xz behind.
        table.insert(configs, "INSTALL_MOD_PATH=" .. package:installdir())
        table.insert(configs, "modules_install")
        make.make(package, configs)
    end)
