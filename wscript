# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
VERSION = "0.1.0"
APPNAME = "libnac-abe"
GIT_TAG_PREFIX = "nac-abe"

from waflib import Logs, Utils, Context
import os

def options(opt):
    opt.load(['compiler_cxx', 'gnu_dirs'])
    opt.load(['boost', 'default-compiler-flags', 'glib2', 'sanitizers', 'doxygen'],
                 tooldir=['.waf-tools'])

    syncopt = opt.add_option_group ("NAC-ABE options")
    syncopt.add_option('--with-tests', action='store_true', default=False, dest='with_tests',
                       help='''build unit tests''')

def configure(conf):
    conf.load(['compiler_cxx', 'gnu_dirs',
               'boost', 'default-compiler-flags', 'glib2', 'doxygen'])

    if 'PKG_CONFIG_PATH' not in os.environ:
       os.environ['PKG_CONFIG_PATH'] = Utils.subst_vars('${LIBDIR}/pkgconfig', conf.env)
    conf.check_cfg(package='libndn-cxx', args=['--cflags', '--libs'],
                   uselib_store='NDN_CXX', mandatory=True)

    USED_BOOST_LIBS = ['system', 'filesystem', 'iostreams',
                       'program_options', 'thread', 'log', 'log_setup']

    conf.env['WITH_TESTS'] = conf.options.with_tests
    if conf.env['WITH_TESTS']:
        USED_BOOST_LIBS += ['unit_test_framework']
        conf.define('HAVE_TESTS', 1)

    conf.check_boost(lib=USED_BOOST_LIBS, mt=True)
    if conf.env.BOOST_VERSION_NUMBER < 105400:
        Logs.error("Minimum required boost version is 1.54.0")
        Logs.error("Please upgrade your distribution or install custom boost libraries" +
                    " (https://redmine.named-data.net/projects/nfd/wiki/Boost_FAQ)")
        return

    conf.load('sanitizers')

    conf.define('SYSCONFDIR', conf.env['SYSCONFDIR'])

    conf.env['STLIBPATH'] = ['.'] + conf.env['STLIBPATH']

    conf.check_cfg (package='glib-2.0', uselib_store='GLIB', atleast_version='2.25.0',
	                args='--cflags --libs')

    conf.env.LIBPATH_PBC = ['/usr/local/Cellar/pbc/0.5.14/lib']
    conf.env.INCLUDES_PBC  = ['/usr/local/Cellar/pbc/0.5.14/include/pbc']
    conf.check_cxx(lib = 'pbc', use = 'PBC', args='--cflags --libs')

    conf.env.LIBPATH_GMP = ['/usr/local/lib']
    conf.env.INCLUDES_GMP  = ['/usr/local/include']
    conf.check_cxx(lib = 'gmp', use = 'GMP', args='--cflags --libs')

    conf.env.STLIBPATH_BSWABE = ['/usr/local/lib']
    conf.env.INCLUDES_BSWABE  = ['/usr/local/include']
    conf.check_cxx(lib = 'bswabe', use = 'BSWABE')

    conf.env.STLIBPATH_BSWABE = ['/usr/local/lib']
    conf.env.INCLUDES_BSWABE  = ['/usr/local/include']
    conf.check_cxx(lib = 'cryptopp', use = 'CRYPTOPP')

    conf.write_config_header('src/nac-abe-config.hpp')

def build(bld):
    core = bld(
        target = "nac-abe",
        features=['cxx', 'cxxshlib'],
        source =  bld.path.ant_glob(['src/**/*.cpp', 'src/**/*.c']),
        vnum = VERSION,
        cnum = VERSION,
        use = 'NDN_CXX BOOST GMP GLIB PBC BSWABE CRYPTOPP',
        includes = ['src'],
        export_includes=['src'],
    )

    bld.recurse('tests')

    bld.install_files(
        dest = "%s/nac-abe" % bld.env['INCLUDEDIR'],
        files = bld.path.ant_glob(['src/**/*.hpp', 'src/**/*.h']),
        cwd = bld.path.find_dir("src"),
        relative_trick = True,
        )

    bld.install_files(
        dest = "%s/nac-abe" % bld.env['INCLUDEDIR'],
        files = bld.path.get_bld().ant_glob(['src/**/*.hpp']),
        cwd = bld.path.get_bld().find_dir("src"),
        relative_trick = False,
        )

    bld(features = "subst",
        source='libnac-abe.pc.in',
        target='libnac-abe.pc',
        install_path = '${LIBDIR}/pkgconfig',
        PREFIX       = bld.env['PREFIX'],
        INCLUDEDIR   = "%s/nac-abe" % bld.env['INCLUDEDIR'],
        VERSION      = VERSION,
        )
