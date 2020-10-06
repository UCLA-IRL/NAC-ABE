# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

from waflib import Utils
import os

VERSION = "0.1.0"
APPNAME = "libnac-abe"
GIT_TAG_PREFIX = "nac-abe"

def options(opt):
    opt.load(['compiler_cxx', 'gnu_dirs'])
    opt.load(['boost', 'default-compiler-flags', 'openssl', 'sanitizers'],
             tooldir=['.waf-tools'])

    optgrp = opt.add_option_group("NAC-ABE options")
    optgrp.add_option('--with-tests', action='store_true', default=False,
                      help='Build unit tests')

def configure(conf):
    conf.load(['compiler_cxx', 'gnu_dirs',
               'boost', 'default-compiler-flags', 'openssl'])

    conf.env.WITH_TESTS = conf.options.with_tests

    conf.check_cfg(package='libndn-cxx', args=['--cflags', '--libs'], uselib_store='NDN_CXX',
                   pkg_config_path=os.environ.get('PKG_CONFIG_PATH', '%s/pkgconfig' % conf.env.LIBDIR))

    conf.check_openssl(lib='crypto', atleast_version=0x1000200f) # 1.0.2

    boost_libs = ['system', 'program_options', 'filesystem']
    if conf.env.WITH_TESTS:
        boost_libs.append('unit_test_framework')

    conf.check_boost(lib=boost_libs, mt=True)
    if conf.env.BOOST_VERSION_NUMBER < 105800:
        conf.fatal('Minimum required Boost version is 1.58.0\n'
                   'Please upgrade your distribution or manually install a newer version of Boost'
                   ' (https://redmine.named-data.net/projects/nfd/wiki/Boost_FAQ)')

    conf.load('sanitizers')

    conf.env['STLIBPATH'] = ['.'] + conf.env['STLIBPATH']

    conf.check_cfg(package='glib-2.0', uselib_store='GLIB', atleast_version='2.25.0',
	               args='--cflags --libs')

    conf.env.STLIBPATH_OPENABE = ['/usr/local/lib']
    conf.env.INCLUDES_OPENABE  = ['/usr/local/include']
    conf.check_cxx(lib = 'openabe', use = 'OPENABE')

    conf.define_cond('HAVE_TESTS', conf.env.WITH_TESTS)
    conf.define('SYSCONFDIR', conf.env.SYSCONFDIR)

    conf.write_config_header('src/nac-abe-config.hpp')

def build(bld):
    bld.shlib(target = "nac-abe",
              source = bld.path.ant_glob(['src/**/*.cpp']),
              vnum = VERSION,
              cnum = VERSION,
              use = 'NDN_CXX BOOST OPENSSL OPENABE',
              includes='src',
              export_includes='src')

    bld.recurse('tests')

    bld.install_files(
        dest='${INCLUDEDIR}/nac-abe',
        files=bld.path.ant_glob('src/**/*.hpp'),
        cwd=bld.path.find_dir('src'),
        relative_trick=True)

    bld.install_files(
        dest='${INCLUDEDIR}/nac-abe',
        files=bld.path.get_bld().ant_glob('src/**/*.hpp'),
        cwd=bld.path.get_bld().find_dir('src'),
        relative_trick=False)

    bld(features='subst',
        source='libnac-abe.pc.in',
        target='libnac-abe.pc',
        install_path='${LIBDIR}/pkgconfig',
        VERSION=VERSION)
