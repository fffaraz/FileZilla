project('fzssh', ['cpp'],
	meson_version: '>=1.3',
	version: '1.3.0',
	default_options: ['cpp_std=c++20,c++2a', 'b_pie=true', 'warning_level=3']
)

# Update the version information only immediately before a public release of your software
# If the library source code has changed at all since the last update, then increment revision (‘c:r:a’ becomes ‘c:r+1:a’).
# If any interfaces have been added, removed, or changed since the last update, increment current, and set revision to 0.
# If any interfaces have been added since the last public release, then increment age.
# If any interfaces have been removed or changed since the last public release, then set age to 0.
# CURRENT:REVISION:AGE
soversion = '13.0.0'

if host_machine.system() == 'windows'
	platform = 'windows'
elif host_machine.system() == 'darwin'
	platform = 'apple'
else
	platform = 'unix'
endif

lfz_dep = dependency('libfilezilla', version: '>= 0.55.3')
nettle_dep = dependency('nettle', version: '>= 3.10')
hogweed_dep = dependency('hogweed', version: '>= 3.10')
gmp_dep = dependency('gmp', version: '>= 6.2')
argon2_dep = dependency('libargon2')

# Substitutions going into configuration headers and other generated files
conf = configuration_data()
conf.set('PACKAGE_VERSION', meson.project_version())
conf.set_quoted('PACKAGE_VERSION_S', meson.project_version())
version_suffix = meson.project_version().split('-')
versions = version_suffix[0].split('.')
conf.set('PACKAGE_NAME', 'libfzssh')
conf.set('PACKAGE_FILENAME', 'libfzssh-' + soversion + '.dll')
conf.set('PACKAGE_VERSION_SUFFIX', version_suffix.length() > 1 ? version_suffix[1] : '')
conf.set_quoted('PACKAGE_VERSION_SUFFIX_S', version_suffix.length() > 1 ? version_suffix[1] : '')
conf.set('PACKAGE_VERSION_MAJOR', versions[0])
conf.set('PACKAGE_VERSION_MINOR', versions.length() > 1 ? versions[1] : '0')
conf.set('PACKAGE_VERSION_MICRO', versions.length() > 2 ? versions[2] : '0')
conf.set('PACKAGE_VERSION_NANO', versions.length() > 3 ? versions[3] : '0')

base_conf = conf
configure_file(
	output: 'config.hpp',
	configuration: base_conf
)

if platform == 'windows'
	windres = import('windows')
endif

fzssh_crypt_sources = [
	'lib/crypt/bcrypt.cpp',
	'lib/crypt/bcrypt.hpp',
	'lib/crypt/blowfish.cpp',
	'lib/crypt/mlkem.cpp',
	'lib/crypt/mlkem_impl.cpp',
	'lib/crypt/util.cpp'
]

fzssh_crypt_deps = [lfz_dep, nettle_dep]

if platform == 'windows'
	fzssh_crypt_deps += meson.get_compiler('cpp').find_library('ws2_32')

	crypt_conf = conf
	crypt_conf.set('PACKAGE_NAME', 'libfzssh-crypt')
	crypt_conf.set('PACKAGE_FILENAME', 'libfzssh-crypt-' + soversion + '.dll')
	crypt_version_rc = configure_file(
		input: 'lib/version.rc.in',
		output: 'version-crypt.rc',
		configuration: crypt_conf,
	)
	crypt_rc = windres.compile_resources(crypt_version_rc,
		include_directories: meson.current_build_dir()
	)
	fzssh_crypt_sources += crypt_rc
endif

fzssh_crypt = shared_library('fzssh-crypt', fzssh_crypt_sources,
	dependencies: fzssh_crypt_deps,
	install: true,
	gnu_symbol_visibility: 'hidden',
	cpp_args: ['-DBUILDING_FZSSH_CRYPT'],
	soversion: soversion
)

version_hpp = configure_file(
	input: 'lib/fzssh/version.hpp.in',
	output: 'version.hpp',
	configuration: base_conf,
	install: true,
	install_dir: 'include/fzssh/'
)

fzssh_sources = [
	'lib/asn1.cpp',
	'lib/buffer_util.cpp',
	'lib/cipher.cpp',
	'lib/ecc.cpp',
	'lib/dh.cpp',
	'lib/connection_protocol.cpp',
	'lib/mac.cpp',
	'lib/mpz.cpp',
	'lib/pubkey.cpp',
	'lib/privkey.cpp',
	'lib/privkey_import.cpp',
	'lib/transport.cpp',
	'lib/sftp.cpp',
	'lib/ssh.cpp',
	'lib/transport.cpp',
	'lib/userauth.cpp',
	'lib/version.cpp',
	version_hpp
]

install_headers(
	'lib/fzssh/pubkey.hpp',
	'lib/fzssh/privkey.hpp',
	'lib/fzssh/ssh.hpp',
	'lib/fzssh/visibility.hpp',
	subdir: 'fzssh'
)

install_headers(
	'lib/fzssh/sftp/sftp.hpp',
	subdir: 'fzssh/sftp'
)

fzssh_deps = [lfz_dep, nettle_dep, hogweed_dep, gmp_dep, argon2_dep]
if platform == 'windows'
	version_rc = configure_file(
		input: 'lib/version.rc.in',
		output: 'version.rc',
		configuration: base_conf
	)
	rc = windres.compile_resources(version_rc,
		include_directories: meson.current_build_dir()
	)
	fzssh_sources += rc
endif

fzssh = shared_library('fzssh', fzssh_sources,
	dependencies: fzssh_deps,
	install: true,
	gnu_symbol_visibility: 'hidden',
	cpp_args: ['-DBUILDING_FZSSH'],
	soversion: soversion,
	link_with: fzssh_crypt
)

# Client part
fzssh_client_sources = [
	'lib/client/agent.cpp',
	'lib/client/client.cpp',
	'lib/client/connection_protocol.cpp',
	'lib/client/sftp_client.cpp',
	'lib/client/transport.cpp',
	'lib/client/userauth.cpp',
]

install_headers(
	'lib/fzssh/agent.hpp',
	'lib/fzssh/client.hpp',
	'lib/fzssh/visibility_client.hpp',
	subdir: 'fzssh'
)

install_headers(
	'lib/fzssh/sftp/sftp_client.hpp',
	subdir: 'fzssh/sftp'
)

fzssh_client_deps = [lfz_dep, nettle_dep, hogweed_dep, gmp_dep]

if platform == 'windows'
	fzssh_client_deps += meson.get_compiler('cpp').find_library('crypt32')
	fzssh_client_deps += meson.get_compiler('cpp').find_library('secur32')

	client_conf = conf
	client_conf.set('PACKAGE_NAME', 'libfzssh-client')
	client_conf.set('PACKAGE_FILENAME', 'libfzssh-client-' + soversion + '.dll')
	client_version_rc = configure_file(
		input: 'lib/version.rc.in',
		output: 'version-client.rc',
		configuration: client_conf,
	)
	client_rc = windres.compile_resources(client_version_rc,
		include_directories: meson.current_build_dir()
	)
	fzssh_client_sources += client_rc
endif

fzssh_client = shared_library('fzssh-client', fzssh_client_sources,
	dependencies: fzssh_client_deps,
	install: true,
	gnu_symbol_visibility: 'hidden',
	cpp_args: ['-DBUILDING_FZSSH_CLIENT'],
	link_with: fzssh,
	soversion: soversion
)

inc = include_directories('lib')
executable('client', ['src/client.cpp' ],
	include_directories: inc,
	link_with: [fzssh_client, fzssh],
	dependencies: lfz_dep,
)

executable('bench', ['src/benchmark.cpp' ],
	include_directories: inc,
	link_with: [fzssh_client, fzssh],
	dependencies: lfz_dep,
)

executable('chatter_client', 'src/chatter_client.cpp',
	include_directories: inc,
	link_with: [fzssh_client, fzssh],
	dependencies: lfz_dep,
)

pkg_mod = import('pkgconfig')
pkg_mod.generate(fzssh_client,
	libraries : [fzssh_client, fzssh],
	name: 'libfzssh-client',
	filebase: 'libfzssh-client',
	description: 'The FileZilla SSH client library')


subdir('tests')
