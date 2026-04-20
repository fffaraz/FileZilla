testinc = include_directories('../lib')
keywords = {
	'implicit_include_directories': false,
	'include_directories': testinc,
	'dependencies': lfz_dep
}

keyfile_test = executable('keyfile_test', 'keyfile_test.cpp', kwargs: keywords + {'link_with': fzssh})
test('keyfile_test', keyfile_test)

