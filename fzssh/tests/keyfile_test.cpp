#ifdef NDEBUG
#undef NDEBUG
#endif

#include "../lib/fzssh/privkey.hpp"

#include <libfilezilla/logger.hpp>

#include <assert.h>

namespace {

// For concrete keys, the loading already does an internal
// self-test, creating and verifying a signature.

bool test_key(std::unique_ptr<fz::ssh::private_key> const& key, fz::logger_interface & log)
{
	auto pkcs8 = fz::ssh::export_pkcs8(key, true);
	if (pkcs8.empty()) {
		return false;
	}

	auto ks = fz::ssh::load_private_keys(pkcs8, log);
	if (ks.size() != 1) {
		return false;
	}
	if (key->pubkey_blob() != ks.front()->pubkey_blob()) {
		return false;
	}

	return true;
}

bool test_key(std::string_view data, fz::logger_interface & log, std::optional<std::string_view> pw = std::nullopt)
{
	auto keys = fz::ssh::load_private_keys(data, log, pw);
	if (keys.size() != 1) {
		return false;
	}
	return test_key(keys.front(), log);
}

void test_putty_keys(fz::logger_interface & log)
{
	constexpr auto putty_ppk =
		"PuTTY-User-Key-File-3: ssh-rsa\n"
		"Encryption: aes256-cbc\n"
		"Comment: rsa-key-20250605\n"
		"Public-Lines: 4\n"
		"AAAAB3NzaC1yc2EAAAADAQABAAAAgQCjQMcWwU/SlIlFZFN8d7RTZGQCOFzVAPRU\n"
		"W5QW+RvWzew+QRZiVrGIanzRK8/9QQ+50EEH4fVsSYJITLXWGsoAwaL30r6+soxn\n"
		"6spUqcVdiRlTr2wkTllMtOCsEsRWeYI9r5gNuHF9vsOfH0m+Ijeuhgq1RMq/1Rw4\n"
		"ycePf28z6Q==\n"
		"Key-Derivation: Argon2id\n"
		"Argon2-Memory: 8192\n"
		"Argon2-Passes: 21\n"
		"Argon2-Parallelism: 1\n"
		"Argon2-Salt: 03c80d89d0c915f091c1a59a52a6ac77\n"
		"Private-Lines: 8\n"
		"Cdh4KqZGohI8vlwPkIp9xl0fK4LlB3zKNH1HkKA2KdwFhz1vTZtjjwKYwaD7QaO+\n"
		"eF9NUTzbKSSUbl472l0TzW+1uHhDCbcDxr3APs606lcPqyVRDESs/hfSnmY7MsP+\n"
		"1kpsKJZ/X6qSmUEMEfETfdZiQxdbe3OzzK2zQiKY2Eqw5vFQcFCFNheH58AtWtB+\n"
		"NLoofOSCh+ikkyuYBdJDSPKLwB4T2HYFvyoEdeh2Nb3R9oLUW2ljcItp4PHP3iFH\n"
		"5NOoDRGW42sltgNYTYm7DFA+BP13i7IdriyJkvV41xauewHJT0ojnf2Gt372WnNq\n"
		"O38MH6R2CDYSZlgw8Kcatqbe3Zqpg99LHAdaE4MTtUqz05YsBhoP4nMjuLjgxU7C\n"
		"W+F9j+jZc75gx3d1dBwaMmbUy10j1E+CGhiqcss+6lARovjBKPxCOnFMxEKMb90O\n"
		"z6VXPC+/QbeFPbXgvGnU0A==\n"
		"Private-MAC: 0936d3bbb3f86ff866f723751611a2b88c54d7c44b868f1d05cc775646d54fb6\n"sv;

	constexpr auto putty_ppkv2 =
		"PuTTY-User-Key-File-2: ecdsa-sha2-nistp256\n"
		"Encryption: aes256-cbc\n"
		"Comment: ecdsa-key-20250605\n"
		"Public-Lines: 3\n"
		"AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGLte54UW3Aq\n"
		"UphDNO6gb1gdZHVYryd+KVn1hikqYmCeMJc3JM3YRJKtjyOUyUIrCEpvGLr740wo\n"
		"Xkoym4QfAzs=\n"
		"Private-Lines: 1\n"
		"YYeU74dShJFcZGax47lpQgSypmuTBSz9TfMASgJOFF6MjKurwTLxsaqHHQxHquPp\n"
		"Private-MAC: 1e13896d9f78278dec65e4d5c5dbc684f11a8ee8\n"sv;

	constexpr auto putty_plain_ppk =
		"PuTTY-User-Key-File-3: ssh-ed25519\n"
		"Encryption: none\n"
		"Comment: eddsa-key-20250605\n"
		"Public-Lines: 2\n"
		"AAAAC3NzaC1lZDI1NTE5AAAAIBM55zeZ0BwwXvmveBzmkty+iRnGPZY48wAF/nFb\n"
		"QJC5\n"
		"Private-Lines: 1\n"
		"AAAAIPkEf6d+x5IfRvzMNxXNx4hf5RiZMQAjxUB8sHKtZUwA\n"
		"Private-MAC: 1802687708046cb9e55ef24c0c2196d3289c53c562e3822e27651763e080c7fa\n";

	constexpr auto putty_plain_ppkv2 =
		"PuTTY-User-Key-File-2: ssh-ed25519\n"
		"Encryption: none\n"
		"Comment: eddsa-key-20250605\n"
		"Public-Lines: 2\n"
		"AAAAC3NzaC1lZDI1NTE5AAAAIBM55zeZ0BwwXvmveBzmkty+iRnGPZY48wAF/nFb\n"
		"QJC5\n"
		"Private-Lines: 1\n"
		"AAAAIPkEf6d+x5IfRvzMNxXNx4hf5RiZMQAjxUB8sHKtZUwA\n"
		"Private-MAC: 3a959bb7db4d5e1233d5be8c14654a04475c55bb\n";

	assert(fz::ssh::load_private_keys(putty_ppk, log, "PuTTY PPK"sv).size() == 1);
	assert(fz::ssh::load_private_keys(putty_ppkv2, log, "PuTTY PPK v2"sv).size() == 1);
	assert(fz::ssh::load_private_keys(putty_plain_ppk, log).size() == 1);
	assert(fz::ssh::load_private_keys(putty_plain_ppkv2, log).size() == 1);

	auto info = fz::ssh::load_private_key_infos(putty_ppk, log);
	assert(info.size() == 1);
	assert(info[0].encrypted());
	assert(info[0].decrypt("PuTTY PPK"sv, &log));
}

void test_openssh_keys(fz::logger_interface & log)
{
	constexpr auto plain_rsa =
		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
		"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\n"
		"-----END OPENSSH PRIVATE KEY-----\n"sv;

	constexpr auto openssh_ecdsa =
		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n"
		"1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSieNL04WTKIKfl/uJvNzWqCwCYdZCT\n"
		"AAzOJh1fQNNR4P53Nkt78Pv8lKCkPfGuFQAmOtQNkPciIBZF19YVu9JVAAAAuOOPwjfjj8\n"
		"I3AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKJ40vThZMogp+X+\n"
		"4m83NaoLAJh1kJMADM4mHV9A01Hg/nc2S3vw+/yUoKQ98a4VACY61A2Q9yIgFkXX1hW70l\n"
		"UAAAAgP4udTPU0FPaoKK7iOQNldqKHYVBwSKi7cGsm92JyL8AAAAAZY29kZXNxdWlkQERF\n"
		"U0tUT1AtRTY5MEVVMwECAwQFBgc=\n"
		"-----END OPENSSH PRIVATE KEY-----\n"sv;

	constexpr auto openssh_ecdsa_384 =
		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS\n"
		"1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQRv6G0vBy8Va0kGQgaU6mJtOo44ha9P\n"
		"p53IG84+eSuKa8DCEDunutClNTLUrHKR+aZQbCj24KaevMvjp6vNC5zZXSoI0zNgd2B63/\n"
		"/xHlnb9FJvONnYF2YgmiIy3OsHaD0AAADY/ciCi/3IgosAAAATZWNkc2Etc2hhMi1uaXN0\n"
		"cDM4NAAAAAhuaXN0cDM4NAAAAGEEb+htLwcvFWtJBkIGlOpibTqOOIWvT6edyBvOPnkrim\n"
		"vAwhA7p7rQpTUy1KxykfmmUGwo9uCmnrzL46erzQuc2V0qCNMzYHdget//8R5Z2/RSbzjZ\n"
		"2BdmIJoiMtzrB2g9AAAAME9ZBHcs7upK8yUB9VIEHXlO/VF1mkWd230wiA3fB7l9z2jlKh\n"
		"L40hb+tbV+NqvLLQAAAA5jb2Rlc3F1aWRAd29wcgEC\n"
		"-----END OPENSSH PRIVATE KEY-----\n"sv;

	constexpr auto openssh_ecdsa_521 =
		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS\n"
		"1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQATOOerPXfuBvXTh8r/Fi02pTmHnqd\n"
		"+y3c1tvHtiJsHKVBCEQVWCZvzclRWXHlw6YwUkHhd5dJX3NwCeRZGifd220BSvg06E2JJr\n"
		"llz0bGcGWTAlfhthuN+QoAs1j7k2NAdHHFrIW7/E+sG5xCmA+3s5S2bWO2XuyxVYozuGRR\n"
		"Jwm83f0AAAEQgWL9A4Fi/QMAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ\n"
		"AAAIUEAEzjnqz137gb104fK/xYtNqU5h56nfst3Nbbx7YibBylQQhEFVgmb83JUVlx5cOm\n"
		"MFJB4XeXSV9zcAnkWRon3dttAUr4NOhNiSa5Zc9GxnBlkwJX4bYbjfkKALNY+5NjQHRxxa\n"
		"yFu/xPrBucQpgPt7OUtm1jtl7ssVWKM7hkUScJvN39AAAAQgF9cnNyLHYDMkz1JZDl++wk\n"
		"y4tj3oP3j9J+AFBe5p6DtlEHtq7dsfr6XyBh6e6dFTD0HybvwAni4jO92ASdfnKi8QAAAA\n"
		"5jb2Rlc3F1aWRAd29wcgECAwQ=\n"
		"-----END OPENSSH PRIVATE KEY-----\n"sv;

	constexpr auto openssh_ed25519_encrypted_with_aes256_gcm =
		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
		"b3BlbnNzaC1rZXktdjEAAAAAFmFlczI1Ni1nY21Ab3BlbnNzaC5jb20AAAAGYmNyeXB0AA\n"
		"AAGAAAABCMWKNPer2huPqZO762xsXBAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAA\n"
		"IDzfvTDvcF3fHe5DZz9zN9ebt42ql7oc06ZWRjB9axYYAAAAoLjndoYGYApK+NQmY3PNSD\n"
		"xsSibN/B3XVS/w97ONobrtDAi5HS2Ylr/dtTZLP694xpaP/zrR1iwRWedR2hwdGTpdQMWn\n"
		"iPHcFZSAKiFMxDcox1cdA/zxQnPGtKAF2v2/9i3//5wIPAZGXdeBOmcPXm81WCQmMFAPdo\n"
		"LpdCK8yL7YodcQpoXyL3i42BP6eCNuZeerNXVq4mMIEa8qD3vsBFoPz5v7tL+pGcQtiDeO\n"
		"H/VE\n"
		"-----END OPENSSH PRIVATE KEY-----\n"sv;

	assert(fz::ssh::load_private_keys(plain_rsa, log).size() == 1);
	assert(test_key(openssh_ecdsa, log));
	assert(test_key(openssh_ecdsa_384, log));
	assert(test_key(openssh_ecdsa_521, log));
	assert(test_key(openssh_ed25519_encrypted_with_aes256_gcm, log, "aes256-gcm@openssh.com encrypted"sv));

	auto info = fz::ssh::load_private_key_infos(openssh_ed25519_encrypted_with_aes256_gcm, log);
	assert(info.size() == 1);
	assert(info[0].encrypted());
	assert(info[0].decrypt("aes256-gcm@openssh.com encrypted"sv, &log));
}

void test_pem(fz::logger_interface & log)
{
	constexpr auto plain_rsa_pem =
		"-----BEGIN RSA PRIVATE KEY-----\n"
		"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\n"
		"-----END RSA PRIVATE KEY-----\n"sv;

	constexpr auto encrypted_rsa_pem =
		"-----BEGIN RSA PRIVATE KEY-----\n"
		"Proc-Type: 4,ENCRYPTED\n"
		"DEK-Info: AES-128-CBC,C6734A44EA51DA657709D88579674952\n"
		"\n"
		"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\n"
		"-----END RSA PRIVATE KEY-----\n"sv;

	auto ecdsa_pem =
		"-----BEGIN EC PRIVATE KEY-----\n"
		"MHcCAQEEIFZSp0O5Nk/mDIhBB8VJPrJLRORfpg5ZG/KNBWFkTWJpoAoGCCqGSM49\n"
		"AwEHoUQDQgAEaxw3THPfXKpCfkch9vFYSdhJPJ3chF/h8vJX3fDpj2cEQo6m6/G+\n"
		"wu+PmbSNpLE3UGwQgw7K+Kh7QotfJdFnag==\n"
		"-----END EC PRIVATE KEY-----\n"sv;

	// No ED5519 here, it seemingly has no standalone non-pkcs8 format.

	assert(fz::ssh::load_private_keys(ecdsa_pem, log).size() == 1);
	assert(fz::ssh::load_private_keys(plain_rsa_pem, log).size() == 1);
	assert(fz::ssh::load_private_keys(encrypted_rsa_pem, log, "password"sv).size() == 1);

	auto info = fz::ssh::load_private_key_infos(encrypted_rsa_pem, log);
	assert(info.size() == 1);
	assert(info[0].encrypted());
	assert(info[0].decrypt("password"sv, &log));
}

void test_pkcs8(fz::logger_interface & log)
{
	constexpr auto rsa =
		"-----BEGIN PRIVATE KEY-----\n"
		"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMzr+Y3Dqe3B2k+E\n"
		"qLYIgTDMoxEKtfn5/KROfHh+KfN3ADJDbyTa9otM7RhRhnICkOo3K613kIXR6G4d\n"
		"4Plz5/bQXb4xPESocVYD0gRyjdY+eT2IGYNTvT1gjXij2QBPc9vpZ+GWQPoNKZsw\n"
		"ztFCsDYAiwt7s6tVv5tyFgx0syTRAgMBAAECgYEAg1qrj4Shc0b0gk49utl+vmIe\n"
		"ELl15nOoz0WEIdR1XZulI5L4Nn6o1KgNvq3baU9dxtRwifP/Ttg7jgJXCG+UewkA\n"
		"OkBh2Do1IfEy/uvqHwYNpbRRaxS4Z9K9Ww2UUs5ju3JCkVTZmZ5ge9lzmlDg7U8c\n"
		"abGjBTtxC8pdoUdtcgECQQD9Jt9EdkwBKkGilLmGVcy5Olfuf5lvUvS6w/crx4SG\n"
		"UhCsb7wIHmfJGQUZ2eAPP4KncPYz08rNO0hV0x4K4inhAkEAzzowwbBKndLivJTt\n"
		"w+zxKXeMK/h7okZWpPzcTjmdpsJKcWU0yZmdC9LBgNR8wVFT72RjO+nzfqlLjSlC\n"
		"fbC48QJAZ6EeDJyQiHmP3ModGEzPPZQQouVBHj1LSZkm+Zj3OzUk9jHXO0uXGM9R\n"
		"Mz/pZNSO25R2dMjiYBlAh0GhLrtegQJAPz/Qj92h+KfcQpjmNU3FkdWGOAmAmtgD\n"
		"LBptl4aoYrScih3MzdeQAoLSQuMYLN0I1GF8lFXk1v0PLUexnrFo0QJBAJ7edAY+\n"
		"AqBQJHRLD51mdFTa6Za8SMIlqN/RWdFqmpUamA/jQUlGnUnAICiq91tYJ7WpwMk+\n"
		"9OQHbvxd2bF+MbI=\n"
		"-----END PRIVATE KEY-----\n"sv;

	constexpr auto ecdsa =
		"-----BEGIN PRIVATE KEY-----\n"
		"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0hqonWD7c2o4+yqb\n"
		"dZiWdJXH8/xeV3YhHWdKS48UFOihRANCAARwWrJB2HKf2R1I3K2FBPpeG6uwOq4r\n"
		"XZKENryq6tLQdML6vbkrlyQtvMheLWJGinoUMvqLi+5qPd6j7OEkO6bs\n"
		"-----END PRIVATE KEY-----\n"sv;

	constexpr auto ecdsa_der =
		"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0hqonWD7c2o4+yqb\n"
		"dZiWdJXH8/xeV3YhHWdKS48UFOihRANCAARwWrJB2HKf2R1I3K2FBPpeG6uwOq4r\n"
		"XZKENryq6tLQdML6vbkrlyQtvMheLWJGinoUMvqLi+5qPd6j7OEkO6bs"sv;

	// aes128-cbc
	constexpr auto ecdsa_encrypted =
	"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
	"MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAiIApiCalxDWwICCAAw\n"
	"DAYIKoZIhvcNAgkFADAdBglghkgBZQMEAQIEELLB634QQE6gDG+AGx5rc7AEgZC2\n"
	"X7pF40pKVWwQ9YI8bxfO62T2zW6Q1pWUD8Gm/N2ueRs75HNMl15KiClMl9DjwkOS\n"
	"r7lNVS1dSipFIdADkC1aLX4dmt9VH+OXo+XYRGx0PW5Gel0uwjORBeb3HvZX3Fgx\n"
	"34GyikPjKtk/XGl6HgdtxJ83RsSMSZYqQ2RyB0Z2yUYbEHf66MY3EGjFl4LWTwE=\n"
	"-----END ENCRYPTED PRIVATE KEY-----\n"sv;

	constexpr auto ed25519 =
		"-----BEGIN PRIVATE KEY-----\n"
		"MC4CAQAwBQYDK2VwBCIEILW9lmcF+vN/Xj/H4TgoIjxnbY6w6inI8eKtPpGH2UU5\n"
		"-----END PRIVATE KEY-----\n"sv;

	auto ed25519_v163 = "MFICAQAwBQYDK2VwBCIEILhbULraDgc2H/wTfBz6CsAEtGeYpbVrEK8rdcKRQcBqoSIEIKODaXy8UKZOkNiThoIOVlGf9a7Vkp7MSd6UYk7kczeG"sv;

	// aes256-cbc
	constexpr auto ed25519_encrypted =
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
		"MIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAgjCRgn+Ng1jwICCAAw\n"
		"DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEA1I/BT9nz1/7QS51Y9srw4EQHnk\n"
		"G9QVDf8fkLQrClLOgHkKHNZFrM6+01AjrwiWwK0yV9FLUUiJecPqCb5HZmxJyNHY\n"
		"HjPLCmb4XEKSltVXksQ=\n"
		"-----END ENCRYPTED PRIVATE KEY-----\n"sv;

	// From RFC8410
	constexpr auto ed25519_with_pubblob =
		"-----BEGIN PRIVATE KEY-----\n"
		"MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n"
		"oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB\n"
		"Z9w7lshQhqowtrbLDFw4rXAxZuE=\n"
		"-----END PRIVATE KEY-----\n"sv;

	assert(test_key(rsa, log));
	assert(test_key(ecdsa, log));
	assert(test_key(fz::base64_decode_s(ecdsa_der), log));
	assert(test_key(ecdsa_encrypted, log, "porcupine"sv));
	assert(test_key(ed25519, log));
	assert(test_key(fz::base64_decode_s(ed25519_v163), log));
	assert(test_key(ed25519_encrypted, log, "password"sv));
	assert(test_key(ed25519_with_pubblob, log));

	auto info = fz::ssh::load_private_key_infos(ed25519_encrypted, log);
	assert(info.size() == 1);
	assert(info[0].encrypted());
	assert(info[0].decrypt("password"sv, &log));
}

void test_generated(fz::logger_interface & log)
{
	auto test = [&](std::string_view alg) {
		auto key = fz::ssh::create_private_key(alg);
		assert(key);
		assert(test_key(key, log));
	};

	for (size_t i = 0; i < 100; ++i) {
		test("ssh-ed25519"sv);
		test("ecdsa-sha2-nistp256"sv);
		test("ecdsa-sha2-nistp384"sv);
		test("ecdsa-sha2-nistp521"sv);
	}

	// RSA keygen is very slow
	for (size_t i = 0; i < 10; ++i) {
		test("ssh-rsa"sv);
	}
}

void test_pubkeys(fz::logger_interface & log)
{
	auto rfc4716_nocomment =
	    "---- BEGIN SSH2 PUBLIC KEY ----\n"
	    "AAAAB3NzaC1yc2EAAAABIwAAAIEA1on8gxCGJJWSRT4uOrR13mUaUk0hRf4RzxSZ1zRb\n"
	    "YYFw8pfGesIFoEuVth4HKyF8k1y4mRUnYHP1XNMNMJl1JcEArC2asV8sHf6zSPVffozZ\n"
	    "5TT4SfsUu/iKy9lUcCfXzwre4WWZSXXcPff+EHtWshahu3WzBdnGxm5Xoi89zcE=\n"
	    "---- END SSH2 PUBLIC KEY ----\n"sv;

	auto rfc4716 =
	    "---- BEGIN SSH2 PUBLIC KEY ----\n"
	    "Comment: \"1024-bit RSA, converted from OpenSSH by me@example.com\"\n"
	    "x-command: /home/me/bin/lock-in-guest.sh\n"
	    "AAAAB3NzaC1yc2EAAAABIwAAAIEA1on8gxCGJJWSRT4uOrR13mUaUk0hRf4RzxSZ1zRb\n"
	    "YYFw8pfGesIFoEuVth4HKyF8k1y4mRUnYHP1XNMNMJl1JcEArC2asV8sHf6zSPVffozZ\n"
	    "5TT4SfsUu/iKy9lUcCfXzwre4WWZSXXcPff+EHtWshahu3WzBdnGxm5Xoi89zcE=\n"
	    "---- END SSH2 PUBLIC KEY ----\n"sv;

	auto rfc4716_multiline_comment =
	    "---- BEGIN SSH2 PUBLIC KEY ----\n"
	    "Comment: This is my public key for use on \\\n"
	    "servers which I don't like.\n"
	    "AAAAB3NzaC1yc2EAAAABIwAAAIEA1on8gxCGJJWSRT4uOrR13mUaUk0hRf4RzxSZ1zRb\n"
	    "YYFw8pfGesIFoEuVth4HKyF8k1y4mRUnYHP1XNMNMJl1JcEArC2asV8sHf6zSPVffozZ\n"
	    "5TT4SfsUu/iKy9lUcCfXzwre4WWZSXXcPff+EHtWshahu3WzBdnGxm5Xoi89zcE=\n"
	    "---- END SSH2 PUBLIC KEY ----\n"sv;

	auto putty_saved_hostkey_rsa = "rsa2@22:127.0.0.1 0x10001,0xbf5f103cd9e0116a282966d51af73fb7d5239bd59e3e827e86eaec7e9271aa6fca4ba42b27e8d8ceff4615a51af40a086a2eaed85135a65adc807dece647074ca478eb54f42185e8158d3ff441ef8bc2f782ca0c5e2737ebdeae064743d039380009988fba561bfb37a057ab4f9ea1f157c9b9c9ffd5bf3f126fef383cd9bb4644fb8179c47e65f877d6a708c890f4de07e6d82346d2e7de869f5e4b7f1f232830d1ebe80e8e35336fda4822a69c3859d7434c0dfedae5affc8204609908cd01fc26b009a0e8004b3ee3528252a905eefd68d3b64fcf4b7345ab0679250afc5412cce394dc995a86ffcf98f44a3aab4dc1bc4e96ebbbc6500dba8898ba656235719891ae7fe330cd19046bcd397933cbfbcc6043081a0f673a42451b3b05a3dea51bf81761364e1f0939a0810a61e9cf6d12b60e286dffe5c58e9a490fce3556e6ff4d28f23eb1c721206758a5164e8b8dedacbdaf672f861a83761b27d65bea1b5faba0fe606c4fe8561d69685ef6027b52494eb1e68a1d9c13aee30b6e8dffefd2aa20e9d8a55d88e3c05de3cb32cfda00b0dc30b460e716a2fba975f82e949e08a069de7ba93e5e0af384efd97f9460566e2b5ec3d2518c48107c16d40b5506ef29ab472d050c22f1a54efb3e83af95ed6a6e70d2e45a5a87ee63d7fd4625a6f0fcf65738d61b0ad3c700c30bce5c61790b428458b99485a9f4745aac19fd"sv;
	auto putty_saved_hostkey_ed2219 = "ssh-ed25519@22:10.0.0.1 0x6d5219ae5bf8d692914e6aacc9eb958048f08a03cfe31741eb9af405908c892b,0xa957f8eb10d8657f71bd240bcc53866e413b3c09bf85b3a5e798bc3a1ed2a5c"sv;
	auto putty_saved_hostkey_ed2219_2 = "ssh-ed25519@22:filezilla-project.org 0x6adbbc0f75481938057d2a256d3ac827d73398259f77f78aab6ee17bca19eecc,0x3e20468773b5ab55da9d4fc5ab31f8d5b1b58a5a57ec037cde3dc4b221182c08"sv;
	auto putty_saved_hostkey_nistp256 = "ecdsa-sha2-nistp256@22:127.0.0.1 nistp256,0x308bcbdb9651e6dc9e497ca1117f0ce72e572e5e4077f062937d7127d9ee88a3,0x31ec2a5eadbc70451567d148dfa2abbe20d53fc844f57540a7e8ccbb2f3eb1dc"sv;
	auto putty_saved_hostkey_nistp256_2 = "ecdsa-sha2-nistp256@22:127.0.0.1 nistp256,0xf1796b7fea6ded9030921ae1c510260d1ec0850684cefac7b25c73bb79cd4b7,0x18ef70cbda66aebf49f6e898a34815c80e963a87611cc84ff54ca0d2ad10d99d"sv;

	auto test = [&](std::string_view key, std::string_view expected_fingerprint) {
		auto k = fz::ssh::load_public_key(key, log);
		if (!k) {
			return false;
		}
		auto fp = k->fingerprint(fz::hash_algorithm::sha256, true);
		if (fp != expected_fingerprint) {
			log.log(fz::logmsg::error, "Wrong fingerprint: %s", fp);
			return false;
		}
		return true;
	};

	assert(test(rfc4716_nocomment, "SHA256:csG+ujEVjJLZpYPqLUDdw20LVTQMjD4FWsNmsr1etGE"sv));
	assert(test(rfc4716, "SHA256:csG+ujEVjJLZpYPqLUDdw20LVTQMjD4FWsNmsr1etGE"sv));
	assert(test(rfc4716_multiline_comment, "SHA256:csG+ujEVjJLZpYPqLUDdw20LVTQMjD4FWsNmsr1etGE"sv));
	assert(test(putty_saved_hostkey_rsa, "SHA256:fZ0GwkEuogt+eBg+ocohfCkQiF1eqylCRVfT5+//EV0"sv));
	assert(test(putty_saved_hostkey_ed2219, "SHA256:4zPBIPP5d0G4RmGgvZ7/QRn7LUYSLt472+SKUm6HAII"sv));
	assert(test(putty_saved_hostkey_ed2219_2, "SHA256:2uLSBHqs3HX9DkIF1U09PetC394rzfAgE6k5rY3t+Ns"sv));
	assert(test(putty_saved_hostkey_nistp256, "SHA256:gvQRa3NeNDAS9CJB+IxDN1XocqEaKuuA20Mpfu768WM"sv));
	assert(test(putty_saved_hostkey_nistp256_2, "SHA256:D9g2Tam9iS5UhJH+PMA5W1M3L7xeDV/OZJikHK9K/vM"sv));
}
}

int main()
{
	fz::stdout_logger log;
	log.set_all(fz::logmsg::type(-1));

	test_openssh_keys(log);
	test_putty_keys(log);
	test_pem(log);
	test_pkcs8(log);

	test_generated(log);

	test_pubkeys(log);

	return 0;
}
