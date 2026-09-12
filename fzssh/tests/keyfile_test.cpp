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

	auto ks = fz::ssh::load_private_keys(pkcs8.to_view(), log);
	if (ks.size() != 1) {
		return false;
	}
	if (key->pubkey_blob() != ks.front()->pubkey_blob()) {
		return false;
	}

	return true;
}

bool test_key(std::string_view data, fz::logger_interface & log, std::optional<std::string_view> pw = std::nullopt, size_t key_count = 1)
{
	auto keys = fz::ssh::load_private_keys(data, log, pw);
	if (keys.size() != key_count) {
		return false;
	}
	for (auto const& k : keys) {
		if (!test_key(k, log)) {
			return false;
		}
	}

	// If a PW was given, try loading PW and decrypt later
	if (pw) {
		auto infos = fz::ssh::load_private_key_infos(data, log);
		if (infos.size() != key_count) {
			return false;
		}
		for (size_t i = 0; i < infos.size(); ++i) {
			auto & info = infos[i];
			if (!info.encrypted()) {
				return false;
			}
			if (!info.decrypt(*pw, &log)) {
				return false;
			}
			if (!test_key(info.privkey_, log)) {
				return false;
			}

			// By test-case constructions, the keys are different.
			if (i && info.privkey_->fingerprint() == infos[0].privkey_->fingerprint()) {
				return false;
			}
		}
	}

	return true;
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

	constexpr auto putty_plain_ed448 =
		"PuTTY-User-Key-File-3: ssh-ed448\n"
		"Encryption: none\n"
		"Comment: eddsa-key-20260716\n"
		"Public-Lines: 2\n"
		"AAAACXNzaC1lZDQ0OAAAADk7+NM0B3iQQmgLNkWcsll/PyzT8hWqfZyr7/KPZeJ3\n"
		"icN8BcarPA2EvMnR+WrFTAcSqBlZPw8F04A=\n"
		"Private-Lines: 2\n"
		"AAAAOaR50bQBs4OQ3MWzRngokw7rCgXjUFnLv7Cxe8sRVnIMrYuxEpwOJT2dcSjw\n"
		"TdDNAs0Hn9Hh9xHaAA==\n"
		"Private-MAC: 6ff69632b3f5cc003c3a3ce339e0041194b040aa3799937e8f71a23dace54f1a\n";

	assert(fz::ssh::load_private_keys(putty_ppk, log, "PuTTY PPK"sv).size() == 1);
	assert(fz::ssh::load_private_keys(putty_ppkv2, log, "PuTTY PPK v2"sv).size() == 1);
	assert(fz::ssh::load_private_keys(putty_plain_ppk, log).size() == 1);
	assert(fz::ssh::load_private_keys(putty_plain_ppkv2, log).size() == 1);
	assert(fz::ssh::load_private_keys(putty_plain_ed448, log).size() == 1);

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

	constexpr auto openssh_ed25519_encrypted_with_aes128_gcm =
		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
		"b3BlbnNzaC1rZXktdjEAAAAAFmFlczEyOC1nY21Ab3BlbnNzaC5jb20AAAAGYmNyeXB0AA\n"
		"AAGAAAABARExqkQZbUOOeSZywj8EU9AAAAQAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAA\n"
		"IH/X4Rl5DXydD4bVnfl4Q4oiW9oZbtqhcqsCEKUxjUpUAAAAoIJIC1UKWRjk3A6e7bSfeT\n"
		"wH5qZsKwsxj/d9v6egmGhDF74ehgeic/DiTYGPRDD8aWscOGNNJuKDZAtDXezfsH+emKji\n"
		"Rk+iit9pn8WeW57iqVlUUyjZPtA9wXc44Rwr/ZWuk8aWSXBLKIC3t2fl9Vj4pTgaWJdLLQ\n"
		"o3zUn95bbDMRImxVqPCtCUQ2MeN+mkq5ZW5NVDPxxEARQNNgPpq5kIil3DJFjqjVtFMq6G\n"
		"hSHb\n"
		"-----END OPENSSH PRIVATE KEY-----";

	constexpr auto openssh_ed25519_encrypted_with_aes256_ctr =
		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
		"b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCZe2wU8P\n"
		"xcQSrVnyzFj66UAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIP2x4Nm5jT2qG5L1\n"
		"BpCFW8k6KUZbtw/D1sk7C2L1JRVGAAAAoKneMFS2Mos1e48nclOby6aikVKMxtYW6ePZvD\n"
		"aOdwHK+nwhekJqqyYT7dy97tons7KCSbSYKQyRNJuwqF5C9pMalvcovRNTm3NCvWFh+glW\n"
		"1T/BKTxunT5KlSI1+nOtmYgzedpd5wUmcDP8TntTEGVKHjQutZ0pOqle/Wy3nEgrSF79KF\n"
		"RzZWYtVc1IAItIshg5u2qv85diIky6XdmGyHg=\n"
		"-----END OPENSSH PRIVATE KEY-----\n"sv;

	constexpr auto openssh_ed448_plain =
		"-----BEGIN OPENSSH PRIVATE KEY-----\n"
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAASgAAAAlz\n"
		"c2gtZWQ0NDgAAAA5O/jTNAd4kEJoCzZFnLJZfz8s0/IVqn2cq+/yj2Xid4nDfAXG\n"
		"qzwNhLzJ0flqxUwHEqgZWT8PBdOAAAAA4KmWIH+pliB/AAAACXNzaC1lZDQ0OAAA\n"
		"ADk7+NM0B3iQQmgLNkWcsll/PyzT8hWqfZyr7/KPZeJ3icN8BcarPA2EvMnR+WrF\n"
		"TAcSqBlZPw8F04AAAABypHnRtAGzg5DcxbNGeCiTDusKBeNQWcu/sLF7yxFWcgyt\n"
		"i7ESnA4lPZ1xKPBN0M0CzQef0eH3EdoAO/jTNAd4kEJoCzZFnLJZfz8s0/IVqn2c\n"
		"q+/yj2Xid4nDfAXGqzwNhLzJ0flqxUwHEqgZWT8PBdOAAAAAEmVkZHNhLWtleS0y\n"
		"MDI2MDcxNgEC\n"
		"-----END OPENSSH PRIVATE KEY-----\n";

	assert(fz::ssh::load_private_keys(plain_rsa, log).size() == 1);
	assert(test_key(openssh_ecdsa, log));
	assert(test_key(openssh_ecdsa_384, log));
	assert(test_key(openssh_ecdsa_521, log));
	assert(test_key(openssh_ed25519_encrypted_with_aes256_gcm, log, "aes256-gcm@openssh.com encrypted"sv));
	assert(test_key(openssh_ed25519_encrypted_with_aes128_gcm, log, "passphrase"sv));
	assert(test_key(openssh_ed25519_encrypted_with_aes256_ctr, log, "counter"sv));
	assert(test_key(openssh_ed448_plain, log));

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

	constexpr auto encrypted_rsa_aes128_cbc_pem =
		"-----BEGIN RSA PRIVATE KEY-----\n"
		"Proc-Type: 4,ENCRYPTED\n"
		"DEK-Info: AES-128-CBC,C6734A44EA51DA657709D88579674952\n"
		"\n"
		"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\n"
		"-----END RSA PRIVATE KEY-----\n"sv;

	constexpr auto encrypted_rsa_aes192_cbc_pem =
		"-----BEGIN RSA PRIVATE KEY-----\n"
		"Proc-Type: 4,ENCRYPTED\n"
		"DEK-Info: AES-192-CBC,50DB2F18638ADC805C76B9861D0EB656\n"
		"\n"
		"7NF2OG0vgmLKMYNya6H/Gllh6yvGrqRb5QjJgzo5Gm5z73W8xk+9lS0dp9OjTJj/\n"
		"469WdQlhLx4WXcMKCtiVEO7ua20hiu3+yIN6JU2GwBb1zWhEwpO7VqLQu+LltDdw\n"
		"RkVpyzG8GQxbRQlC1nYjDMPUSu/+/ESBC6v8yyu1CQ3RGXOp9HI0oPw08lwkdiFR\n"
		"wuzkWoI3FohkIYQVXIoyb1mj03xbe1edqajQSpwfJLuOeDBOXJBjuHZGc2N2F0ZS\n"
		"HzTHYp+Jn0GfwCkBPpZp0MwQxeqJBu6pnbvUtJahj0Y8R2VTR/e/hNCoCHfPLASJ\n"
		"Ye8VeEPhLYV71hggM21OH1IHzCz2utncLmj6eXtkGx+ZORC7qdYO7EiF4A+e+O3u\n"
		"Wv8+AIj+gJBEVsIU+INUOaZXOr5znKAo1+AiAi5N2NSUlIKC6iNF0lkxLNbyUyBQ\n"
		"75guABcaTnD1EvuEsfVJeUVu5ac0kG2ldRubzwXd77iPxSCBmD3mE2NUul/dcaTh\n"
		"1ozlyROhQRa978S+AfwePXtrOqIlKRVV+BbkA3h1897XdenTDimCm2a82DsUgO8o\n"
		"HHiQp3B5ra9mY3J4bxnKQkBCQxqgjJpJFhnX+JEqrPIlhampJ1/srHIW9phnYoPj\n"
		"Tjngv/JOZ94tB1hRfjB4dM0x4SV1mcgjzbKvEsMNDEPHJabSBXCN2H5aH7/+N/Ca\n"
		"RFWi2EFP+AU4fzfaQBDkWEC4TT2And4bbq3lgu+lKNw+LG0nXGDIIi7IcxV+UdOB\n"
		"6s9VYbysyBwf27rCSFHTAWJHHJMKbIP1sKCbd7lQ6p3suIaltUkTxaVOZ1Q+YMqs\n"
		"N60U6Gx68AXVkQzwwt7kKRbr65L8HGBuloDEODksS12SNeuf2oB2/HIk9IYmbytu\n"
		"B7UZ7eFl9HUhSTlxZZVpA4eR84BNL0R8PQF/Fwel09sIb0ytHUv2MB2t5cJoXLc7\n"
		"Qq3qouhmEH/uWxQZ8GfZNrd0tR9//0HL6nkxcglFBj9nlkj7uk+fv6wjzGd2h/17\n"
		"gPfSTpYNzAelfoVpPq7zd1kf6kWzgz643/L0aPMMQLZh4DOL3DM3pZsRKhCh9YT2\n"
		"PpxrLKvmM8ix179sqYy1gyLU3Ez/xqsX0NRa4r79ztkG9dUjkOlHIDPxysFShkV4\n"
		"1Lu3bUTxWGUHlKVlP/++e+Yk3mB0iTNjXLqQEzABu7zJD6xu+g4N74e9J01tUQFT\n"
		"RbTqKYIlFxhVqy+qbaAUfApTTmIH/4l8EOW9cIltDjd2O55eHYIk/beLiHwurhNl\n"
		"rz6mjE87KEWiYKWHwHo9MQAb203OtfmiG7CYhxiWtjBiJcTKwHj1Yi/onHiBLPMR\n"
		"GUc8OuXB04nISIhG0ZqkkUTASo0RqhtkkJKm5xyidDWz3Bkcwpg4xKFoSsfDl5yr\n"
		"Vf2JBp5d41SfdoN73PByMV4Hz7nlUuYAkLGI4VZM+3CfUGWBMGbYJ7WC5cnpL+FL\n"
		"5dvj75FPv49VoXOQnyIZ7eysr15bOV+8J1AJsuuk39Oke0vH5TMh0vOCK4Dw2z/W\n"
		"/0OWhpMa/+19U8/2WNRgRQjESZsCex2G6pkibkn26PdFAmrpbB8amxutRo7WNZvB\n"
		"-----END RSA PRIVATE KEY-----\n";

	constexpr auto encrypted_rsa_aes256_cbc_pem =
		"-----BEGIN RSA PRIVATE KEY-----\n"
		"Proc-Type: 4,ENCRYPTED\n"
		"DEK-Info: AES-256-CBC,EDBE34844358837314819B6DCB6075E3\n"
		"\n"
		"sLAlSS+TmTc7/7Ytg7CBlOF3IfYZgbmSj3pPEsMMhY/ltBEvCajWpHfB+xU2C5SR\n"
		"lojSdVfl31TcV1m2NaV+JdHPSfXKFJQrdB/sMyVq/G2KLB/PfgdrNPy7RZCwLjfC\n"
		"8ltW8TUie0jov1SkcV606N+n2RXn0SqygZeJf4W/QBmGwy++ElzQKvnrRN45BVQq\n"
		"nyVKAzq1f5GY2pEizqy3P14hAmn5rKl1XXoh6rYD+oSOcJiwIpcMGLwOijeFWaFc\n"
		"e2ZL0YOBGWS/9vW3awIm96B2mxN/M3NjJpYViAFqH2KAOYEEvLKnrizJmQj3Qhhv\n"
		"UPd8+nhJwFl5zw+9LC0lLTIfyzE2yrtnj0yhjrel8A0zsdx+PYvwC9EWQU3kunez\n"
		"XSlioFNKIxFyMiFrcmSyVsI7iVCOlgFB9aSoC1m0iXirBXRhQjXjabYhAJLgk6Di\n"
		"0v3G7znzzMlqq9LjSGLk42wwVBrywa3L/DbOjIgPelvGpbLUBY59EXTCRET/dVGk\n"
		"9qe2x437FfMYKUmtQ0Z7stzSK7bHyjS14bHXbABdRGJKHkj9mYxIOmPj8c2VDNi6\n"
		"gJZ2q9ie34hxMZdjTft+mTni5DrZv9bHtxlEaCmr4i6BdAXoqqo6iPI1yxy300eK\n"
		"sR1wDVRyuLTVlobq+4vmNucSFVI3mc0srn/1GVSDMieS0v9i8BOLNJ+06zrR62nQ\n"
		"N2Ptc3MpWcSnV335w3lq+SGyzRySsnJaxDQZcW93HqxyBQSr8LkkhKEFIE9I220J\n"
		"Wr2YUkhcZNcznI5LilZa1/gyS6Z/yJpRbrFo3ufhe7DpQ7RrZ6XaObkuNrVGiq0J\n"
		"V6GIvQdIFDlXfjXxt7kqWnRekdt3cDQGbicUW4iUu1B9f/XhFuW8gjty4D4T5ZHb\n"
		"/CtqLlq7LkKkMmeu5TnJOOGMOQHS4b8o0bojL0L0LQnuNZKVt3OwC2/xzF2Fyaba\n"
		"kLL5s4AogHMJZXWG6LPQCm5Pxcpi5KFReVjXVTRfjh3keuzwAy9484dxlPSfiPuB\n"
		"3V3hqjj4BBydV/GYDIm/oYd9JlFBNY8cbkXm23Pw8oS2lTfKXhXIgYXUgMB2sNbj\n"
		"XKpAP+TiwVcU+xbzLvflgT+1831o5wGGwF0R3ju/bcj3Q4xxzcck6J90qwNnTjtK\n"
		"ZIjpxcsB/5HKnzVjYX9rbTzkyjqUsJZx9Uz1+zMqIZGB0jNHQ63AzdRcBoIKySMD\n"
		"sgB8Dx8XJbwBr+rYb/Cghp33L0fzx7HF58VTNBbSH6F+OjlCs4ROekxEjwIKS3ZN\n"
		"1g9iwJ5OWz8HLuMAA3w/wyAalFdKKxqIN6/m1umG9vOqJ6D2S6DPUUthL/PQ1Z+f\n"
		"HrRD694ysaIT9H7C8XSvhaszxY9X+UpBtfg6BQnKLtnjJrvwzTcg683rtZV+qiQc\n"
		"H+TPdaOmC5wudOXMO5O4ylgJ81zU7ySst4p6hS0Drv6zpfej/XhXIxyPrvnAJqN5\n"
		"XoNEhiRN/2PY4sXr7EANsJS/iwiZRNhlKRqbyHJpE7195bcdidWBzJ2u6JRSr07x\n"
		"T5Rrbd4/GE0ywJiDG9beqS5k4Nxq/9gddF8Z7G3c0Ip0hp/0X/2mrXzm1eg9oVav\n"
		"-----END RSA PRIVATE KEY-----\n";

	constexpr auto encrypted_rsa_des3_cbc_pem =
		"-----BEGIN RSA PRIVATE KEY-----\n"
		"Proc-Type: 4,ENCRYPTED\n"
		"DEK-Info: DES-EDE3-CBC,CE0500C8821DEFD6\n"
		"\n"
		"k5y4TAV/hRDafK2a+JiyGYMs50QYrsg5K2l5Zt2TLhClZQjsONqdspaXd2WOAwFf\n"
		"g+JeNi6DiuWZhrKoN3L2CglqwYDTK5iwwMveyd7BeH68FzF/UyR9xVlxRZ5bZyrY\n"
		"RzEfRyDgBnkoJATBHR+ggSlRJM27KSxy0v1COclx6c8bEjYajz31rHMGQ0u9IHg2\n"
		"GGwHMJnCiQIIthhUDXeM+qUHtKEQJLm6pjxNjfiHXinw0OP2WJMLl9qhK6uHIhmM\n"
		"jxed6zLb4YB61pnieyW4ZqZWCus+ZyYAzRUeyc7J6nq6G+cE8jif7+zuU2Fhg8Jc\n"
		"YGN7uV8tGSp8cAHgC4qSKvBGPVjhFgoP5VINtQ2EiEKpAuUf6R6zK23TtyoqVDEj\n"
		"/MWxx/WW4ASykg3lpZowI0UGC3pgxKYlkFlVLMRrAFO7N05ndfRxR93tlXBSI1Zw\n"
		"D9cjg4+J85fCdtfrDGFyb4E60CkCxUEtlbhfw+AvcYyRKzWnqjpU7tBU65CG2DId\n"
		"o/PJXfMaa//JkywYy/EG9gaXtcEQcBuon5V1GZZYHknnjT4WZce3R9CKXlKQj7z3\n"
		"XwDSULv+aZaUbNBNR53Lq0mPPXTYRg+rt5+wQOGxZgAd7T9cOLqDjunUVoju5MVc\n"
		"84kY5jBn70ys0i9/h6S9BN7npfAt/GGc5U6pPOz4IqKuhnQ89lXs0r05/y/oZoQo\n"
		"dBTSXbqFby6I2fgyV0zt7T3U+5TohRgdrqv5S6JE5RqChS4glwMM+ByLMwNPf/Mt\n"
		"H/V6gxG80LLxJnt3Wa0VDBeQ5KvbO2Nn3Afi1ZC968EL1vVdhHGwyF5aQNJH3wuX\n"
		"vrU8xSomW6Qfnig/rD0nDjZOlUi0WTrvLHjRvI+1ePreehPB91LHs+yiqB2uGwd/\n"
		"I4J7ESDQWgsJO4wco9fItkXcoRDCkDx2LZJeWykCjSvIAei4+aKPIS9qMr2542f2\n"
		"d+kM+fS8BZBvGRF9YXVuvzKDVxpBs6MCzNk4eOmCVylkVCqEeGViigEeJpBz1TKG\n"
		"WQTrK+iTTyfRrMNu0w8K8rJjV3SqLkACs5CRcw6kccSLj7aVbcROy1/wX5yoK/t6\n"
		"1ONVZCR1H80myi9uUQoBGczCrlDG1V3noGLUlfFg4F5suMmwYrds0mzmWd3NbhOm\n"
		"rRTSEZV7kouqM3iNos0JWe40Vbmb9XLWAqkpUvk2xhjRk/RPk0xlSoufJE4/QXfJ\n"
		"+2pRAkXrdfFFD6692OUACuYQSjggNcQeYz30h+VnMM05Dp0MdJrxavV4EUTG7HvA\n"
		"iRMKSA4L3SrjuwAH3DSt+Ezuv6BJbUKAHqwmfJDFR/11OFg+JKKJL0vLKizViv1f\n"
		"3Zk370wLHJEYwNM4D900AY2+2EuuWuEDv7k5EtQfk1IPDkXtaeaGqCqExKLM7+xf\n"
		"YZVlwHYy/k4bdh1naB2lKqwtL5TVPbAXmcMlyvAKO87nahzuESfE4XNE1DwnuVk7\n"
		"TkThabaCfDGjpfyqal4PEsDX8OYfWwyK5HcDl7Gz708Iuk3xEOGretgzSHnRROFl\n"
		"padDhbLeZNf0kZKtwof+9/y6h1y8RsD2jMTG+Rm5vi3NQTFWaBJM3JSU8V1aMPWX\n"
		"-----END RSA PRIVATE KEY-----\n";

	constexpr auto ecdsa_pem =
		"-----BEGIN EC PRIVATE KEY-----\n"
		"MHcCAQEEIFZSp0O5Nk/mDIhBB8VJPrJLRORfpg5ZG/KNBWFkTWJpoAoGCCqGSM49\n"
		"AwEHoUQDQgAEaxw3THPfXKpCfkch9vFYSdhJPJ3chF/h8vJX3fDpj2cEQo6m6/G+\n"
		"wu+PmbSNpLE3UGwQgw7K+Kh7QotfJdFnag==\n"
		"-----END EC PRIVATE KEY-----\n"sv;

	// No ED5519 here, it seemingly has no standalone non-pkcs8 format.

	assert(fz::ssh::load_private_keys(ecdsa_pem, log).size() == 1);
	assert(fz::ssh::load_private_keys(plain_rsa_pem, log).size() == 1);
	assert(fz::ssh::load_private_keys(encrypted_rsa_aes128_cbc_pem, log, "password"sv).size() == 1);
	assert(fz::ssh::load_private_keys(encrypted_rsa_aes192_cbc_pem, log, "testpass"sv).size() == 1);
	assert(fz::ssh::load_private_keys(encrypted_rsa_aes256_cbc_pem, log, "testpass"sv).size() == 1);
	assert(fz::ssh::load_private_keys(encrypted_rsa_des3_cbc_pem, log, "testpass"sv).size() == 1);

	auto info = fz::ssh::load_private_key_infos(encrypted_rsa_aes128_cbc_pem, log);
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

	constexpr auto ed448_encrypted =
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
		"MIGzMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBDPfGSWjiN1+B0Wxlg/\n"
		"JAlgAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQjwj5p8aPV7dEShi3\n"
		"do/JNgRQixVn7XBzk6vIZUQHkV46ZmJW2Qbtvo0KCllJC/HF/1AyXAmHnX4AdzQm\n"
		"fJKSdrbUjX7LH8IXva4NDuXkdZM/ZNknXt2+6b4wog6q3HOBuYs=\n"
		"-----END ENCRYPTED PRIVATE KEY-----";

	constexpr auto aes256cb_hmac_sha1_encrypted =
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
		"MIIC1zBRBgkqhkiG9w0BBQ0wRDAjBgkqhkiG9w0BBQwwFgQQSDjYm4IspiGdtTSw\n"
		"PV6ndwICJxAwHQYJYIZIAWUDBAEqBBC5FsJDpynDDqKmEVte1MUABIICgMqyJGfw\n"
		"ssz/BX2qbPwuAhmnxUPtpGo+BenZZ0uWTaEYdlRS6XZw4cw7ns/kdH2Hs8R6qtm/\n"
		"+v4LrOMaqgpLEbbblQQSY2NZAHdAfRT5HEDQwAbMnQqhbd7aM27iZW68SNj/SVPU\n"
		"+OhEhS85gjhi66sQMDaSYmlBQ7EfohfWQdG2Rjf32N9hvTmogg7cV8jysHivFWvc\n"
		"eLzApFWKJWZSR6yGDnb90uV990ccf5gOkk9fUxb97/NS/xGrYtEydmL9lpYHEnML\n"
		"7j4c3VCJgMlg/Jf1nMvx8lzMaLtIw9nn518p/i7NlvY9Oh62xwPt7aqA//UchR5I\n"
		"z1BZOyqmqiwyIM+riJ4S7s2BdlP07IzJEAYg1LpuHxSndx3QtaSF3Z7SZXjuz71z\n"
		"Z4cRc8q/J9w1TEdJNeytMITjF9B7EdKJz3jeNaWWXvatUU7JaWZ2q25URJhLkcRE\n"
		"nYjl/vTlazosI//shrEsOv1C66BAjLe3xtua67iG+yxYgth9Nro4gOsgAl/Sg1Sd\n"
		"V1DauzVFbRVnS9cfZqkI8KtAJxZCQBZUsKU4isx1efTx8c6pQ9dt/6auYitPnUag\n"
		"nkdbYV40eJiSo4ih4z/q5JXvyzOGJc7/m4WKOOoJmKBG8BxTnSjrsEihZErFVBWl\n"
		"SmvBrZaYLqALlreH6Bp8Ybr2gg4RM0RYjsjdeZO0CrITfhsKXbo32PCNwkhkj0Sw\n"
		"Ul0MVmXzbSf/AgU4m4e3NzqNctmLgIYV2HV+fpkGFCymgOQWFCzc8pZ+/TO140Kr\n"
		"wd2d/awaz3iiPXdj5lJy+rUFD6NSgw3aIgZ2gCm5rTxFjwqcqKKxmwdQT2p1A5gO\n"
		"EJGPj5POx9w4QYE=\n"
		"-----END ENCRYPTED PRIVATE KEY-----\n";

	constexpr auto aes256cbc_with_optiona_keylen_encrypted =
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
		"MIIFODBiBgkqhkiG9w0BBQ0wVTA0BgkqhkiG9w0BBQwwJwQQn+kAghPA35iwp+Mk+ni2Jg\n"
		"ICJxACASAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEKDt7nVjqIKbBctnkc3bnlYE\n"
		"ggTQzNB9bou39Tj7wkB8/sEmtqy2+0jQXizePPLyMzlJFG8S6oMmyAtn3sVWip/Wy6LWIT\n"
		"uW7OdeUlBBikfvtlyMYtBFcVLaO4tVbVfNmUVZrXGBFsEsMXORKMQuhErcprYep6Eqs9CQ\n"
		"d7BqMDEFnyl3VftOzy74V23Klg17qJOTfUz5Jn2j9ZBgRzZqKx02cRzxz+S3tumszN6KMK\n"
		"8OeSkZKaHEsCf6AYphfKQjPd1MkyMoYxpcrhN2FryLeYRek2LnK6uPhgcLu6OjHGv/0xPb\n"
		"tcgdV5u5rc4JzzblfEKCAGyyk1DAEH6gQSWI4r30WUeRIh3PaUjoC6MKZae5Zg5vZEG3x0\n"
		"SE3tUC9mCvUTW+w+lgYP3L0CfF7JIANV96yQfv07FfkPmjB1RSfvTAZsIbbMmx4HbBrM1z\n"
		"+4MQ70EPAXLpPldB6wH7gipWXOd1mSDzY9OlYdzxWQZZDfmZq/+gVvsMKW1WnWYj78isJ5\n"
		"DkHUIyUuqVxFS7dLcXDC0S+OAZnzzrVNayhdQH9wHSzZJ3RoH+8mwYhuOULdILnxqZa7e3\n"
		"6P6JxsDrrtBmtWLnfVI2A7aa4kMhbGMMtxaW+AsKNv09gz7ZlyYk7EVPfbDGVlSzfaL/Ge\n"
		"vPKflPYHnBG/jJcTWsHbIbXWvJqekxdRXF79SJODTWlohnVO5nL+1rsHzgtgEuKY6CSxq/\n"
		"FQdqVABdqbARGYmfwtAOoIv8kW8O2WiYk80epkgZDx7Z8VCm23AjuZjIRh6Q2901Zt6kV+\n"
		"NX2wr9XxTN4QSRlzRY4COZ/vr3G2ItFEYIAoZlNq5kLw3dZvu1wu7F687QQQez88xoQ349\n"
		"m0UP+SVcFVLsYLvH2R0rwVIQ5ZcoqlsZp0Ipm5f2gFsagNFDgvn9uHUsYIZd2vmwfVVuSR\n"
		"psiPmhAj31906qWaDe7I5H8grgdRA3fUHHfJnqe2RxSDvRASIUj9i2TDI640Olm/wpZPbm\n"
		"ZRolwHkP7B9t2ra3mP5u/SBNl4ow5Bkvi95P1KQ5TrU0SC3/SPWK0FWdaYyfzmpwNzxpPS\n"
		"Bhox1MCTTfj7dhWpLv4gGzjvSKMBZ7HdduIdN7OSCqWoQLZR2PlZ1bATZQP+t8sOvcqZ4G\n"
		"BJa/cSIdvcBidTGSbfRyDCQDmJnXr/mcqk4jA2dbDSZJGnOYEoHCc6Bw33IkKW8svITosH\n"
		"MW+qmR+20ZUQKNuKA6XXKcINvj89LwqCAPEVQc4IS/VDgl43c2i5w/xDpZUy+IsEjg6fu2\n"
		"i8aItvbkxH2u18tT+4aLqviCIF7On49avJNXUwhByu+drN4KD6tH2puWos4rE4HL5EtHx4\n"
		"t8A35ro5Z/RJDXjzO+y6x/HoHbOX8lYORZsFz33QCB8Z8JFZj6epixBzyKkwahmnnacRkM\n"
		"dE9xmlGFjfdcMFwB+7kspCGK2yJd8cHRjzy+U5mEXxASvnBIq2jufwsOyZxkwhaREd9RpN\n"
		"g3hfS+HXKmq+3I+GcbYJNqO+lalPnNQrf9zbfLBfZSVrv+xcZjNx++GeLF7rEnDDciJcVA\n"
		"HhEOhsm+05BDauHoXjOV45Hx489lPMxcKPdkTy5BH8ZcfAKetWChFgwGeABVlnn96doVzv\n"
		"WiCwQk8oxfvIGyiRK1hSx91ydXccjXS3icsQY=\n"
		"-----END ENCRYPTED PRIVATE KEY-----\n";

	constexpr auto aes256cbc_hmac_sha512_encrypted =
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
		"MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQLoYhJMTTQF1KO8BL\n"
		"KEFvYAICJxAwDAYIKoZIhvcNAgsFADAdBglghkgBZQMEASoEEC/Q+J++Dse608Ye\n"
		"FWKPe1MEggTQvsUDNqFLXejMyDnmJ0FR1c7nCu97xef76vre7+6/bWJuMuptSq/M\n"
		"lyJiUg/cMTNSeMLCD9E7QxXwseY2KQnosneXDB3e7aJrcmYav1bSI247haDNlkG6\n"
		"IN6e3b8IFt2igrfj7dAAWvwJagkd2eZgHuzraVHPLWXKtMJY3H4p5uoRJ6ZBRfNF\n"
		"7SHCX+gw+5+YepFZVqUuOiJwNRL5eZj6lpjpwx8z0gPbERzTqE4MXCf4WA6mJiqA\n"
		"8DaW4AMAJFweWTeP0rBKj2EytrsqSO3b3AlXZYRO7vhLKr0xOQQw2A0jOhnlqVyy\n"
		"+PHS3kx/OrV06JB24xlUs9cjKYoRcTaroFOPwo++cGTmnOM6yDL0Nu5tL3E8QF/5\n"
		"SlEpEzUF+mpu1Zu/uXfWVunNxJBieGdvH/cdaGqBnximptAURk9qkH68BXG4wCFi\n"
		"ZXDGXtSLNvuyUUkPppkee8zrTfY7WBVDLw8BZzItQRRS1vQ5GQ/dClQVb+dmhbVz\n"
		"LMfZ5u6lUFA+Yt5leaJL1z8JpyROHbX2ni9J8gW82Alwb/XjN80jKxT2kn9h52CD\n"
		"1LVfxjhlLQpt2KB2EA8p+Q1Q9GiBoTim6UCSWPisABelDrOgsmpP1hLMxnMOzkCt\n"
		"JLFUTsfHc0IGUkbkaR3Cs6zPjhy7gV4tt1sIzV9TgZi5OoHqGYj8RNOWBHi012KM\n"
		"g1Nt0vJ4R7C/jF5KthxA0bhP2KAtoCr6JVDVZFn9BGp+Nb1uyibS444Hk7mQuCjM\n"
		"wP2vLatoxqiJDMKunJibcvOnxRKn1+qU+b+3chHu52p4cXS8ztReSvbcVm7a0QDz\n"
		"m9oagf5Am9gJM5gVdUEpURoWGO9dyBGH+HyQB6RyG70QmGBbiJfDoIGF7sSeqKO3\n"
		"k4Bk7NgP4X2PohkZSkL5X+CNm52V8kCGeeVfrezAUUYE8f88eNHG/kJofokwXsav\n"
		"Zfif9pP3Df/uXDf+YUdcFQ0f9mW/MRD3wyCvXVtpkaSCx3dV6CimwQOEkjVMeV9I\n"
		"J0jOe8T74Z1UfleUteH3dpy7oQsevxr4w74FJQZ2KreFjj9rPnldbl0sVi9FE50y\n"
		"DT0PyAdh9oRDouhwjRCAjqu/ruCQE5/ohGQHSXfWgHQ6VxX3MocVq6DXKvJZwlhS\n"
		"jzOhSNYikJBpccyFKsGAexpfCKeOCCS4Tjrn9ik62Fz8yabh5M/jFY4spnaZUTX/\n"
		"WjqQu2CwpjUVwEES3i2yLEZAoALoZzDQJMiUtaqU1KZd/78TN68lg3nq3nPUSre2\n"
		"F6ED67P1D50Lf2+/pRMgWiZ1if1DHskStrj36PYJuzTo8OfjOiUT6bsKbYbCNZzt\n"
		"4q7nLQlKnT37edCB0cDur1nGTb340HIpKh8HfssBGRYkjw7SheYrHcmJb6RAReF3\n"
		"Jqa68Y+tm8WKD+PySTX+hkusPa/xR5j66kWPEeVigMblvC+2HCj3oCU7NVu9E4Ww\n"
		"pkJ9cBHaVB8p4nuccHf3qG0kFq/tpxNTKsNl3BDoRJvzgkgzicnt7+T2y0CQhSo9\n"
		"tL5bi8lId+DMgjtA+I21ll1LLga0q0HMNoTTWi0Pjlhr6T37sBFF0tYO8HWVSN7T\n"
		"HWfYJMovlfNMsDPa7V9cvgMJOlPJpv1baDimAxIVTHNdmIj+07YNiIA=\n"
		"-----END ENCRYPTED PRIVATE KEY-----\n";

	constexpr auto aes192cbc_hmac_sha256_encrypted =
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
		"MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQWSqv63bMroNVIYJu\n"
		"PzxtmgICJxAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEARYEEFGavP6a5pqbKpPg\n"
		"R50dBHMEggTQ/cpCkKB71pHKXBSKO7Zhi3/vX5JyVeqakeqLeqZbaqrgHif2Bpg1\n"
		"za0veW3a7YUGxCzjw0NTjX0HMTh03ny0EawJ1yj4jpU1eCFJIm5GxZ8PLJY9X862\n"
		"BOT5O3TT2UHsdQDk2nxRW+laXUTnbE1tlPWRPCtq/D8HjVp6iUX5QUvMdg5vdxIC\n"
		"rbdqKLqluvnZz398RsIdCrE+w5goKMYgx1b7WeipTNYyv7Q+xN4bXJPxR5qLzzI6\n"
		"O+O04pLipV7PEdyMjnAUEplh2nP0/rpUwjKGDFfCJzQMmWkfWMRoCKy2oFt0ntz/\n"
		"9LfAqGCCqZ3fsUmniBO6fW1n8coRuhW51bOiKtwKNFcmWBlmnQAwVbaL2bmudltP\n"
		"9Ro5Xt0n/pmne811slm8TGxuh3prP4joaHDHrlifZgL3/4aASzMMK9Syu7O5qLdO\n"
		"FKwjibuQiU1jfcq/mznB9OHJqXI7rZJFrH6u2+ZDZmpJi4dE9m39NHj+JK6iyPVm\n"
		"i1fHyKNcKOaSF/uX7fSyLTeAobhaQXsLgpq5WX8x69XKKEIAHsMX/bRId8qcmRqa\n"
		"rZfNoThxcQqvQayNbPcRAcI1pUi+FiOldgyeRau1ogPU1IkuR+AjXtqf9kwf0sBt\n"
		"dmTZ6ngXAMed+twMEA0ntIuc2xHiUjQVXPkCUvKxLxqYqYw1bKJLfwdWyYkQHsX3\n"
		"/NSiReQFkNXgvHeSAeTeZnaYBe2R1sHBoNH2O1ZsLZdAnv9apC6vyC09ZKDTlU05\n"
		"ZdyvKSD9LScnEwyGT+Yb1ulUbnycCXXJC+5VH5UXlglw7UOwIeHNqC8tdohFrMLL\n"
		"uy/06mXyxqo0pqwxhWLXR6OFFzYTkZ/s615GttqSDFsBn7wBBm08nwbe18q7tEE0\n"
		"b6/a2WD+MEc4Jq0L9bOejp0QvPXbtP5J3/Bg/3F1JSNbdT+UDW5TufbuA7iLpo1A\n"
		"KUdkISqo8AQcaCk6TK0bvRSDn18xaX/nfDGotqiJYQqJ6vFWDNMLg6vbfMNrPukS\n"
		"T60SrXfpZhLZNeK7jps2cljzaeWGa0kxyopjJMQDJ4Iq9NJ08bkwWygXB2O0hDIv\n"
		"zyiEsthDv7tv6hy+k8eTxM7csgkMrdgYfLrxrnNcEVJX3lrDwSV2wrZDhO4SP5tP\n"
		"eh2/ySJW6BPH/ZeA9sjHsZmm6f72sJGOVTGmo6Qgocxfx0FUNMPvbkN8Gtgkvgzz\n"
		"UrmAG+V6lR5EyX2ZSef3IH1eeRb9EDL98x0einDZz4hjKybhuHCNvsudwygZfFfU\n"
		"3RNPEyCWeTUpsk3AFJrWW+SNnimCRQub8DIvU+DXIo8J8C+Wl0KfKE0uOF729q+P\n"
		"D6Y0+O0ApN9dFf4Q9AXaMb1K8LtNYmXf0Ta67bxi/En5k7M9Iwe5KOFNOU9AVHNT\n"
		"woj5Btqz0sGHlcBVwo6s9xQ9wFHPTJc4g12GN+g6lnpyqkO/hH54R+LM/lYIR34Y\n"
		"B2Zm1/4+kzb5pIARvXuF1FH5OYzkdIciaEdPOTXejq0Tk8lWLOTGnqT1RwsCUaJ2\n"
		"XDWZA69TN8Ndz/0S/MDk5nJBSYK0ZJTCaj75N00usrOaPKEYmb8PcoS6wojvuZRF\n"
		"7MvGZj1HbPhAWG4xaFAqf2IND9BDd/9FAYr91OQjy2sK6nCyEqQIDww=\n"
		"-----END ENCRYPTED PRIVATE KEY-----\n";

	constexpr auto pbes1_des_md5 =
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
		"MIIE6TAbBgkqhkiG9w0BBQMwDgQIsMk9mzwuCeACAicQBIIEyL2LqjsMs3QjMINx\n"
		"Lo6pDcofWo/kfRF/U0s1pwQMbTsKlQU48LYZ29zQwPwaYjyyuDokcYVGhuZwp6pB\n"
		"u864fFloBN4AgrCsv0Q4TvhBtRNbudrkBoEhBKSHlaQB36omek605zr2lVK/BhUe\n"
		"9YVm7pIR4GpOpnZVtDmD13ZigdbhvcKvTZ1fgXpJMi14Ad3iBnjI/8661uVTikzf\n"
		"1yGqj/L2tqR+vi9nUspa5d5Ufk87qCWwtqghFUgGAK6HS9v/gmqLPddjm9tzvNak\n"
		"Ns9jxO0bkE17bGfucgywnyyOV8nyjKob9N0VnlHqUgd0Wtc2tyuoYAoIYCWKQwRv\n"
		"8UXXz5HIADOSezZYrotENEIiC7PtP9S4LYibldf7IwoXoFL175x5mPYg1kWj5C5b\n"
		"wTP5Wl31Ud1sD9MX1kt+LaTWRolagzzro2gYF1fR7c6TMNhH0yGuzweq95FZfjsi\n"
		"ZRoL47naUsfAeFLfCg6HGOtuPw1ff4kFGczBgH8wbmgCaPPukAMcLnH1dQ0lHs8i\n"
		"QS9KdHO58l9W/hhlQYS1s7jgjHwJ8PiyHNquVHpbqvlvaPy2/wmbnUcPxR0Amaq/\n"
		"Lj/7BAhmHQLUVAbqPlxMLIFlxUy17ueAlolTE2ovy+46lJZKDHyUy7jYa9qz4/FF\n"
		"SQL3ng/x6QFQvs+D3Dgzm3Dh+NuTWT7sjNZhQLzE1f/yWXPh8T6nx9XFCzjMnWWO\n"
		"qiqmEWkpajGgMRMO/D47s/EGGxdoJsgx0emLMS/L3WSZjwpsCJ6Bse61Wz0TZozo\n"
		"6WxIsnxNYZU8matBeSuiToAAyueRl1fwowFTV3PHZvb0BqRCFgvOWv9+t61+vg+n\n"
		"xFiQnDxYwjoeRqazMH2cJ4B2/7JklDp7Xd+/Sxs3xerZdHI/ytbZOVpNTfwbn58o\n"
		"wlgQMTL/4RyriBOv2GDvTN3ROIxdGn29wfPmjO4bZRxIgZMs7VXS3QR7qaz7QQi8\n"
		"p82gFn9icuqT6p7bRpwCe3oZ8ebcg+vDepf2gH3MXS2ATadI4mTkuVsJxxw9nNHl\n"
		"MLmRyQvRMP2hUve5RcFxPZy0qfxgV3P22bdWMvaRUJznpF5It3n8yCLH9mEzES7K\n"
		"akeoCV8uGmQbZiKz+ldh5azmGyQ86GV9UQ0jHx0ckhluPyDn0fzw6baXHtA9Vj0p\n"
		"urr/nkz9zBllCMd7CWiI2kv0qgXTRg7ISfNvDHnG7VIswokN4JUcW23LRM0fWymZ\n"
		"qkw72Y2ZM7nccpgsJfOkBhdLpmHTdAQ68JhoByGEQzAeI7368nPF3UIaKE+MW3pX\n"
		"sv3PNriVb1bcUP9r/3W8EbQuf3CosOZATVqOiLzqLnB+wy6aSrEXW1FCJNUqYz9U\n"
		"TwHc758u6nJmoJdYCr/UbXVC6Sol282eVtcipbujlDW05C2+Nbq5c0yoA5KjeESX\n"
		"IbRkq6ApjHs0gHG3LnrmXGYqnb/fyrkXeb/85FAWjsQ4NgafsBoX6RJJVknqe3gI\n"
		"Qq8SadgdVT7RUiOCN9PvCs8K39ZoOigvNbUxrwltmDtlTko2kTT5EmJztwBTfgXM\n"
		"50AUGTH/zYmVhZkOrxAce/S5qVkrz8V238YpC2TEydq2WEJArsqQa/Gmo9m64PrN\n"
		"Kr/In7P/ajWiJn/Yrg==\n"
		"-----END ENCRYPTED PRIVATE KEY-----\n";

	constexpr auto pbes1_3des_sha1 =
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
		"MIIE6jAcBgoqhkiG9w0BDAEDMA4ECMT9dJyjt7StAgInEASCBMjzyXCWEk1lcTwZ\n"
		"QmkQFY6o66VJCi6dEUig9Zv+w6G+/V2zj1Nm02CM4C6swoemS9n7AMn8xwDFyAjC\n"
		"9xqoHe00yDxFum2snWhHQ3UmqTISBkksWJz6Rsaw2+GkBv6v8KyD8g9ED4A1Ymrt\n"
		"UZw1rBrVJyL7g3wW41AzspAWwZEYGFrf4ZvFFBbj5zxSUTDHxwq/ilf/ONkPnOts\n"
		"3PcFGl4eRQw0JHy5Lpkjp/LeRr3+wukgTAUI3Tsx3pbiZ1AHcU+/NYp3SQRXgsOx\n"
		"1kkYxxDfD3DdWRpowFwwVrCNaNlK4u7psD8Fy5M/9cfGQYhia9UGe+uUoFMwRBOf\n"
		"/ZgrQi2yzDWCG+G27T74EIf8hIoghlNUAmPreQbJH8AKls9ITkpGJZ7JmAph44lM\n"
		"Fx379bbu2n7sAA76OsZTaH6DziQweb+uYA+PKY8TMS3WLPoU7XD4QHx2BwmUS9uq\n"
		"Gx36kxPZw7v7eSw8s1Lz9D/NOKRI5af4C4b1mgTvxKQ9Lijd5ii/47DO1bsT63Wv\n"
		"utwRTeu8EWCit/6skvUjVNjYrivqEjE2sXkEXpHPzjRJTp2G5XJEq5fU/BKTmbsP\n"
		"W/XRVui1YeIWVfTBV3fDbWMJEex5bxcevq7TD7aiII1CEymRnsEb7KjX/CKwWIZL\n"
		"8T3HJZ2d91g9lms/Ofs4CRgmJus/XUUxl1y1OUvrjhkZW5O1GfplfycuPjR9GZsQ\n"
		"QSXXwLHbbUA5sPa7PsX+e1zyCMfew2A1ZX1Yt8NuIJuwBe7ER5Hw0sZyQxEFG8vO\n"
		"tvFy5ftkH9MVjma9YahYqzhNALoO89vp+XvY2IBMEalLrM2+aVP3Soz5q5sObHUs\n"
		"LaehlFyQK8kBqFcqhy4DUJym/eBOwzIIuZjhsKh8Ga+uqEro3GBwxzAfNbDM66vJ\n"
		"Ctp5+ApjcxGZz1dMjpId/xUOkpeKS8BIbkdoVN5JGkrXmb3JelX5Y4VVCIl5wMZr\n"
		"0w/JqffXfWwrpOjJ+FKv0VaE1fCLKDBZYrIsr7qDYkDovXO4BE4DTZDGpVW0ygI9\n"
		"c72wzycnHPWWjqca8Uvfbl6qa5MrhmtAtZLK1WmZCr5S8J560ybl2E2RS46WOmA4\n"
		"Nz8CQGA8CAKMgCTK+w5brAOL3F9FQyikimFJ3t68tpS+WjbnFKD2go7rG47PfgZs\n"
		"FPZcp64bmYQ+GshV6BlO2F1FxlBxON/b68q+bEX6/DF3sUnYZQNtvVmaE8wRiu0G\n"
		"PN6K55szYcLWMzQFnlnYKoIpsvL+cnrGc/c7nF1v9foMHDxf+bt0K5H4cJ39ur1U\n"
		"TlDHIBXvAS75/EnP1SUst8MSPolelo1fxU0kxsJC2P3vCHkKq+2A1rIR6Z3aHBmw\n"
		"DqaUpfl00lvr/CXLbmPQVkLM1c3Iab65+P65GY92GnJ4hr5Qgty9JO20v5H4n4xx\n"
		"4FzppHbWKGzPqVnomvPCBGibtDppzvk8qadsag+fQ5ZjK99mvd+LfwJi5SqALibr\n"
		"hj+b9tY0EeKWbUPaUwN0LWX1ZIx1tOdKZJsiG9bnb7r/iBZxZiRTN/Sglj2KvSrF\n"
		"02gnJTzCdZDvlnKWePTm8DT1/vpjtwfeJtSRSE6KIfPNaAjGgV171H4kZsq+wMmX\n"
		"9njPpnxaKFes4DUyiHg=\n"
		"-----END ENCRYPTED PRIVATE KEY-----\n";

	assert(test_key(rsa, log));
	assert(test_key(ecdsa, log));
	assert(test_key(fz::base64_decode_s(ecdsa_der), log));
	assert(test_key(ecdsa_encrypted, log, "porcupine"sv));
	assert(test_key(ed25519, log));
	assert(test_key(fz::base64_decode_s(ed25519_v163), log));
	assert(test_key(ed25519_encrypted, log, "password"sv));
	assert(test_key(ed25519_with_pubblob, log));
	assert(test_key(ed448_encrypted, log, "ed448"sv));
	assert(test_key(aes256cb_hmac_sha1_encrypted, log, "herebepassword"sv));
	assert(test_key(aes256cbc_with_optiona_keylen_encrypted, log, "the_password_used_in_production"sv));
	assert(test_key(aes256cbc_hmac_sha512_encrypted, log, "testpass"sv));
	assert(test_key(aes192cbc_hmac_sha256_encrypted, log, "testpass"sv));
	assert(test_key(pbes1_des_md5, log, "testpass"sv));
	assert(test_key(pbes1_3des_sha1, log, "testpass"sv));

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
		test("ssh-ed448"sv);
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

	auto ed448 =
		"---- BEGIN SSH2 PUBLIC KEY ----\n"
		"Comment: \"eddsa-key-20260716\"\n"
		"AAAACXNzaC1lZDQ0OAAAADk7+NM0B3iQQmgLNkWcsll/PyzT8hWqfZyr7/KPZeJ3\n"
		"icN8BcarPA2EvMnR+WrFTAcSqBlZPw8F04A=\n"
		"---- END SSH2 PUBLIC KEY ----\n";

	auto putty_saved_hostkey_rsa = "rsa2@22:127.0.0.1 0x10001,0xbf5f103cd9e0116a282966d51af73fb7d5239bd59e3e827e86eaec7e9271aa6fca4ba42b27e8d8ceff4615a51af40a086a2eaed85135a65adc807dece647074ca478eb54f42185e8158d3ff441ef8bc2f782ca0c5e2737ebdeae064743d039380009988fba561bfb37a057ab4f9ea1f157c9b9c9ffd5bf3f126fef383cd9bb4644fb8179c47e65f877d6a708c890f4de07e6d82346d2e7de869f5e4b7f1f232830d1ebe80e8e35336fda4822a69c3859d7434c0dfedae5affc8204609908cd01fc26b009a0e8004b3ee3528252a905eefd68d3b64fcf4b7345ab0679250afc5412cce394dc995a86ffcf98f44a3aab4dc1bc4e96ebbbc6500dba8898ba656235719891ae7fe330cd19046bcd397933cbfbcc6043081a0f673a42451b3b05a3dea51bf81761364e1f0939a0810a61e9cf6d12b60e286dffe5c58e9a490fce3556e6ff4d28f23eb1c721206758a5164e8b8dedacbdaf672f861a83761b27d65bea1b5faba0fe606c4fe8561d69685ef6027b52494eb1e68a1d9c13aee30b6e8dffefd2aa20e9d8a55d88e3c05de3cb32cfda00b0dc30b460e716a2fba975f82e949e08a069de7ba93e5e0af384efd97f9460566e2b5ec3d2518c48107c16d40b5506ef29ab472d050c22f1a54efb3e83af95ed6a6e70d2e45a5a87ee63d7fd4625a6f0fcf65738d61b0ad3c700c30bce5c61790b428458b99485a9f4745aac19fd"sv;
	auto putty_saved_hostkey_ed2219 = "ssh-ed25519@22:10.0.0.1 0x6d5219ae5bf8d692914e6aacc9eb958048f08a03cfe31741eb9af405908c892b,0xa957f8eb10d8657f71bd240bcc53866e413b3c09bf85b3a5e798bc3a1ed2a5c"sv;
	auto putty_saved_hostkey_ed2219_2 = "ssh-ed25519@22:filezilla-project.org 0x6adbbc0f75481938057d2a256d3ac827d73398259f77f78aab6ee17bca19eecc,0x3e20468773b5ab55da9d4fc5ab31f8d5b1b58a5a57ec037cde3dc4b221182c08"sv;
	auto putty_saved_hostkey_ed448 = "ssh-ed448@22:localhost 0x76c31d9d9fc38b12b6fa45077b005681e1d2f378d427629fa8b64caa832fc01aefee072870528546ba73c6831c329c092ea608605c8d3e28,0xe1e41b61fd3881fcf891c1ebea57d998e55ff58e137aea9d38d6db8d69a49a8227021e454ec47094849500a5b16d429e2b74715e148cc138"sv;

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
	assert(test(ed448, "SHA256:GIXBS6zwSIsjxXfEeKdV3NXeNvpH+D51T6t6lZGVkzw"sv));
	assert(test(putty_saved_hostkey_rsa, "SHA256:fZ0GwkEuogt+eBg+ocohfCkQiF1eqylCRVfT5+//EV0"sv));
	assert(test(putty_saved_hostkey_ed2219, "SHA256:4zPBIPP5d0G4RmGgvZ7/QRn7LUYSLt472+SKUm6HAII"sv));
	assert(test(putty_saved_hostkey_ed2219_2, "SHA256:2uLSBHqs3HX9DkIF1U09PetC394rzfAgE6k5rY3t+Ns"sv));
	assert(test(putty_saved_hostkey_ed448, "SHA256:HSOKW9LTbxZcwGj5QOYZ+Iz/2SZG7i2pSpKmmRrsd/U"sv));
	assert(test(putty_saved_hostkey_nistp256, "SHA256:gvQRa3NeNDAS9CJB+IxDN1XocqEaKuuA20Mpfu768WM"sv));
	assert(test(putty_saved_hostkey_nistp256_2, "SHA256:D9g2Tam9iS5UhJH+PMA5W1M3L7xeDV/OZJikHK9K/vM"sv));
}

void test_pfx(fz::logger_interface & logger)
{
	constexpr auto pfx_plain_nomac =
		"MIIFEAIBAzCCBQkGCSqGSIb3DQEHAaCCBPoEggT2MIIE8jCCBO4GCSqGSIb3DQEHAaCCBN8EggTb\n"
		"MIIE1zCCBNMGCyqGSIb3DQEMCgEBoIIEwjCCBL4CAQAwDQYJKoZIhvcNAQEBBQAEggSoMIIEpAIB\n"
		"AAKCAQEAxsKI7YsgcRMU4BCkmro2+GHWiyxIO2+3YMOqNs682zfLXzZAcmYY3WRxRPJ31ZlAllBk\n"
		"e8cuMTmPAKR4KB0SPLSrNZfUcik60uZ9y2zPv8otvdTBMjtdx3bj6rtumHnxmxDJ1IExQra0IqGn\n"
		"nigWYMfs7Fw6uazQOzFk5QoQCJVIWSuZJDQKlFE/bD+CeDScYRdD8T9WAdsMhhCxdeVPXkMyX0vT\n"
		"tGLKrGN02pX05c+5TDix9eyu9lHM+nid1POQyJWXc4l/U8mObXFje3pG9E31MLX3FqXQglr65jZ7\n"
		"IHqcmMlutPz4g74LbQLbCXSHMy+rfTDpWzjzXSfuCZuYDQIDAQABAoIBAAI2yeLfnfNo0xX5mlmh\n"
		"zMvEiNsHiHb9WjW3RTp5mukBJUPNvAMuihLMnYxWSEprHniaSGE8YLvOgQ+klO/LggaGfhZjavxF\n"
		"svogw9wRS40VIFsY2B9GxWwIwz6j4+hiM5NmRLf8mS8XvKyZAIzaYPn5+9H+hms10lNxt0a7YZyq\n"
		"Tdns/Z65WytS9H+Xte1flICme9REVPOMGB/FNoCMp6T0uMnNh6wAJYsDq7atYVlmK9/21ydjEIWG\n"
		"Yl3MpagvLO75M+2ZaUqtqEAfSugTJ/18I/IUvpOXeBNBbHjaAA0DFQwqP55/MdKdgKYqBLLjULdM\n"
		"V/ROYnG1YiwBsAGw9QUCgYEA5DQNV8jsFgIhLcZTx/DH0t0CQavS7GHZlSDTccst5eDR5/rdQsAt\n"
		"7gnD7DjuUI5nDZfa+fxRoFW4mIgsDpGgtdOuZTgRF3c5Z6aSw1kwlfs0Nkyuo4lT8hNgdmGuTMWU\n"
		"woFPKnPCHPnOAsilolrtSPjnkMUDcIZbyZ/rH2KvNY8CgYEA3vhdCIFtaRGBIuxe13G2wZGXreTi\n"
		"haBb/4XKWckEqZwiplJBhfHHCylKokKW/9vgBWaM53t+5xuCQn6HqcPBuwf7K/E1OBw9/vjriI61\n"
		"crBS0g/nqwHjVaA4TZCQZP1ADte9tZBR0tHafkMxaDT7e5kc36n8Cfofv1IE5OVYoqMCgYEA40/a\n"
		"LqRMTovmgtM4Z0Q3t5pAgivmmWHKu5qMJKCv4nj0ffBMcA5Acgk2KNp4wLNogYjPLg4hPOXGT+Hs\n"
		"iMKU5CmsYNTdaZNwEghBzubL18n3M1Nk7i9/9/VHNASO+5ggWzM1KWNPa0+F3w4At119WR/egj1M\n"
		"9MxRJ+Ds80F4p48CgYAI+nlMkWGlfHX1wQzkogiY7NLtxqy0csuhk3KdgPG2Hrpqdh97VEwOkAAY\n"
		"XpQUA3eW4BVGcPugNMRfBxdRZ7eSX3TmxRS+iKyaas2ZNx3pW15KZSeQBEhyNzxtKygVWPlOX7Oc\n"
		"7w3MbnTc5rnDl3aU+IpoG0Ex6aeDnbriuLWD/wKBgQCsWK1fO8kL4+jjF+K7IVN5or7CEN7ceLOj\n"
		"VdgzS/4PueqfuHyxIju3p6+Ts/ks8GOYNR18iY3ah5Mv67/QJ8aiHNQ0tThVWQy7sPf2Pzkekmgw\n"
		"JYIv47IIKg1OUlY86epABedu8kssqUfcntrVq9tkPrm1rnRn3Mjlm8rAnUn8cQ==\n";

	constexpr auto pfx_plain_mac =
		"MIIFUwIBAzCCBQkGCSqGSIb3DQEHAaCCBPoEggT2MIIE8jCCBO4GCSqGSIb3DQEHAaCCBN8EggTb\n"
		"MIIE1zCCBNMGCyqGSIb3DQEMCgEBoIIEwjCCBL4CAQAwDQYJKoZIhvcNAQEBBQAEggSoMIIEpAIB\n"
		"AAKCAQEAxsKI7YsgcRMU4BCkmro2+GHWiyxIO2+3YMOqNs682zfLXzZAcmYY3WRxRPJ31ZlAllBk\n"
		"e8cuMTmPAKR4KB0SPLSrNZfUcik60uZ9y2zPv8otvdTBMjtdx3bj6rtumHnxmxDJ1IExQra0IqGn\n"
		"nigWYMfs7Fw6uazQOzFk5QoQCJVIWSuZJDQKlFE/bD+CeDScYRdD8T9WAdsMhhCxdeVPXkMyX0vT\n"
		"tGLKrGN02pX05c+5TDix9eyu9lHM+nid1POQyJWXc4l/U8mObXFje3pG9E31MLX3FqXQglr65jZ7\n"
		"IHqcmMlutPz4g74LbQLbCXSHMy+rfTDpWzjzXSfuCZuYDQIDAQABAoIBAAI2yeLfnfNo0xX5mlmh\n"
		"zMvEiNsHiHb9WjW3RTp5mukBJUPNvAMuihLMnYxWSEprHniaSGE8YLvOgQ+klO/LggaGfhZjavxF\n"
		"svogw9wRS40VIFsY2B9GxWwIwz6j4+hiM5NmRLf8mS8XvKyZAIzaYPn5+9H+hms10lNxt0a7YZyq\n"
		"Tdns/Z65WytS9H+Xte1flICme9REVPOMGB/FNoCMp6T0uMnNh6wAJYsDq7atYVlmK9/21ydjEIWG\n"
		"Yl3MpagvLO75M+2ZaUqtqEAfSugTJ/18I/IUvpOXeBNBbHjaAA0DFQwqP55/MdKdgKYqBLLjULdM\n"
		"V/ROYnG1YiwBsAGw9QUCgYEA5DQNV8jsFgIhLcZTx/DH0t0CQavS7GHZlSDTccst5eDR5/rdQsAt\n"
		"7gnD7DjuUI5nDZfa+fxRoFW4mIgsDpGgtdOuZTgRF3c5Z6aSw1kwlfs0Nkyuo4lT8hNgdmGuTMWU\n"
		"woFPKnPCHPnOAsilolrtSPjnkMUDcIZbyZ/rH2KvNY8CgYEA3vhdCIFtaRGBIuxe13G2wZGXreTi\n"
		"haBb/4XKWckEqZwiplJBhfHHCylKokKW/9vgBWaM53t+5xuCQn6HqcPBuwf7K/E1OBw9/vjriI61\n"
		"crBS0g/nqwHjVaA4TZCQZP1ADte9tZBR0tHafkMxaDT7e5kc36n8Cfofv1IE5OVYoqMCgYEA40/a\n"
		"LqRMTovmgtM4Z0Q3t5pAgivmmWHKu5qMJKCv4nj0ffBMcA5Acgk2KNp4wLNogYjPLg4hPOXGT+Hs\n"
		"iMKU5CmsYNTdaZNwEghBzubL18n3M1Nk7i9/9/VHNASO+5ggWzM1KWNPa0+F3w4At119WR/egj1M\n"
		"9MxRJ+Ds80F4p48CgYAI+nlMkWGlfHX1wQzkogiY7NLtxqy0csuhk3KdgPG2Hrpqdh97VEwOkAAY\n"
		"XpQUA3eW4BVGcPugNMRfBxdRZ7eSX3TmxRS+iKyaas2ZNx3pW15KZSeQBEhyNzxtKygVWPlOX7Oc\n"
		"7w3MbnTc5rnDl3aU+IpoG0Ex6aeDnbriuLWD/wKBgQCsWK1fO8kL4+jjF+K7IVN5or7CEN7ceLOj\n"
		"VdgzS/4PueqfuHyxIju3p6+Ts/ks8GOYNR18iY3ah5Mv67/QJ8aiHNQ0tThVWQy7sPf2Pzkekmgw\n"
		"JYIv47IIKg1OUlY86epABedu8kssqUfcntrVq9tkPrm1rnRn3Mjlm8rAnUn8cTBBMDEwDQYJYIZI\n"
		"AWUDBAIBBQAEIApoTiM/nAXZy/ozyV+aYGVN8lehmyuILy1XN+zs4uVpBAhsGr4rgz0mOwICCAA=\n";

	constexpr auto pfx_encrypted_nomac =
		"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\n";

	 constexpr auto pfx_encrypted_mac =
		"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\n"
		"AgIIAA==\n";

	constexpr auto pfx_multiple_keys =
		"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\n";


	assert(test_key(fz::base64_decode_s(pfx_plain_nomac), logger));
	assert(test_key(fz::base64_decode_s(pfx_plain_mac), logger, "macpass"sv));
	assert(test_key(fz::base64_decode_s(pfx_encrypted_mac), logger, "pfxxx"sv));
	assert(test_key(fz::base64_decode_s(pfx_encrypted_nomac), logger, "password"sv));
	assert(test_key(fz::base64_decode_s(pfx_multiple_keys), logger, "storepass"sv, 2));
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
	test_pfx(log);

	test_generated(log);

	test_pubkeys(log);

	return 0;
}
