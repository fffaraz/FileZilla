#include "libfilezilla/buffer.hpp"
#include "libfilezilla/util.hpp"
#include "libfilezilla/time.hpp"

#include <cassert>
#include <random>

#include <time.h>
#include <string.h>

#include <nettle/memops.h>

#if FZ_WINDOWS
	#include "libfilezilla/glue/windows.hpp"
	#include <wincrypt.h>
#else
	#if HAVE_GETRANDOM
		#include <sys/random.h>
	#endif
	#if HAVE_GETENTROPY
		#ifdef __APPLE__
			#include <Availability.h>
			#include <sys/random.h>
		#endif
		#include <unistd.h>
	#endif
	#include "libfilezilla/file.hpp"
	#include <stdio.h>
	#include <sys/stat.h>
#endif

namespace fz {

void sleep(duration const& d)
{
#ifdef FZ_WINDOWS
	Sleep(static_cast<DWORD>(d.get_milliseconds()));
#else
	timespec ts{};
	ts.tv_sec = d.get_seconds();
	ts.tv_nsec = (d.get_milliseconds() % 1000) * 1000000;
	nanosleep(&ts, nullptr);
#endif
}

void yield()
{
#ifdef FZ_WINDOWS
	Sleep(static_cast<DWORD>(1)); // Nothing smaller on MSW?
#else
	timespec ts{};
	ts.tv_nsec = 100000; // 0.1ms
	nanosleep(&ts, nullptr);
#endif
}

namespace {
// Don't trust std::random_device, it may not actually use a random device. Such idiotic decision to allow such behavior.
// On Windows, use CryptGenRandom.
// On other platforms, use in order (and if available) getrandom(), getentropy() and /dev/urandom
// If all fails, abort(), a crash is more desirable than accidentally handing out non-randm data
#if FZ_WINDOWS
// Unfortunately MiNGW does not have a working random_device
struct provider
{
	provider()
	{
		if (!CryptAcquireContextW(&h_, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
			h_ = 0;
		}
	}
	~provider()
	{
		if (h_) {
			CryptReleaseContext(h_, 0);
		}
	}

	HCRYPTPROV h_{};
};
#endif

struct guaranteed_random_device
{
	typedef uint64_t result_type;

	constexpr static result_type min() { return std::numeric_limits<result_type>::min(); }
	constexpr static result_type max() { return std::numeric_limits<result_type>::max(); }

	result_type operator()()
	{
		result_type ret{};
		for (size_t i = 0; i < 10; ++i) { // Loop in case of transient errors
#if FZ_WINDOWS
			thread_local provider prov;
			if (prov.h_ && CryptGenRandom(prov.h_, sizeof(ret), reinterpret_cast<BYTE*>(&ret))) {
				return ret;
			}
#else
	#if HAVE_GETRANDOM
			size_t len = sizeof(ret);
			uint8_t* p = reinterpret_cast<uint8_t*>(&ret);
			while (len) {
				int res = getrandom(p, len, 0);
				if (res >= static_cast<int>(len)) {
					return ret;
				}
				else if (res > 0) {
					len -= res;
					p += res;
				}
				else if (res != -1 || errno != EINTR) {
					break;
				}
			}
	#endif
	#if HAVE_GETENTROPY
			if (!getentropy(&ret, sizeof(ret))) {
				return ret;
			}
	#endif
			thread_local file f;
			if (f.opened() || f.open("/dev/urandom", fz::file::reading)) {
				// Check it's a character device
				struct stat statbuf{};
				if (!fstat(f.fd(), &statbuf) && statbuf.st_mode & S_IFCHR) {
					rwresult r = f.read2(&ret, sizeof(ret));
					if (r && r.value_ == sizeof(ret)) {
						return ret;
					}
				}
			}
			f.close();
#endif
			sleep(duration::from_milliseconds(1 + i));
		}
		// We gave our best.
		fprintf(stderr, "Could not generate random number\n");
		abort();
	}
};
}

int64_t random_number(int64_t min, int64_t max)
{
	assert(min <= max);
	if (min >= max) {
		return min;
	}

	std::uniform_int_distribution<int64_t> dist(min, max);
	guaranteed_random_device rd;
	return dist(rd);
}

std::vector<uint8_t> random_bytes(size_t size)
{
	std::vector<uint8_t> ret;
	ret.resize(size);
	random_bytes(size, ret.data());
	return ret;
}

void random_bytes(size_t size, uint8_t* destination)
{
	if (!size) {
		return;
	}

	guaranteed_random_device rd;

	size_t i = 0;
	auto misalign = reinterpret_cast<uintptr_t>(destination) % alignof(guaranteed_random_device::result_type);
	if (misalign) {
		i = alignof(guaranteed_random_device::result_type) - misalign;
		auto v = rd();
		memcpy(destination, &v, std::min(size, i));
	}

	for (; i + sizeof(guaranteed_random_device::result_type) <= size; i += sizeof(guaranteed_random_device::result_type)) {
		*reinterpret_cast<guaranteed_random_device::result_type*>(destination + i) = rd();
	}

	if (i < size) {
		auto v = rd();
		memcpy(destination + i, &v, size - i);
	}
}

void random_bytes(size_t size, buffer& destination)
{
	if (!size) {
		return;
	}
	random_bytes(size, destination.get(size));
	destination.add(size);
}


uint64_t bitscan(uint64_t v)
{
#if !FZ_WINDOWS || defined(__MINGW32__) || defined(__MINGW64__)
	return __builtin_ctzll(v);
#else
	unsigned long i;
	_BitScanForward64(&i, v);

	return static_cast<uint64_t>(i);
#endif
}

uint64_t bitscan_reverse(uint64_t v)
{
#if !FZ_WINDOWS || defined(__MINGW32__) || defined(__MINGW64__)
	return 63 - __builtin_clzll(v);
#else
	unsigned long i;
	_BitScanReverse64(&i, v);

	return static_cast<uint64_t>(i);
#endif
}

bool equal_consttime(std::basic_string_view<uint8_t> const& lhs, std::basic_string_view<uint8_t> const& rhs)
{
	if (lhs.size() != rhs.size()) {
		return false;
	}

	if (lhs.empty()) {
		return true;
	}

	return nettle_memeql_sec(lhs.data(), rhs.data(), lhs.size()) != 0;
}

void wipe(void* p, size_t n)
{
	if (p && n) {
#if FZ_WINDOWS
		SecureZeroMemory(p, n);
#else
		// TODO: Consider using explicit_bzero or memset_s where available.
		// Eventually C23's memset_explicit perhaps across all platforms?
		volatile unsigned char* vp = reinterpret_cast<volatile unsigned char*>(p);
		while (n--){
			*vp++ = 0;
		}
#endif
	}
}

void wipe(std::string & s)
{
	size_t const orig_size = s.size();
	s.resize(s.capacity());
	wipe(s.data(), s.size());
	s.resize(orig_size);
}

void wipe(std::wstring & s)
{
	size_t const orig_size = s.size();
	s.resize(s.capacity());
	wipe(s.data(), s.size() * sizeof(wchar_t));
	s.resize(orig_size);
}

void wipe_unused(std::string & s)
{
	size_t const orig_size = s.size();
	s.resize(s.capacity());
	wipe(s.data() + orig_size, s.size() - orig_size);
	s.resize(orig_size);
}

void wipe_unused(std::wstring & s)
{
	size_t const orig_size = s.size();
	s.resize(s.capacity());
	wipe(s.data() + orig_size, (s.size() - orig_size) * sizeof(wchar_t));
	s.resize(orig_size);
}

void wipe(std::vector<uint8_t> & v)
{
	size_t const orig_size = v.size();
	v.resize(v.capacity());
	wipe(v.data() + orig_size, v.size() - orig_size);
	v.resize(orig_size);
}

void wipe_unused(std::vector<uint8_t> & v)
{
	size_t const orig_size = v.size();
	v.resize(v.capacity());
	wipe(v.data() + orig_size, v.size() - orig_size);
	v.resize(orig_size);
}

}
