#include "asn1.hpp"

#include <libfilezilla/string.hpp>
#include <libfilezilla/util.hpp>

namespace fz::ssh {

std::optional<uint64_t> toUInt(ASN1Value const& v)
{
	if (v.data_.empty()) {
		return {};
	}
	if (static_cast<uint8_t>(v.data_[0]) & 0x80u) {
		// Negative number
		return {};
	}
	size_t i = 0;
	if (v.data_.size() > 1 && !v.data_[0]) {
		if (!(static_cast<uint8_t>(v.data_[1]) & 0x80u)) {
			// Violating shortest representation rule
			return {};
		}
		i = 1;
	}
	if (v.data_.size() - i > sizeof(uint64_t)) {
		// Too long
		return {};
	}

	uint64_t ret{};
	for (; i < v.data_.size(); ++i) {
		ret *= 256;
		ret += static_cast<uint8_t>(v.data_[i]);
	}

	return ret;
}

ASN1Value parseDer(std::string_view & data)
{
	ASN1Value ret;

	if (data.empty()) {
		return {};
	}

	uint8_t const* const start = reinterpret_cast<uint8_t const*>(&data[0]);
	uint8_t const* p = start;
	uint8_t const* const end = start + data.size();

	ret.tag_ = *p & 0x1fu;
	ret.class_ = static_cast<ASN1Class>(*p & 0xc0u);
	ret.constructed_ = *p & 0x20u;
	++p;

	if (ret.class_ == ASN1Class::universal) {
		bool should_constructed{};
		switch (static_cast<ASN1Type>(*ret.tag_)) {
		case ASN1Type::Sequence:
		case ASN1Type::Set:
			should_constructed = true;
			break;
		default:
			break;
		}
		if (should_constructed != ret.constructed_) {
			data = std::string_view();
			return {};
		}
	}

	if (ret.tag_ == 0x1fu) {
		if (ret.class_ == ASN1Class::universal) {
		}
		ret.tag_ = 0;
		do {
			if (p >= end) {
				// Unterminated tag
				data = std::string_view();
				return {};
			}
			if (!ret.tag_ && *p == 0x80u) {
				// Violating shortest representation rule
				data = std::string_view();
				return {};
			}
			if (*ret.tag_ & 0x0080000000000000ull) {
				// Tag too big
				data = std::string_view();
				return {};
			}
			*ret.tag_ <<= 7;
			*ret.tag_ += *p & 0x7fu;
		}
		while (*(p++) & 0x80u);
	}

	if (p >= end) {
		// Incomplete value
		data = std::string_view();
		return {};
	}

	if (*p == 0x80u) {
		// Indefinite isn't allowed in DER
		data = std::string_view();
		return {};
	}

	size_t len = 0;
	if (!(*p & 0x80u)) {
		len = *(p++);
	}
	else {
		size_t llen = *(p++) & 0x7fu;
		if (!llen) {
			// Violating shortest representation rule
		}
		else if (llen > sizeof(size_t)) {
			// Length of length too big
			data = std::string_view();
			return {};
		}
		else if (llen > static_cast<size_t>(end - p)) {
			// Unterminated length
			data = std::string_view();
			return {};
		}
		while (llen--) {
			len <<= 8;
			len += *(p++);
			if (!len) {
				// Violating shortest representation rule
				data = std::string_view();
				return {};
			}
		}
	}
	if (len > static_cast<size_t>(end - p)) {
		// Length too big
		data = std::string_view();
		return {};
	}
	if (len) {
		ret.data_ = std::string_view(reinterpret_cast<char const*>(p), len);
	}
	p += len;

	if (p < end) {
		data.remove_prefix(p - start);
	}
	else {
		data = std::string_view();
	}

	return ret;
}

ASN1Value parseDer(std::string_view & data, ASN1Type expected)
{
	ASN1Value ret = parseDer(data);
	if (!ret.is(expected)) {
		data = std::string_view();
		return {};
	}
	return ret;
}

ASN1Value parseDer(std::string_view & data, ASN1Class cl, int64_t tag)
{
	ASN1Value ret = parseDer(data);
	if (!ret.is(cl, tag)) {
		data = std::string_view();
		return {};
	}
	return ret;
}

std::string parse_oid(ASN1Value const& v)
{
	std::string_view in = v.data_;
	if (in.empty()) {
		return {};
	}

	std::string ret;
	auto c = static_cast<uint8_t>(in[0]);
	if (c >= 120) {
		return {};
	}

	ret += '0' + c / 40;
	ret += '.';
	ret += to_string(c % 40);
	ret += '.';

	uint64_t n{}; // Technically one needs a bignum library to parse OID as there are no restrictions.
	for (size_t i = 1; i < in.size(); ++i) {
		c = static_cast<uint8_t>(in[i]);
		if (c == 0x80u && !n) {
			return {};
		}
		n <<= 7;
		n += c & 0x7fu;
		if (!(c & 0x80u)) {
			ret += to_string(n);
			ret += '.';
			n = 0;
		}
	}

	ret.pop_back();
	return ret;
}


void der_encode_length(std::string& out, size_t len)
{
	if (len < 128) {
		out.push_back(static_cast<char>(len));
	}
	else {
		auto octets = (bitscan_reverse(len)) / 8 + 1;
		out.push_back(static_cast<char>(octets | 0x80u));
		out.resize(out.size() + octets);
		for (size_t i = 1; i <= octets; ++i) {
			out[out.size() - i] = static_cast<char>(len & 0xffu);
			len >>= 8;
		}
	}
}

void der_encode(std::string& out, uint64_t v)
{
	out.push_back(static_cast<char>(static_cast<uint8_t>(ASN1Class::universal) | static_cast<uint8_t>(ASN1Type::Integer)));

	auto octets = v ? (bitscan_reverse(v) + 8) / 8 : 1;
	out.push_back(static_cast<char>(octets));
	out.resize(out.size() + octets);
	for (size_t i = 1; i <= octets; ++i) {
		out[out.size() - i] = static_cast<char>(v & 0xffu);
		v >>= 8;
	}
}

namespace {
void encode_base128(std::string & out, uint64_t v)
{
	auto octets = v ? ((bitscan_reverse(v) + 7) / 7) : 1;
	out.resize(out.size() + octets);
	for (size_t i = 1; i <= octets; ++i) {
		out[out.size() - i] = static_cast<char>((v & 0x7fu) | ((i > 1) ? 0x80u : 0u));
		v >>= 7;
	}
}
}

void der_encode_oid(std::string& out, std::string_view oid)
{
	out.push_back(static_cast<char>(static_cast<uint8_t>(ASN1Class::universal) | static_cast<uint8_t>(ASN1Type::ObjectIdentifier)));

	std::string tmp;
	strtokenizer tok(oid, '.', false);
	auto it = tok.begin();
	if (it == tok.end()) {
		abort();
	}
	auto first = to_integral<uint64_t>(*it);
	if (++it == tok.end()) {
		abort();
	}
	auto second = to_integral<uint64_t>(*it);
	tmp.push_back(static_cast<char>(first * 40 + second));
	while (++it != tok.end()) {
		auto c = to_integral<uint64_t>(*it);
		encode_base128(tmp, c);
	}

	der_encode_length(out, tmp.size());
	out += tmp;
}

void der_encode(std::string& out, std::string_view data, ASN1Type type, bool constructed)
{
	out.push_back(static_cast<char>(static_cast<uint8_t>(ASN1Class::universal) | static_cast<uint8_t>(type) | (constructed ? 0x20u : 0u)));

	der_encode_length(out, data.size());
	out += data;
}

void der_encode(std::string& out, std::string_view data, ASN1Class cl, uint64_t tag, bool constructed)
{
	if (tag < 32) {
		out.push_back(static_cast<char>(static_cast<uint8_t>(cl) | static_cast<uint8_t>(tag) | (constructed ? 0x20u : 0u)));
	}
	else {
		out.push_back(static_cast<char>(static_cast<uint8_t>(cl) | 0x1fu | (constructed ? 0x20u : 0u)));
		encode_base128(out, tag);
	}
	der_encode_length(out, data.size());
	out += data;
}

}
