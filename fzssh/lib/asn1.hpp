#ifndef FZSSH_ASN1_HEADER
#define FZSSH_ASN1_HEADER

#include <cstdint>
#include <string_view>
#include <optional>

namespace fz::ssh {

enum class ASN1Type : uint64_t
{
	Integer          = 0x02u,
	BitString        = 0x03u,
	OctetString      = 0x04u,
	Null             = 0x05u,
	UTF8String       = 0x0cu,
	ObjectIdentifier = 0x06u,
	Sequence         = 0x10u,
	Set              = 0x11u,
	PrintableString  = 0x13u,
	T61String        = 0x14u,
	IA5String        = 0x16u
};

enum class ASN1Class : uint8_t
{
	universal        = 0x00u,
	application      = 0x40u,
	context_specific = 0x80u,
	private_type     = 0xc0u
};

struct ASN1Value
{
	bool is(ASN1Type t) const {
		return tag_ && class_ == ASN1Class::universal && tag_ == static_cast<uint64_t>(t);
	}

	bool is(ASN1Class cl, uint64_t tag) const {
		return tag_ && class_ == cl && tag_ == tag;
	}

	std::optional<uint64_t> tag_{};
	ASN1Class class_{};
	bool constructed_{};
	std::string_view data_;

	bool universal() const {
		return class_ == ASN1Class::universal;
	}

	explicit operator bool() const { return tag_ >= 0; }
};

std::string parse_oid(ASN1Value const& v);

std::optional<uint64_t> toUInt(ASN1Value const& v);

ASN1Value parseDer(std::string_view & data);
ASN1Value parseDer(std::string_view & data, ASN1Type expected);
ASN1Value parseDer(std::string_view & data, ASN1Class cl, int64_t tag);

void der_encode_length(std::string& out, size_t len);
void der_encode(std::string& out, uint64_t v);
void der_encode_oid(std::string& out, std::string_view oid);
void der_encode(std::string& out, std::string_view data, ASN1Type type, bool constructed);
void der_encode(std::string& out, std::string_view data, ASN1Class cl, uint64_t tag, bool constructed);

}

#endif
