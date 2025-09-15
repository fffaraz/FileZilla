#ifndef LIBFILEZILLA_JSON_HEADER
#define LIBFILEZILLA_JSON_HEADER

/** \file
 * \brief Simple \ref fz::json "json" parser/builder
 */
#include "string.hpp"

#include <limits.h>
#include <map>
#include <optional>
#include <type_traits>
#include <variant>

namespace fz {

/// Types of JSON values
enum class json_type {
	none, /// Not a JSON value
	null, /// The explicit null value
	object,
	array,
	string,
	number,
	boolean
};

class buffer;

/** \brief json parser/builder
 */
class FZ_PUBLIC_SYMBOL json final
{
public:
	json() noexcept = default;
	json(json const&) = default;
	json(json &&) noexcept = default;

	/// Explicitly creates a value of a specific type, mainly needed for null objects
	explicit json(json_type t);

	json_type type() const {
		return static_cast<json_type>(value_.index());
	}

	/// Returns string, number and boolean values as string
	std::string string_value() const;

	/// Returns string, number and boolean values as wstring
	std::wstring wstring_value() const {
		return fz::to_wstring_from_utf8(string_value());
	}


	/// Returns number and string values as the passed integer type
	template<typename T, std::enable_if_t<std::is_integral_v<typename std::decay_t<T>>, int> = 0>
	T number_value(T errorval = {}) const {
		auto v = number_value_o<T>();
		if (v) {
			return *v;
		}
		return errorval;
	}

	template<typename T, std::enable_if_t<std::is_integral_v<typename std::decay_t<T>>, int> = 0>
	std::optional<T> number_value_o() const {
		bool constexpr is_signed = std::is_signed_v<typename std::decay_t<T>>;
		if constexpr (is_signed) {
			std::optional<int64_t> tmp = number_value_integer_s();
			if (tmp) {
				if (tmp >= std::numeric_limits<T>::min() && tmp <= std::numeric_limits<T>::max()) {
					return static_cast<T>(*tmp);
				}
			}
		}
		else {
			std::optional<uint64_t> tmp = number_value_integer_u();
			if (tmp) {
				if (tmp <= std::numeric_limits<T>::max()) {
					return static_cast<T>(*tmp);
				}
			}
		}

		return {};
	}

	/// Returns number and string values as the passed floating point type
	template<typename T, std::enable_if_t<std::is_floating_point_v<typename std::decay_t<T>>, int> = 0>
	T number_value() const {
		return static_cast<T>(number_value_double());
	}

	/// Returns boolean and string values as bool
	bool bool_value() const;

	/// If object value, deletes child value with given name
	void erase(std::string const& name);

	/// If object, get the value with the given name. Returns none if not object or name doesn't exist
	json const& operator[](std::string const& name) const;

	/** \brief Returns reference to the child value with the given name
	 *
	 * If type is none, sets type to object.
	 * If type is object, adds a new value with name if needed
	 * If of any other type, returns garbage
	 */
	json& operator[](std::string const& name);

	/// If array, get the value with the given index. Returns none if not array or index doesn't exist
	json const& operator[](size_t i) const;

	/** \brief Returns reference to the child value with the given index
	 *
	 * If type is none, sets type to array.
	 * If type is array, adds a new value with the given index if needed, filling holes with none
	 * If of any other type, returns garbage
	 */
	json& operator[](size_t i);

	/// For arrays and objects, returns the number of elements
	size_t children() const;

	/// Sets type to boolean and assigns value
	template<typename Bool, std::enable_if_t<std::is_same_v<bool, typename std::decay_t<Bool>>, int> = 0>
	json& operator=(Bool b) {
		value_ = b;
		return *this;
	}

	/// Sets type to number and assigns value
	template<typename T, std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<bool, typename std::decay_t<T>>, int> = 0>
	json& operator=(T n) {
		value_.emplace<std::size_t(json_type::number)>(fz::to_string(n));
		return *this;
	}

	/** \brief Sets type to string and assigns value.
	 *
	 * Input must be UTF-8.
	 */
	json& operator=(std::string_view const& v);

	/// Sets type to string and assigns value
	json& operator=(std::wstring_view const& v) {
		return *this = to_utf8(v);
	}

	json& operator=(json const&);
	json& operator=(json &&) noexcept;

	explicit operator bool() const { return type() != json_type::none; }

	bool has_non_null_value() const {
		return type() != fz::json_type::none && type() != fz::json_type::null;
	}

	bool is_null() const { return type() == fz::json_type::null; }
	bool is_object() const { return type() == fz::json_type::object; }
	bool is_array() const { return type() == fz::json_type::array; }
	bool is_number() const { return type() == fz::json_type::number; }
	bool is_boolean() const { return type() == fz::json_type::boolean; }

	/** \brief Serializes JSON structure
	 *
	 * Children of objects with none type are ignored.
	 * Children of arrays with none type are serialized as null.
	 */
	std::string to_string(bool pretty = false, size_t depth = 0) const;

	/** \brief Serializes JSON structure
	 *
	 * Children of objects with none type are ignored.
	 * Children of arrays with none type are serialized as null.
	 *
	 * Does not clear output string
	 */
	void to_string(std::string & ret, bool pretty = false, size_t depth = 0) const;

	/** \brief Parses JSON structure from input.
	 *
	 * Returns none if there is any null-byte in the input
	 */
	static json parse(std::string_view const& v, size_t max_depth = 20);
	static json parse(fz::buffer const& b, size_t max_depth = 20);

	void clear();

private:
	void to_string_impl(std::string & ret, bool pretty = false, size_t depth = 0) const;

	std::optional<int64_t> number_value_integer_s() const;
	std::optional<uint64_t> number_value_integer_u() const;
	double number_value_double() const;

	bool FZ_PRIVATE_SYMBOL check_type(json_type t);
	void FZ_PRIVATE_SYMBOL set_type(json_type t);

	static json FZ_PRIVATE_SYMBOL parse(char const*& p, char const* end, size_t max_depth);

	typedef std::variant<
		std::monostate,                           // json_type::none
		std::nullptr_t,                           // json_type::null
		std::map<std::string, json, std::less<>>, // json_type::object
		std::vector<json>,                        // json_type::array
		std::string,                              // json_type::string,
		std::string,                              // json_type::number,
		bool                                      // json_type::boolean
	> value_type;
	value_type value_;
};

template <bool isconst>
struct json_array_iterator final {
	using json_ref_t = std::conditional_t<isconst, json const&, json &>;

	struct sentinel final {};

	json_array_iterator(json_ref_t j)
		// 0 if it's an array, -1 otherwise
		: idx_((j.type() == json_type::array)-1)
		, json_(j)
	{}

	json_array_iterator & operator++()
	{
		++idx_;

		return *this;
	}

	json_ref_t operator*() const
	{
		return json_[idx_];
	}

	bool operator!=(json_array_iterator::sentinel const&) const
	{
		return idx_ < json_.children();
	}

private:
	std::size_t idx_;
	json_ref_t json_;
};

inline json_array_iterator<false> begin(json &j) { return {j};	}
inline json_array_iterator<false>::sentinel end(json &) { return {}; }

inline json_array_iterator<true> begin(json const& j) { return {j}; }
inline json_array_iterator<true>::sentinel end(json const&) { return {}; }

}

#endif
