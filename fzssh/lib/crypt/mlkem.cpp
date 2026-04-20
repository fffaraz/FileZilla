#include "mlkem.hpp"
#include "mlkem.h"

namespace fz::ssh {

void mlkem_keygen(fz::buffer & pub, fz::buffer & priv)
{
	BinarySink pub_bs;
	pub_bs.p = &pub;

	BinarySink priv_bs;
	priv_bs.p = &priv;

	mlkem_keygen(&pub_bs, &priv_bs, &mlkem_params_768);
}

fz::buffer mlkem_encaps(fz::buffer & ciphertext, std::string_view const& pub)
{
	fz::buffer shared_secret;
	BinarySink shared_secret_bs;
	shared_secret_bs.p = &shared_secret;

	BinarySink ciphertext_bs;
	ciphertext_bs.p = &ciphertext;
	if (!mlkem_encaps(&ciphertext_bs, &shared_secret_bs, &mlkem_params_768, make_ptrlen(pub.data(), pub.size()))) {
		return {};
	}

	return shared_secret;
}

fz::buffer mlkem_decaps(fz::buffer & priv, std::string_view const& ciphertext)
{
	fz::buffer shared_secret;
	BinarySink shared_secret_bs;
	shared_secret_bs.p = &shared_secret;

	if (!mlkem_decaps(&shared_secret_bs, &mlkem_params_768, make_ptrlen(priv.get(), priv.size()), make_ptrlen(ciphertext.data(), ciphertext.size()))) {
		return {};
	}

	return shared_secret;
}

}
