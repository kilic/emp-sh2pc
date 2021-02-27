#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;

inline const char *hex_char_to_bin(char c)
{
	switch (toupper(c))
	{
	case '0':
		return "0000";
	case '1':
		return "0001";
	case '2':
		return "0010";
	case '3':
		return "0011";
	case '4':
		return "0100";
	case '5':
		return "0101";
	case '6':
		return "0110";
	case '7':
		return "0111";
	case '8':
		return "1000";
	case '9':
		return "1001";
	case 'A':
		return "1010";
	case 'B':
		return "1011";
	case 'C':
		return "1100";
	case 'D':
		return "1101";
	case 'E':
		return "1110";
	case 'F':
		return "1111";
	default:
		return "0";
	}
}

inline string hex_to_binary(string hex)
{
	string bin;
	for (unsigned i = 0; i != hex.length(); ++i)
		bin += hex_char_to_bin(hex[i]);
	return bin;
}

inline void reverse_str(string &str)
{
	int n = str.length();

	for (int i = 0; i < n / 2; i++)
		swap(str[i], str[n - i - 1]);
}

inline Integer hex_to_integer(int len, string hex_input, int party)
{
	string bin_input = hex_to_binary(hex_input);
	reverse_str(bin_input);
	Integer a(len, bin_input, party);
	return a;
}

inline string bin_to_hex(string &s)
{
	string out;
	for (uint i = 0; i < s.size(); i += 4)
	{
		int8_t n = 0;
		for (uint j = i; j < i + 4; ++j)
		{
			n <<= 1;
			if (s[j] == '1')
				n |= 1;
		}

		if (n <= 9)
			out.push_back('0' + n);
		else
			out.push_back('a' + n - 10);
	}

	return out;
}

inline string bin_to_hex_reversed(string &s)
{
	reverse_str(s);
	return bin_to_hex(s);
}

inline void debug_int(int party, Integer a, string desc)
{

	cout << desc << endl;
	string debug = a.reveal<string>(party);
	cout << bin_to_hex_reversed(debug) << endl;
}

inline void copy_int(Integer &dst, Integer &src, size_t offset_dst, size_t offset_src, size_t len)
{
	for (int i = 0; i < len; i++)
	{
		dst[i + offset_dst] = src[i + offset_src];
	}
}

// inline Integer xor_secret(Integer &pad, Integer &secret)
// {
// 	Integer res(512, 0, XOR);
// 	int off = 512 - secret.size();
// 	int u = 64 - off / 8;

// 	for (int i = 0; i < u; i++)
// 	{
// 		int ii = i * 8;
// 		int iii = (u - 1 - i) * 8;
// 		for (int j = 0; j < 8; j++)
// 		{
// 			res[off + ii + j] = pad[ii + j] ^ secret[iii + j];
// 		}
// 	}
// 	copy_int(res, pad, 0, 0, off);
// 	return res;
// }

inline Integer xor_secret(Integer &pad, Integer &secret)
{
	Integer res(512, 0, XOR);
	int off = 512 - secret.size();
	copy_int(res, pad, 0, 0, 512);
	for (int i = 0; i < secret.size(); i++)
	{
		res[i + off] = pad[i + off] ^ secret[i];
	}
	return res;
}

inline Integer pad_int(int len)
{
	int pad_int_len = 512 - (len % 512);
	Integer pad(pad_int_len, len, PUBLIC);
	pad[len - 1] = 1;
	return pad;
}

inline Integer tls_master_secret_seed(string client_random_hex, string server_random_hex)
{
	Integer client_random_int = hex_to_integer(256, client_random_hex, ALICE);
	Integer server_random_int = hex_to_integer(256, server_random_hex, ALICE);
	Integer label_master_secret = hex_to_integer(104, "6d617374657220736563726574", PUBLIC); // "master secret"
	Integer seed(256 + 256 + 104, 0, PUBLIC);
	copy_int(seed, server_random_int, 0, 0, 256);
	copy_int(seed, client_random_int, 256, 0, 256);
	copy_int(seed, label_master_secret, 512, 0, 104);
	return seed;
}

inline Integer tls_key_expansion_seed(string client_random_hex, string server_random_hex)
{
	Integer client_random_int = hex_to_integer(256, client_random_hex, ALICE);
	Integer server_random_int = hex_to_integer(256, server_random_hex, ALICE);
	Integer label_master_secret = hex_to_integer(104, "6b657920657870616e73696f6e", PUBLIC); // "key expansion"
	Integer seed(256 + 256 + 104, 0, PUBLIC);
	copy_int(seed, client_random_int, 0, 0, 256);
	copy_int(seed, server_random_int, 256, 0, 256);
	copy_int(seed, label_master_secret, 512, 0, 104);
	return seed;
}

class HMAC
{

public:
	Integer iv = hex_to_integer(256, "6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19", PUBLIC);
	Integer ipad_start = hex_to_integer(512, "36363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636", PUBLIC);
	Integer opad_start = hex_to_integer(512, "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c", PUBLIC);
	Integer outer_end_pad = pad_int(512 + 256);

	Integer ipad;
	Integer opad;

	BristolFashion hasher;

	HMAC(BristolFashion hasher) : hasher(hasher)
	{
	}

	void set_secret(Integer &secret)
	{
		ipad = xor_secret(ipad_start, secret);
		opad = xor_secret(opad_start, secret);
	}

	inline vector<Integer> derive_enc_keys_for_alice(string share, string client_random_hex, string server_random_hex)
	{

		Integer seed_master_secret = tls_master_secret_seed(client_random_hex, server_random_hex);
		Integer premaster_share_alice = hex_to_integer(256, share, ALICE);
		Integer premaster_share_bob = hex_to_integer(256, share, BOB);
		Integer premaster_secret(256, 0, XOR);
		premaster_secret = premaster_share_alice + premaster_share_bob;
		this->set_secret(premaster_secret);

		vector<Integer> key_material_master_secret = this->run(2, seed_master_secret);

		Integer master_secret(384, 0, XOR);
		copy_int(master_secret, key_material_master_secret[0], 128, 0, 256);
		copy_int(master_secret, key_material_master_secret[1], 0, 128, 128);

		Integer seed_expansion = tls_key_expansion_seed(client_random_hex, server_random_hex);
		this->set_secret(master_secret);
		vector<Integer> key_material_expansion = this->run(3, seed_expansion);

		Integer client_enc(128, 0, ALICE);
		Integer server_enc(128, 0, ALICE);
		copy_int(client_enc, key_material_expansion[2], 0, 128, 128);
		copy_int(server_enc, key_material_expansion[2], 0, 0, 128);
		vector<Integer> enc_keys;
		enc_keys.push_back(client_enc);
		enc_keys.push_back(server_enc);

		return enc_keys;
	}

	vector<Integer> run(int t, Integer seed)
	{

		Integer empty(0, 0, PUBLIC);
		vector<Integer> A;
		for (int i = 0; i < t; i++)
		{
			// * a_i can be public
			// * after calculating a_1 in 2PC
			//	remaining a_i can be calculated locally by ALICE
			Integer state(256, 0, PUBLIC);
			if (i == 0)
			{
				state = inner_hmac(seed, empty);
			}
			else
			{
				state = inner_hmac(A[i - 1], empty);
			}
			state = outer_hmac(state);
			A.push_back(state);
		}
		vector<Integer> U;
		for (int i = 0; i < t; i++)
		{
			Integer state = inner_hmac(seed, A[i]);
			state = outer_hmac(state);
			U.push_back(state);
		}
		return U;
	}

protected:
	Integer inner_hmac(Integer &seed, Integer &chain)
	{

		int block_size = this->ipad.size() + seed.size() + chain.size();
		Integer end_pad = pad_int(block_size);
		bool has_chain = chain.size() != 0;

		// key = (premaster_secret^ipad)<64>
		// hash_1 = hash(ipad<64>, seed<_>)

		// * input: xor
		// * intermadiate compression results: public
		// * output: public

		// inner compression:
		// in 2PC
		// inp_1 = [iv<32>, ipad<64>]
		Integer inp_inner(512 + 256, 0, PUBLIC);
		Integer out(256, 0, PUBLIC);
		copy_int(inp_inner, this->iv, 512, 0, 256);
		// TODO: copying public data into xor?
		copy_int(inp_inner, this->ipad, 0, 0, 512);
		hasher.compute(out.bits.data(), inp_inner.bits.data());

		Integer inp(512 + 256, 0, PUBLIC);
		int z = block_size / 512;
		int pad_size = block_size % 512;
		int seed_off = seed.size();
		if (pad_size != 0)
		{
			z -= 1;
		}

		// outer compressions:
		// TODO: can be ALICE only computation
		for (int i = 0; i < z; i++)
		{
			// new_iv<32> = out<32>
			// inp = [new_iv<32>, seed[_:_]<_>, pad<_>]
			Integer inp(512 + 256, 0, PUBLIC);
			copy_int(inp, out, 512, 0, 256);
			if (i == 0 && has_chain)
			{
				seed_off -= 256;
				copy_int(inp, chain, 256, 0, 256);
				copy_int(inp, seed, 0, seed_off, 256);
			}
			else
			{
				seed_off -= 512;
				copy_int(inp, seed, 0, seed_off, 512);
			}
			// cout << "loop " << seed_off << endl;
			hasher.compute(out.bits.data(), inp.bits.data());
		}

		// ALICE only
		if (pad_size != 0)
		{
			// new_iv<32> = out<32>
			// inp = [new_iv<32>, seed[_:]<_>, pad<_>]
			copy_int(inp, out, 512, 0, 256);
			copy_int(inp, seed, end_pad.size(), 0, seed_off);
			copy_int(inp, end_pad, 0, 0, end_pad.size());
			hasher.compute(out.bits.data(), inp.bits.data());
		}

		return out;
	}

	Integer outer_hmac(Integer &chain)
	{

		// TODO: we arrive at same intermadiate compression result
		//	many times. we may want to consider store and reuse this value

		// * input: xor
		// * intermadiate compression result: public
		// * output: xor

		// inner compression:
		// inp = [iv<32>, opad_premaster_secret<64>]
		Integer inp(512 + 256, 0, PUBLIC);
		Integer out_1(256, 0, PUBLIC);
		copy_int(inp, this->iv, 512, 0, 256);
		copy_int(inp, this->opad, 0, 0, 512);
		hasher.compute(out_1.bits.data(), inp.bits.data());

		// outer compression:
		// new_iv<32> = out_1<32>
		// inp = [new_iv<32>, chain<32>, pad<32>]
		Integer inp_2(512 + 256, 0, PUBLIC);
		Integer out_2(256, 0, PUBLIC);
		copy_int(inp_2, out_1, 512, 0, 256);
		copy_int(inp_2, chain, 256, 0, 256);
		copy_int(inp_2, this->outer_end_pad, 0, 0, 256);
		hasher.compute(out_2.bits.data(), inp_2.bits.data());

		return out_2;
	}
};

// int main(int argc, char **argv)
// {
// 	setup_plain_prot(false, "");

// 	finalize_plain_prot();
// }

int main(int argc, char **argv)
{
	string client_random = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	string server_random = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

	int port, party;
	parse_party_and_port(argv, &party, &port);

	NetIO *io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
	setup_semi_honest(io, party);

	string filepath = "./test/sha256circuts/bristol_fashion/sha256.txt";
	BristolFashion hasher(filepath.c_str());

	HMAC hmac = HMAC(hasher);
	string secret;
	if (party == ALICE)
	{
		secret = "1";
	}
	else
	{
		secret = "0";
	}
	vector<Integer> enc_keys = hmac.derive_enc_keys_for_alice(secret, client_random, server_random);
	// expect
	// client enc: bb0941a9c66263c9106bab97169183a4
	// server enc: 30e6464281fd14092b1a30af241007cb

	cout << CircuitExecution::circ_exec->num_and() << endl;
	finalize_semi_honest();
	delete io;
}
