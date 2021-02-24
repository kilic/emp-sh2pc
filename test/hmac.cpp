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

inline std::string hex_to_binary(std::string hex)
{
	std::string bin;
	for (unsigned i = 0; i != hex.length(); ++i)
		bin += hex_char_to_bin(hex[i]);
	return bin;
}
void reverse_str(string &str)
{
	int n = str.length();

	for (int i = 0; i < n / 2; i++)
		swap(str[i], str[n - i - 1]);
}

inline Integer hex_to_integer(int len, std::string hex_input, int party)
{
	string bin_input = hex_to_binary(hex_input);
	reverse_str(bin_input);
	Integer a(len, bin_input, party);
	return a;
}

string bin_to_hex(string &s)
{
	// reverse_str(s);
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

string bin_to_hex_reversed(string &s)
{
	reverse_str(s);
	return bin_to_hex(s);
}

std::string bytes_to_hex_str(char *bytes, int size)
{
	char const hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	std::string str;
	for (int i = 0; i < size; ++i)
	{
		const char ch = bytes[i];
		str.append(&hex[(ch & 0xF0) >> 4], 1);
		str.append(&hex[ch & 0xF], 1);
	}
	return str;
}

int hex2bin(char *source_str, char *dest_buffer)
{
	char *line = source_str;
	char *data = line;
	int offset;
	int read_byte;
	int data_len = 0;

	while (sscanf(data, " %02x%n", &read_byte, &offset) == 1)
	{
		dest_buffer[data_len++] = read_byte;
		data += offset;
	}
	return data_len;
}

void debug_int(int party, Integer a, string desc)
{

	if (party == ALICE)
	{
		string debug = a.reveal<string>(ALICE);
		cout << desc << endl;
		cout << bin_to_hex_reversed(debug) << endl;
	}
	else if (party == BOB)
	{
		string debug = a.reveal<string>(BOB);
		cout << desc << endl;
		cout << bin_to_hex_reversed(debug) << endl;
	}
	else if (party == XOR)
	{
		string debug = a.reveal<string>(XOR);
		cout << desc << endl;
		cout << bin_to_hex_reversed(debug) << endl;
	}
	else
	{
		string debug = a.reveal<string>(PUBLIC);
		cout << desc << endl;
		cout << bin_to_hex_reversed(debug) << endl;
	}

	// cout << a.reveal<uint64_t>(PUBLIC) << endl;
}

inline void copy_int(Integer &dst, Integer &src, size_t offset_dst, size_t offset_src, size_t len)
{
	for (int i = 0; i < len; i++)
	{
		dst[i + offset_dst] = src[i + offset_src];
	}
}

inline Integer xor_secret(Integer &pad, Integer &secret)
{

	Integer res(512, 0, XOR);
	int u = 32;
	for (int i = 0; i < u; i++)
	{
		int ii = i * 8;
		int iii = (u - 1 - i) * 8;
		for (int j = 0; j < 8; j++)
		{
			res[256 + ii + j] = pad[ii + j] ^ secret[iii + j];
		}
	}
	copy_int(res, pad, 0, 0, 256);
	return res;
}

Integer pad_int(int len)
{

	int pad_int_len = 512 - (len % 512);
	Integer pad(pad_int_len, len, PUBLIC);
	pad[len - 1] = 1;
	return pad;
}

class HMAC
{

public:
	Integer iv = hex_to_integer(256, "6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19", PUBLIC);
	Integer ipad_start = hex_to_integer(512, "36363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636", PUBLIC);
	Integer opad_start = hex_to_integer(512, "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c", PUBLIC);
	Integer label_master_secret = hex_to_integer(104, "6d617374657220736563726574", PUBLIC);
	Integer outer_end_pad = pad_int(512 + 256);

	Integer ipad;
	Integer opad;
	Integer seed;

	BristolFashion hasher;

	HMAC(BristolFashion hasher, string premaster_share, string client_random_hex, string server_random_hex) : hasher(hasher)
	{
		Integer empty(0, 0, PUBLIC);
		Integer premaster_share_alice = hex_to_integer(256, premaster_share, ALICE);
		Integer premaster_share_bob = hex_to_integer(256, premaster_share, BOB);
		Integer premaster_secret(256, 0, XOR);
		premaster_secret = premaster_share_alice + premaster_share_bob;
		ipad = xor_secret(ipad_start, premaster_secret);
		opad = xor_secret(opad_start, premaster_secret);

		Integer client_random_int = hex_to_integer(256, client_random_hex, ALICE);
		Integer server_random_int = hex_to_integer(256, server_random_hex, ALICE);
		Integer label_master_secret = hex_to_integer(104, "6d617374657220736563726574", PUBLIC); // "master secret"
		seed = Integer(256 + 256 + 104, 0, PUBLIC);
		copy_int(seed, server_random_int, 0, 0, 256);
		copy_int(seed, client_random_int, 256, 0, 256);
		copy_int(seed, label_master_secret, 512, 0, 104);
	}

	std::vector<Integer> run(int t)
	{
		Integer empty(0, 0, PUBLIC);
		std::vector<Integer> A;
		for (int i = 0; i < t; i++)
		{
			Integer state(256, 0, PUBLIC);
			if (i == 0)
			{
				state = inner(this->seed, empty);
			}
			else
			{
				state = inner(A[i - 1], empty);
			}
			state = outer(state);
			A.push_back(state);
		}
		std::vector<Integer> U;
		for (int i = 0; i < t; i++)
		{
			Integer state = inner(this->seed, A[i]);
			state = outer(state);
			U.push_back(state);
		}

		return U;
	}

protected:
	Integer inner(Integer &seed, Integer &chain)
	{

		int block_size = this->ipad.size() + seed.size() + chain.size();
		Integer end_pad = pad_int(block_size);
		bool has_chain = chain.size() != 0;

		// key = (premaster_secret^ipad)<64>
		// hash_1 = hash(ipad<64>, seed<_>)

		// first iteration:
		// in 2PC
		// inp_1 = [iv<32>, ipad<64>]
		Integer inp_1(512 + 256, 0, XOR);
		Integer out(256, 0, PUBLIC);
		copy_int(inp_1, this->iv, 512, 0, 256);
		copy_int(inp_1, this->ipad, 0, 0, 512);
		hasher.compute(out.bits.data(), inp_1.bits.data());

		Integer inp(512 + 256, 0, ALICE);
		int z = block_size / 512;
		int pad_size = block_size % 512;
		int seed_off = seed.size();
		if (pad_size != 0)
		{
			z -= 1;
		}

		// ALICE only
		for (int i = 0; i < z; i++)
		{
			// new_iv<32> = out<32>
			// inp = [new_iv<32>, seed[_:_]<_>, pad<_>]
			Integer inp(512 + 256, 0, ALICE);
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

	Integer outer(Integer &chain)
	{

		// inp = [iv<32>, opad_premaster_secret<64>]
		// TODO: very same calculation occurs many times, we may want to store the result and reuse it.
		Integer inp(512 + 256, 0, XOR);
		Integer out_1(256, 0, PUBLIC);
		copy_int(inp, this->iv, 512, 0, 256);
		copy_int(inp, this->opad, 0, 0, 512);
		hasher.compute(out_1.bits.data(), inp.bits.data());

		// new_iv<32> = out_1<32>
		// inp = [new_iv<32>, chain<32>, pad<32>]
		// TODO: consider that this can be ALICE only
		Integer inp_2(512 + 256, 0, PUBLIC);
		Integer out_2(256, 0, PUBLIC);
		copy_int(inp_2, out_1, 512, 0, 256);
		copy_int(inp_2, chain, 256, 0, 256);
		copy_int(inp_2, this->outer_end_pad, 0, 0, 256);
		hasher.compute(out_2.bits.data(), inp_2.bits.data());

		return out_2;
	}
};

int main(int argc, char **argv)
{
	string client_random = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	string server_random = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

	int port, party;
	parse_party_and_port(argv, &party, &port);
	string share_hex = argv[3];

	NetIO *io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
	setup_semi_honest(io, party);

	std::string filepath = "./test/sha256circuts/bristol_fashion/sha256.txt";
	emp::BristolFashion hasher(filepath.c_str());
	HMAC hmac = HMAC(hasher, share_hex, client_random, server_random);
	std::vector<Integer> U = hmac.run(2);

	// 0x3946e027a4b0ab19540ff28d3b5369f75daf4737ce075f309882b72eb1d7f01e
	debug_int(PUBLIC, U[1], "u_1");

	cout << CircuitExecution::circ_exec->num_and() << endl;
	finalize_semi_honest();
	delete io;
}

// Integer hmac_a_hash_inner(BristolFashion hasher, Integer &secret, Integer &seed, Integer &chain)
// {

// 	Integer ipad = hex_to_integer(512, "36363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636", PUBLIC);
// 	Integer iv = hex_to_integer(256, "6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19", PUBLIC);

// 	assert(secret.size() == 256);
// 	int block_size = ipad.size() + seed.size() + chain.size();
// 	Integer end_pad = pad_int(block_size);
// 	bool has_chain = chain.size() != 0;

// 	// key = (premaster_secret^ipad)<64>
// 	// hash_1 = hash(key<64>, seed<_>)

// 	// first iteration:
// 	// in 2PC
// 	// ipad_premaster_secret = ipad ^ premaster_secret
// 	// inp_1 = [iv<32>, ipad_premaster_secret<64>]
// 	Integer ipad_premaster_secret = xor_secret(ipad, secret);
// 	Integer inp_1(512 + 256, 0, XOR);
// 	Integer out(256, 0, PUBLIC);
// 	copy_int(inp_1, iv, 512, 0, 256);
// 	copy_int(inp_1, ipad_premaster_secret, 0, 0, 512);
// 	hasher.compute(out.bits.data(), inp_1.bits.data());

// 	Integer inp(512 + 256, 0, ALICE);
// 	int z = block_size / 512;
// 	int pad_size = block_size % 512;
// 	int seed_off = seed.size();
// 	if (pad_size != 0)
// 	{
// 		z -= 1;
// 	}

// 	// cout << "block size " << block_size << endl;
// 	// cout << "z " << z << endl;
// 	// cout << "seed size " << seed_off << endl;

// 	// ALICE only
// 	for (int i = 0; i < z; i++)
// 	{
// 		// new_iv<32> = out<32>
// 		// inp = [new_iv<32>, seed[_:_]<_>, pad<_>]
// 		Integer inp(512 + 256, 0, ALICE);
// 		copy_int(inp, out, 512, 0, 256);
// 		if (i == 0 && has_chain)
// 		{
// 			seed_off -= 256;
// 			copy_int(inp, chain, 256, 0, 256);
// 			copy_int(inp, seed, 0, seed_off, 256);
// 		}
// 		else
// 		{
// 			seed_off -= 512;
// 			copy_int(inp, seed, 0, seed_off, 512);
// 		}
// 		// cout << "loop " << seed_off << endl;
// 		hasher.compute(out.bits.data(), inp.bits.data());
// 	}

// 	// ALICE only
// 	if (pad_size != 0)
// 	{
// 		// new_iv<32> = out<32>
// 		// inp = [new_iv<32>, seed[_:]<_>, pad<_>]
// 		copy_int(inp, out, 512, 0, 256);
// 		copy_int(inp, seed, end_pad.size(), 0, seed_off);
// 		copy_int(inp, end_pad, 0, 0, end_pad.size());
// 		hasher.compute(out.bits.data(), inp.bits.data());
// 	}

// 	return out;
// }

// Integer hmac_a_hash_outer(BristolFashion hasher, Integer &secret, Integer &chain)
// {

// 	assert(secret.size() == 256);
// 	assert(chain.size() == 256);

// 	Integer opad = hex_to_integer(512, "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c", PUBLIC);
// 	Integer iv = hex_to_integer(256, "6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19", PUBLIC);
// 	Integer end_pad = pad_int(512 + 256);

// 	// inp = [iv<32>, opad_premaster_secret<64>]
// 	// TODO: very same calculation occurs many times, we may want to save it.
// 	Integer opad_premaster_secret = xor_secret(opad, secret);
// 	Integer inp(512 + 256, 0, XOR);
// 	Integer out_1(256, 0, PUBLIC);
// 	copy_int(inp, iv, 512, 0, 256);
// 	copy_int(inp, opad_premaster_secret, 0, 0, 512);
// 	hasher.compute(out_1.bits.data(), inp.bits.data());

// 	// new_iv<32> = out_1<32>
// 	// inp = [new_iv<32>, chain<32>, pad<32>]
// 	// TODO: consider that this can be alice only
// 	Integer inp_2(512 + 256, 0, PUBLIC);
// 	Integer out_2(256, 0, PUBLIC);
// 	copy_int(inp_2, out_1, 512, 0, 256);
// 	copy_int(inp_2, chain, 256, 0, 256);
// 	copy_int(inp_2, end_pad, 0, 0, 256);
// 	hasher.compute(out_2.bits.data(), inp_2.bits.data());

// 	return out_2;
// }

// void enc_keys_to_alice(int party, string client_random_hex, string server_random_hex, string premaster_share)
// {

// 	Integer iv = hex_to_integer(256, "6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19", PUBLIC);
// 	Integer ipad = hex_to_integer(512, "36363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636", PUBLIC);
// 	Integer opad = hex_to_integer(512, "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c", PUBLIC);

// 	Integer pad141 = hex_to_integer(408, "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000468", PUBLIC);
// 	Integer pad96 = hex_to_integer(256, "8000000000000000000000000000000000000000000000000000000000000300", PUBLIC);
// 	Integer pad173 = hex_to_integer(152, "80000000000000000000000000000000000568", PUBLIC);

// 	Integer client_random_int = hex_to_integer(256, client_random_hex, ALICE);
// 	Integer server_random_int = hex_to_integer(256, server_random_hex, ALICE);
// 	Integer label_master_secret = hex_to_integer(104, "6d617374657220736563726574", PUBLIC); // "master secret"
// 	size_t seed_size = 256 + 256 + 104;
// 	Integer seed_1(seed_size, 0, PUBLIC);
// 	Integer empty(0, 0, PUBLIC);

// 	copy_int(seed_1, server_random_int, 0, 0, 256);
// 	copy_int(seed_1, client_random_int, 256, 0, 256);
// 	copy_int(seed_1, label_master_secret, 512, 0, 104);

// 	string filepath = "";
// 	BristolFashion cf(filepath.c_str());

// 	Integer premaster_share_alice = hex_to_integer(256, premaster_share, ALICE);
// 	Integer premaster_share_bob = hex_to_integer(256, premaster_share, BOB);
// 	Integer premaster_secret(256, 0, XOR);
// 	premaster_secret = premaster_share_alice + premaster_share_bob;

// 	Integer ipad_premaster_secret = xor_secret(ipad, premaster_secret);
// 	Integer opad_premaster_secret = xor_secret(opad, premaster_secret);

// 	// TODO:
// 	// We need to have an access to compression function of sha-256
// 	// in order to compute alice only compressions. So for now let's
// 	// use the circuit :/

// 	//  a_1 = hmac(premaster_secret, seed)
// 	//  u_0 = hmac(premaster_secret, [a_1, seed])
// 	//  a_2 = hmac(premaster_secret, a_1)
// 	//  u_1 = hmac(premaster_secret, [a_2, seed])
// 	//  master_secret = (u_0 + u_1)[0:48]

// 	// a_1, a_2 can be know to Alice

// 	// hmac_1:
// 	// seed<77> = [client_random, server_random, label]
// 	// a_1
// 	//	= hmac(premaster_secret, seed)
// 	//  = hash(premaster_secret^opad, hash(premaster_secret^ipad, seed))

// 	// the inner hash of hmac_1
// 	// key = (premaster_secret^ipad)<64>
// 	// hash(key<64>, seed<77>)
// 	Integer out_hash_1 = hmac_a_hash_inner(cf, premaster_secret, seed_1, empty);

// 	debug_int(PUBLIC, out_hash_1, "");

// 	// the outer hash of hmac_1
// 	// key = (premaster_secret^opad)<64>
// 	// hash(key<64>, out_hash_1<32>)
// 	Integer out_hash_2 = hmac_a_hash_outer(cf, premaster_secret, out_hash_1);
// 	// a_1 = out_hash_2
// 	debug_int(PUBLIC, out_hash_2, "");

// 	// hmac_2:
// 	// seed<109> = [a1, client_random, server_random, label]
// 	// hmac(premaster_secret, [a1, seed])
// 	//  = hash(premaster_secret^opad, hash(premaster_secret^ipad, [a1, seed]))

// 	// the inner hash of hmac_2
// 	// key = (premaster_secret^ipad)<64>
// 	// hash(key<64>, seed<109>)
// 	Integer out_hash_3 = hmac_a_hash_inner(cf, premaster_secret, seed_1, out_hash_2);
// 	debug_int(PUBLIC, out_hash_3, "");

// 	// the outer hash of hmac_2
// 	// key = (premaster_secret^opad)<64>
// 	// hash(key<64>, out_hash_3<32>)
// 	Integer out_hash_4 = hmac_a_hash_outer(cf, premaster_secret, out_hash_3);
// 	// u_0 = out_hash_4
// 	debug_int(PUBLIC, out_hash_4, "");

// 	// hmac_3:
// 	// a_1 = out_hash_2
// 	// a_2
// 	//		= hmac(premaster_secret, a_1)
// 	//		= hash(premaster_secret^opad, hash(premaster_secret^ipad, a_1))

// 	// the inner hash of hmac_3
// 	// key = (premaster_secret^ipad)<64>
// 	// hash(key<64>, a_1<32>)
// 	Integer out_hash_5 = hmac_a_hash_inner(cf, premaster_secret, out_hash_2, empty);
// 	debug_int(PUBLIC, out_hash_5, "");

// 	// the outer hash of hmac_3
// 	// key = (premaster_secret^opad)<64>
// 	// hash(key<64>, out_hash_5<32>)
// 	Integer out_hash_6 = hmac_a_hash_outer(cf, premaster_secret, out_hash_5);
// 	debug_int(PUBLIC, out_hash_6, "");

// 	// a_2 = out_hash_6

// 	// hmac_4:
// 	// seed<109> = [a2, client_random, server_random, label]
// 	// hmac(premaster_secret, seed)
// 	//  = hash(premaster_secret^opad, hash(premaster_secret^ipad, seed))

// 	// the inner hash of hmac_4
// 	// key = (premaster_secret^ipad)<64>
// 	// hash(key<64>, seed<109>)
// 	Integer out_hash_7 = hmac_a_hash_inner(cf, premaster_secret, seed_1, out_hash_6);
// 	debug_int(PUBLIC, out_hash_7, "");

// 	// the outer hash of hmac_4
// 	// key = (premaster_secret^opad)<64>
// 	// hash(key<64>, out_hash_7<32>)
// 	Integer out_hash_8 = hmac_a_hash_outer(cf, premaster_secret, out_hash_7);
// 	debug_int(PUBLIC, out_hash_8, "");

// 	debug_int(XOR, out_hash_8, "master key xor");
// 	debug_int(PUBLIC, out_hash_8, "master key public");
// }

/*
	circuit outs
	
	bristol_fashion/sha256.txt
	w/o iv
	7ca51614425c3ba8ce54dd2fc2020ae7b6e574d198136d0fae7e26ccbf0be7a6
	w/ iv
	da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8

	bristol_format/sha-256.txt
	1b95ec18579f7f5dc2464b03892ba731537df9ee99eacc46962d9de87d196a5b
	which is reverse of 
	da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8


*/

// void test_sha256_fashion_with_iv(int party)
// {
// 	Integer iv = hex_to_integer(256, "6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19", PUBLIC);

// 	std::string filepath = "";
// 	emp::BristolFashion cf(filepath.c_str());

// 	emp::Integer inp(512 + 256, 0, emp::ALICE);
// 	for (int i = 0; i < 256; i++)
// 	{
// 		inp[i + 512] = iv[i];
// 	}
// 	emp::Integer out(256, 0, emp::PUBLIC);

// 	cf.compute(out.bits.data(), inp.bits.data());
// 	string out_revealed = out.reveal<std::string>();
// 	std::cout << out_revealed << std::endl;
// 	std::cout << bin_to_hex(out_revealed) << std::endl;
// }

// void test_sha256_fashion(int party)
// {

// 	std::string filepath = "";
// 	emp::BristolFashion cf(filepath.c_str());
// 	emp::Integer inp(512 + 256, 0, emp::ALICE);
// 	emp::Integer out(256, 0, emp::PUBLIC);
// 	cf.compute(out.bits.data(), inp.bits.data());
// 	string out_revealed = out.reveal<std::string>();
// 	std::cout << out_revealed << std::endl;
// 	std::cout << bin_to_hex(out_revealed) << std::endl;
// }

// void test_sha256_format(int party)
// {
// 	Integer iv = hex_to_integer(32, "6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19", PUBLIC);

// 	std::string filepath = "";
// 	emp::BristolFormat cf(filepath.c_str());

// 	emp::Integer inp2(512 + 256, 0, emp::ALICE);
// 	emp::Integer inp1(0, 0, emp::ALICE);
// 	emp::Integer out(256, 0, emp::PUBLIC);

// 	cf.compute(out.bits.data(), inp2.bits.data(), inp1.bits.data());
// 	string out_revealed = out.reveal<std::string>();
// 	std::cout << out_revealed << std::endl;
// 	std::cout << bin_to_hex(out_revealed) << std::endl;
// }