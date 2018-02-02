#include <iostream>
#include <fstream>

#include "rsa.h"

using rsa::TByte;

#define RSA_PRIM_MIN 2
#define RSA_PRIM_MAX 5000

#define SERIALIZE_MAGIC "TKey"
#define SERIALIZE_MAGIC_LEN 4
#define SERIALIZE_OUT_LEN RSA_KEY_SIZE + SERIALIZE_MAGIC_LEN

bool serialize(TByte * pKey, TByte * out)
{
    if (out == nullptr)
        return false;

    ::strncpy((char *) out, SERIALIZE_MAGIC, SERIALIZE_MAGIC_LEN);
    ::memcpy(out + SERIALIZE_MAGIC_LEN, pKey, RSA_KEY_SIZE);

    return true;
}

bool deserialize(TByte * in, size_t in_len, rsa::TKey * out)
{
    if (in_len < RSA_KEY_SIZE)
        return false;

    if (::strncmp((char *) in, SERIALIZE_MAGIC, SERIALIZE_MAGIC_LEN) != 0)
        return false;

    ::memcpy(out, in + SERIALIZE_MAGIC_LEN, RSA_KEY_SIZE);
    return true;
}

void generate_keys()
{
    rsa::TGeneratorOutput go = rsa::generate<rsa::TInt>(RSA_PRIM_MAX, RSA_PRIM_MIN);

    std::ofstream ofPub("publickey.dat"), ofPriv("privatekey.dat");

    TByte * serialized = new TByte[SERIALIZE_OUT_LEN]();
    serialize((TByte *) go.publicKey(), serialized);
    ofPub.write((char *) serialized, SERIALIZE_OUT_LEN);

    serialize((TByte *) go.privateKey(), serialized);
    ofPriv.write((char *) serialized, SERIALIZE_OUT_LEN);
}

rsa::TKey * load_key(const char * szFilename)
{
    std::ifstream ofKey(szFilename);

    rsa::TKey * key = new rsa::TKey();
    TByte * buf = new TByte[SERIALIZE_OUT_LEN]();
    ofKey.get((char *) buf, SERIALIZE_OUT_LEN);

    deserialize(buf, SERIALIZE_OUT_LEN, key);

    return key;
}

bool is_file_exist(const char * szFilename)
{
    std::ifstream infile(szFilename);
    return infile.good();
}

int decrypt_buffer(TByte * buffer, size_t len)
{
    rsa::TKey * key = load_key("privatekey.dat");

    rsa::TInt n = 0;
    ::memcpy(&n, buffer, sizeof(rsa::TInt));

    if (n != key->getN()) {
        std::cerr << "error: invalid decryption key" << '\n';
        return 1;
    }

    buffer += sizeof(rsa::TInt);
    len -= sizeof(rsa::TInt);

    rsa::TInt outlen = len * sizeof(rsa::TInt);
    TByte * out = new TByte[outlen]();

    rsa::decode(key, buffer, len, out, outlen);

    std::cout.write((char *) out, outlen);
    return 0;
}

int encrypt_buffer(TByte * buffer, size_t len)
{
    rsa::TKey * key = load_key("publickey.dat");

    rsa::TInt outlen = len / sizeof(rsa::TInt);
    TByte * out = new TByte[outlen]();

    rsa::encode(key, buffer, len, out, outlen);

    rsa::TInt n = key->getN();

    std::cout.write("TEncrypted", 10);
    std::cout.write(reinterpret_cast<const char *>(&n), sizeof(n));
    std::cout.write((char *) out, outlen);

    return 0;
}

int process_file(std::string strFilename)
{
    std::ifstream ifIn(strFilename);

    ifIn.seekg(0, ifIn.end);
    size_t length = ifIn.tellg();
    ifIn.seekg(0, ifIn.beg);

    TByte buffer[length];
    ifIn.read((char *) buffer, length);

    if (::strncmp((char *) buffer, "TEncrypted", 10) == 0)
        return decrypt_buffer(buffer + 10, length - 10);

    return encrypt_buffer(buffer, length);
}

int main(int argc, char * argv[])
{
    ::srand(time(NULL));

    if (! (is_file_exist("publickey.dat") || is_file_exist("privatekey.dat"))) {
        generate_keys();
        std::cout << "New keys generated!" << '\n';
        return 0;
    }

    if (argc == 1) {
        std::cout << "Usage: " << argv[0] << " [filename]" << '\n';
        return 1;
    }

    return process_file(argv[1]);
}
