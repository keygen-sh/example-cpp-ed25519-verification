#include "include/ed25519/ed25519.h"
#include "include/base64/base64.h"
#include <stdlib.h>
#include <assert.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// We don't need Ed25519 key generation
#define ED25519_NO_SEED

// ansii_color_str adds ANSII color codes to a string.
std::string ansii_color_str(const std::string str, const int color_code)
{
  std::ostringstream stream;

  stream << "\033[1;";
  stream << color_code;
  stream << "m";
  stream << str;
  stream << "\033[0m";

  return stream.str();
}

// split_str splits a string by delimiter into a vector of strings.
std::vector<std::string> split_str(std::string str, std::string delim)
{
  std::vector<std::string> result;
  size_t pos;

  while ((pos = str.find(delim)) != std::string::npos)
  {
    result.push_back(str.substr(0, pos));

    str = str.substr(pos + delim.size());
  }

  result.push_back(str); // Last word

  return result;
}

// replace_str replaces occurences of a string within a string with another string.
std::string replace_str(std::string str, const std::string& from, const std::string& to) {
  size_t pos = 0;

  while ((pos = str.find(from, pos)) != std::string::npos)
  {
    str.replace(pos, from.length(), to);

    pos += to.length(); // Handles case where 'to' is a substring of 'from'
  }

  return str;
}

// base64_url_decode decodes a base64-url encoded string.
unsigned char* base64_url_decode(std::string enc, int* len)
{
  // Convert base64url encoding to base64 (see https://keygen.sh/docs/api/#license-signatures)
  enc = replace_str(enc, "-", "+");
  enc = replace_str(enc, "_", "/");

  unsigned char* buf = unbase64(enc.c_str(), enc.size(), len);

  return buf;
}

// unhex convert a hex string to raw bytes.
inline void unhex(std::string str, unsigned char* bytes)
{
  std::stringstream converter;

  for (int i = 0; i < str.size(); i += 2)
  {
    int byte;

    converter << std::hex << str.substr(i, 2);
    converter >> byte;

    bytes[i / 2] = byte & 0xff;

    converter.str(std::string());
    converter.clear();
  }
}

// verify_license_key_authenticity verifies a license key's authenticity by verifying its cryptographic signature.
bool verify_license_key_authenticity(const std::string public_key, const std::string license_key)
{
  const std::string LICENSE_KEY_DELIMITER = ".";
  const std::string SIGNING_PREFIX_DELIMITER = "/";
  const std::string SIGNING_PREFIX = "key";

  std::string signing_data;
  std::string encoded_sig;
  std::string encoded_key;

  // Key should have the format: key/{BASE64URL_KEY}.{BASE64URL_SIGNATURE}
  {
    std::vector<std::string> vec = split_str(license_key, LICENSE_KEY_DELIMITER);
    if (vec.size() != 2)
    {
      std::cerr << ansii_color_str("[ERROR]", 31) << " "
                << "License key is incorrectly formatted or invalid: "
                << license_key
                << std::endl;

      exit(1);
    }

    signing_data = vec[0];
    encoded_sig = vec[1];
  }

  // Split encoded key from prefix
  {
    std::vector<std::string> vec = split_str(signing_data, SIGNING_PREFIX_DELIMITER);
    if (vec.size() != 2)
    {
      std::cerr << ansii_color_str("[ERROR]", 31) << " "
                << "License key is incorrectly formatted or invalid: "
                << license_key
                << std::endl;

      exit(1);
    }

    if (vec[0] != SIGNING_PREFIX)
    {
      std::cerr << ansii_color_str("[ERROR]", 31) << " "
                << "License key prefix is invalid: "
                << vec[0].c_str()
                << std::endl;

      exit(1);
    }

    encoded_key = vec[1];
  }

  // Base64 decode signature
  int sig_len;
  unsigned char* sig_buf = base64_url_decode(encoded_sig, &sig_len);

  // Recreate signing data using signing prefix
  std::string re_signing_data = SIGNING_PREFIX + SIGNING_PREFIX_DELIMITER + encoded_key;

  // Cast to bytes
  int data_len = re_signing_data.size();
  unsigned char* data_buf = reinterpret_cast<unsigned char *>(
    const_cast<char *>(re_signing_data.c_str())
  );

  // Decode hex public key into bytes
  unsigned char key_bytes[32];

  unhex(public_key, key_bytes);

  // Verify signature
  auto ok = ed25519_verify(sig_buf, data_buf, data_len, key_bytes);
  if (ok)
  {
    // Base64 decode license key
    int key_len;
    unsigned char* key_buf = base64_url_decode(encoded_key, &key_len);

    std::cerr << ansii_color_str("[INFO]", 34) << " "
              << "License key contents: "
              << key_buf
              << std::endl;
  }

  return (bool) ok;
}

int main(int argc, char* argv[])
{
  if (!getenv("KEYGEN_PUBLIC_KEY"))
  {
    std::cerr << ansii_color_str("[ERROR]", 31) << " "
              << "Environment variable KEYGEN_PUBLIC_KEY is missing"
              << std::endl;

    exit(1);
  }

  if (argc == 1)
  {
    std::cerr << ansii_color_str("[ERROR]", 31) << " "
              << "License key argument is required"
              << std::endl;

    exit(1);
  }

  std::string public_key = getenv("KEYGEN_PUBLIC_KEY");
  std::string license_key = argv[1];
  bool ok = verify_license_key_authenticity(public_key, license_key);
  if (ok)
  {
    std::cout << ansii_color_str("[OK]", 32) << " "
              << "License key is authentic!"
              << std::endl;
  }
  else
  {
    std::cerr << ansii_color_str("[ERROR]", 31) << " "
              << "License key is not authentic!"
              << std::endl;
  }
}
