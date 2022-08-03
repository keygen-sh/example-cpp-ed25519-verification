# Example C++ Cryptographic Verification

This is an example of cryptographically verifying a license key's authenticity,
and extracting embedded tamper-proof data within the key for offline use, all by
using your Keygen account's public key. This example implements the [`ED25519_SIGN`](https://keygen.sh/docs/api/policies/#policies-create-attrs-scheme)
scheme. For an RSA example, check out [this repo](https://github.com/keygen-sh/example-cpp-cryptographic-verification).

Cryptographically verifying schemed licenses can be used to implement
offline licensing, as well as to add additional security measures to
your licensing model. All that is needed to cryptographically verify
a license is your account's public key.

You can find your Ed25519 public key within [your account's settings page](https://app.keygen.sh/settings).

## Running the example

First up, add an environment variable containing your public key:
```bash
# Your Keygen account's Ed25519 public key
export KEYGEN_PUBLIC_KEY='e8601e48b69383ba520245fd07971e983d06d22c4257cfd82304601479cee788'
```

You can either run each line above within your terminal session before
starting the app, or you can add the above contents to your `~/.bashrc`
file and then run `source ~/.bashrc` after saving the file.

On macOS, compile the source using g++:

```bash
g++ main.cpp -o bin.out -std=c++17 -stdlib=libc++ -I include/**/*.c
```

Then run the script, passing in the `key` as the first argument:

```bash
./bin.out 'key/signed.key'
```

Alternatively, you can prefix the below command with env variables, e.g.:

```bash
KEYGEN_PUBLIC_KEY=... ./bin.out 'key/...'
```

The license key's signature will be verified using Ed25519.

You can find your public key in your settings.

## Running on other platforms

We are only including instructions on how to compile and run this example on macOS.
If you'd like to create a PR with instructions for another platform, such as
Windows or Linux, please feel free to open a PR.

If you have any tips on how to improve the compilation, please open a PR.

## Questions?

Reach out at [support@keygen.sh](mailto:support@keygen.sh) if you have any
questions or concerns!
