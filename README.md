WARNING
=======

**This package is deprecated! Do not use for new projects.**

Instead of it, use scrypt or bcrypt from the official go.crypto repository:

* https://code.google.com/p/go/source/browse/scrypt/?repo=crypto
* https://code.google.com/p/go/source/browse/bcrypt/?repo=crypto

**Drawbacks of this package are:**

1. Deriving 64-byte output from HMAC-SHA256-PBKDF2 allows for 2x speedup of attacks
  (PBKDF2 takes twice as long to derive 64 bytes, but attackers only need to
  derive 32 bytes to compare matches).

2. Default number of iterations (5000) is too low for most uses.

3. Currenly Go's SHA256 implementation is too slow.


If you use this package, but do not use full 64-byte output for any purposes
other than what this package provides, please switch import to:

	import "github.com/dchest/passwordhash/fixed/passwordhash"

The "fixed" version uses only the first 32 bytes of hash for comparison to
avoid the speedup attack, and the default number of iterations is increased
to 100000.
