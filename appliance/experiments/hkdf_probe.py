"""Prepare private HKDF diagnostic modules, never a replacement crypto provider.

Both modules run the vendor known-answer tests. They export no symbols and do
not hook or replace kernel functions. Passing this probe is not FIPS validation
or a repair of the installed kernel's failed boot self-test.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re

VENDOR_SHA256 = '28e87dd76eaa4a2c62c243e2b6c007ec0d6a83501b4e86157eab750b85deeebf'
ANCHOR = '\tint err;\n\n\terr = crypto_shash_setkey(hmac_tfm, salt, saltlen);'
REPAIR = '''\tint err;
\tu8 padded_salt[112 / 8] = { 0 };

\t/* HKDF salt is public; the secret is ikm. HMAC already zero-pads
\t * keys to its block size (RFC 2104 section 2). Canonicalizing a
\t * short salt here preserves the HMAC input without changing the
\t * generic HMAC minimum-key check or any known-answer test.
\t */
\tif (saltlen < sizeof(padded_salt) &&
\t    crypto_shash_blocksize(hmac_tfm) >= sizeof(padded_salt)) {
\t\tif (saltlen)
\t\t\tmemcpy(padded_salt, salt, saltlen);
\t\tsalt = padded_salt;
\t\tsaltlen = sizeof(padded_salt);
\t}

\terr = crypto_shash_setkey(hmac_tfm, salt, saltlen);'''

WRAPPER = r'''
static int kat_count;
module_param(kat_count, int, 0444);
static bool hmac_guard_enforced;
module_param(hmac_guard_enforced, bool, 0444);
static bool fips_observed;
module_param(fips_observed, bool, 0444);

static int __init qualification_init(void)
{
    struct crypto_shash *tfm;
    const u8 short_key = 1;
    int ret;

    if (!fips_enabled || IS_ENABLED(CONFIG_CRYPTO_MANAGER_DISABLE_TESTS))
        return -EPERM;
    fips_observed = true;
    ret = crypto_hkdf_module_init();
    if (ret)
        return ret;
    tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
    ret = crypto_shash_setkey(tfm, &short_key, sizeof(short_key));
    crypto_free_shash(tfm);
    if (ret != -EINVAL)
        return -EINVAL;
    hmac_guard_enforced = true;
    kat_count = ARRAY_SIZE(hkdf_sha256_tv) + ARRAY_SIZE(hkdf_sha384_tv) +
                ARRAY_SIZE(hkdf_sha512_tv);
    pr_info("CaptainsLog HKDF diagnostic: %d vendor vectors passed; HMAC guard retained\n", kat_count);
    return 0;
}
module_init(qualification_init);
'''


def prepare(source, output):
    raw = Path(source).read_bytes()
    if hashlib.sha256(raw).hexdigest() != VENDOR_SHA256:
        raise ValueError('Vendor source differs from the reviewed Rocky kernel')
    original = raw.decode()
    if original.count(ANCHOR) != 1:
        raise ValueError('HKDF repair anchor is not unique')
    candidate = original.replace(ANCHOR, REPAIR)
    # Preserve all test vectors, checks, expected outputs and failure paths.
    assert original.split('struct hkdf_testvec', 1)[1] == candidate.split('struct hkdf_testvec', 1)[1]
    output = Path(output)
    output.mkdir(mode=0o700)
    patch = ''.join(difflib.unified_diff(original.splitlines(True), candidate.splitlines(True),
                                      fromfile='a/crypto/hkdf.c', tofile='b/crypto/hkdf.c'))
    (output/'hkdf-short-salt-candidate.patch').write_text(patch)
    receipt = {'schema':1, 'vendor_source_sha256':VENDOR_SHA256,
               'candidate_source_sha256':hashlib.sha256(candidate.encode()).hexdigest(),
               'vendor_test_vectors_unchanged':True, 'vector_count':original.count('.test ='),
               'production_kernel_modified':False, 'fips_qualified':False, 'modules':{}}
    for variant, text in [('control', original), ('candidate', candidate)]:
        name = 'captainslog_hkdf_' + variant
        text = text.replace('#include <linux/module.h>', '#include <linux/module.h>\n#include <linux/fips.h>')
        for function in ('hkdf_extract', 'hkdf_expand'):
            text = text.replace('EXPORT_SYMBOL_GPL(' + function + ');', '')
            text = re.sub(r'\b' + function + r'\b', 'qualification_' + function, text)
            text = text.replace('int qualification_' + function + '(', 'static int qualification_' + function + '(')
        text = text.replace('module_init(crypto_hkdf_module_init);', WRAPPER)
        assert 'EXPORT_SYMBOL' not in text
        directory = output/variant
        directory.mkdir(mode=0o700)
        (directory/(name+'.c')).write_text(text)
        (directory/'Makefile').write_text('obj-m += ' + name + '.o\n')
        receipt['modules'][variant] = {'name':name, 'source_sha256':hashlib.sha256(text.encode()).hexdigest()}
    (output/'preparation.json').write_text(json.dumps(receipt, indent=2)+'\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor-source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.vendor_source, args.output), indent=2))
