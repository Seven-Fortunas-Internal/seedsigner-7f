"""
    Tests seedsigner.models.sevenf.cert_request -- the ctypes bridge to
    firmware/mldsa7f's X.509 Root/Deputy TBS-building, assembly, and CSR
    verification/building functions. Backs
    7f-signing-support-x509-cert-request-foundation.

    Requires firmware/mldsa7f's compiled library (see test_sevenf_mldsa.py's
    own docstring for the search order); skips cleanly if it's missing.
"""
import pytest

from seedsigner.chains.base import ReviewField
from seedsigner.models.sevenf import mldsa
from seedsigner.models.sevenf.constants import ML_DSA_PK_LEN, ChainKind
from seedsigner.models.sevenf.path_lexicon import root_path
from seedsigner.models.sevenf.cert_request import (
    DEPUTY_DAYS,
    ROOT_DAYS,
    CertRequestError,
    assemble_csr_der,
    assemble_deputy_cert_der,
    assemble_root_cert_der,
    build_deputy_tbs_v2,
    build_root_tbs,
    csr_info_der,
    deputy_cross_cert_v2_review_fields,
    generate_serial,
    parse_root_certificate_der,
    root_self_cert_review_fields,
    verify_and_parse_csr_der,
)


def _lib_available() -> bool:
    try:
        mldsa._lib_handle()
        return True
    except FileNotFoundError:
        return False


def _csr_tooling_available() -> bool:
    """ csr_info_der/assemble_csr_der's FFI entry points only exist in a
        library built with `cargo build --release --features test-tooling`
        (7f-review-csr-tooling-ships-in-production-cdylib, 2026-10-04) -- a
        plain `cargo build --release` (sufficient for every OTHER test in
        this file) omits them. `hasattr` is the right probe: ctypes raises
        AttributeError for a symbol the loaded library doesn't export, and
        `hasattr` catches exactly that.

        CAVEAT (found by this session's own adversarial review,
        2026-10-04): `mldsa._lib_handle()` is a module-level singleton,
        cached for the life of the Python process -- this check (and the
        `skipif` decorator it feeds, evaluated once at collection time) can
        only see whichever library was loaded first. Correct for a plain
        `pytest tests/` invocation (a fresh process every run, confirmed),
        but would give a STALE answer in a long-lived process that
        rebuilds the .so mid-session (a REPL, a Jupyter kernel, pytest's
        own `--looponfail`/`pytest-watch`). Restart the process after
        rebuilding with/without --features test-tooling if using one of
        those workflows. """
    if not _lib_available():
        return False
    return hasattr(mldsa._lib_handle(), "mldsa7f_cert_build_csr_info")


_csr_tooling_skipif = pytest.mark.skipif(
    not _csr_tooling_available(),
    reason="mldsa7f built without --features test-tooling -- run `cargo build --release "
           "--features test-tooling` in firmware/mldsa7f/ to exercise csr_info_der/assemble_csr_der",
)


pytestmark = pytest.mark.skipif(
    not _lib_available(),
    reason="firmware/mldsa7f not built -- run `cargo build --release` in firmware/mldsa7f/ first",
)

ROOT_VK = bytes([0xAB]) * 1952
SERIAL = bytes([0x11]) * 16
NOW = 1_700_000_000
DAYS = 3650


# --- FFI: build_root_tbs / build_deputy_tbs ---

def test_build_root_tbs_is_deterministic():
    a = build_root_tbs(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, SERIAL)
    b = build_root_tbs(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, SERIAL)
    assert a == b
    assert len(a) > 0


def test_build_root_tbs_differs_by_chain_kind():
    testnet = build_root_tbs(ROOT_VK, ChainKind.TESTNET, NOW, DAYS, SERIAL)
    mainnet = build_root_tbs(ROOT_VK, ChainKind.MAINNET, NOW, DAYS, SERIAL)
    assert testnet != mainnet


def test_build_root_tbs_rejects_a_malformed_subject_key():
    with pytest.raises(CertRequestError):
        build_root_tbs(bytes([0xAB]) * 10, ChainKind.TESTNET, NOW, DAYS, SERIAL)


# --- PKCS#10 / real-certificate-based Deputy cross-certification ---
# Real reference vectors, copied verbatim (via a script reading the source
# file directly, not retyped by hand) from firmware/mldsa7f/src/ffi.rs's own
# FFI_ROOT_CERT_DER_HEX/FFI_DEPUTY_CSR_DER_HEX/FFI_DEPUTY_SUBJECT_VK_HEX --
# themselves captured directly from 7fchain's real crates/sf-ca/src/
# x509_ceremony.rs (root_cert, request_issuer, verify_issuer_request,
# deputy_tbs_for_root), a temporary #[ignore]d test added to that checkout,
# run once, captured, reverted immediately (D12). Root keypair
# from_seed([0x11; 32]), Deputy keypair from_seed([0x22; 32]),
# chain_kind=Testnet, NOW=1_800_000_000, days=DEPUTY_DAYS (3650).
_ROOT_CERT_DER_HEX = (
    "308216213082091ea003020102021054a7bde049c80e55bbead0de1151bf4e300b0609608648016503040312305531173015"
    "060355040a0c0e536576656e20466f7274756e61733110300e060355040b0c07746573746e65743128302606035504030c1f"
    "536576656e20466f7274756e617320526f6f74204341203035373564313561301e170d3237303131353038303030305a170d"
    "3437303131303038303030305a305531173015060355040a0c0e536576656e20466f7274756e61733110300e060355040b0c"
    "07746573746e65743128302606035504030c1f536576656e20466f7274756e617320526f6f74204341203035373564313561"
    "308207b2300b0609608648016503040312038207a100b1f7a2c606aef9f29e79e78147e9b5221a1abdd580b279d49d5316db"
    "ccbc006c946403e3982e0d25f397c5603f36c0ac01d6aea3519674da558737ada3692feea24b032395b831a78bbf23469c2a"
    "9ffd2cb964c9cd9e3451845ac575f183dc207bb3256d4ec1c67eb4296e22e8d7df0ad9f2236f04186e06b7e7b3fb7ddfcaab"
    "a0c6d615cf74736cb103e37de2c4f79214c1adfa985d50cd144d7686e2e428706a5c83261b43fa100a8c4471f33b584c6369"
    "3a815b49899acff9dfb1461e80689284355f9221fb15b414e60a34d10cb493b84395f75c00bc8569998ebec235546cbf0579"
    "6ed21babaca5f06954c2a241bbeccef2d252b9c0829ebfe55470d89c27f642c433cce3c8360e63a00fd374208b98f42cdecf"
    "11c615895ea9dc1cf32461f47786e75651e83edd40f1e49a46114ea012e2afc09b6b132c3f64ed0105e1920ac5685e166b11"
    "b6affbf22482cf19c7c83a757025dca619a6bc12c2d4cab5f1d3a0eebdf901b118148c0450da1d3d10e71134dce059019f9d"
    "af64b5e8581afe8a2855265a616cbafc17bd9f9748ae8227672bd3bc60d3b696cffa8ae2f035d16a45792b0e01abc5aa646a"
    "fb229ae7b4cc1f2efb1cf3cd8deaf03e84ae1cb3788baec9aee1ee3b7abac2598ab1e4c01a247352a3f50ec69a2e3507cc34"
    "ff291e7f5c9102900c8dd3d3fb0cc5bef2aff14305b297845bf1100a3e32d5c15172e23fd1cbf170dbf852912996dd45309e"
    "3c29a2dd17dd2cf975a8fcea46a2502ebdf951b7d0472ec310b974bb6533ccb45afee8179d8aee71b984ecb4d60d8d5d144e"
    "9158333a0437ae93307b81a841b0699e450697d43152c262b28cd9a008c73b2a992ffe63f7e1946614ae637db40f1424f8f4"
    "35bbc0be450b3f2a64b7c4932d41bc6a1d4d646f11cadcf605ce503a372104425b816074081c4bd6ebb4a8b7703fd5d93477"
    "0f064137cbc1eed2d1b0c030baae907230143b7eac2b3c472c164430b9d96e289bb0b5ec40cd0f8aa2ae1337c6e3b21f2b47"
    "615c23918e17e826f633450dfeef67b9570184430cd86e0243abc13dec38841e80c4cadd825dfce38a43d7b272d2ec4b8ac1"
    "c7faf09473979e8a1dad24f6240bfb7f803ca22215dec88b0f5f558bebd6dfd0a5812f2e8c90b1552d48dac05cf6d53cc9d7"
    "ade44fc37f50f1f9ff7433789eae78822e5b6c80bbc8fc91892c15dd8cf2f020899a0fa7b7e0e52f146a060b87da0f25be2e"
    "53c7bfa1ef263d6ff0953df957728ff596b402072026dd0aa2ca4ae3894a3adb4a93749394e5a6e22102ed7df14c20584f0d"
    "a1cfbf92a0329e860378133b6c2c4f46e17874eb9424ac84b83d5e6ce8a8b1625949c8449892bc83659120e0292ccb40dcb6"
    "ae7ebe4e4901871ae023d7456f495f9d5c26f33c4382ad5431a2bb69102a1571c88d4b24a23d89c64efbe9d5894b51116bb1"
    "548f4648ae2a46dd71f602c71c72595735d558db8170391229b9c44f1a081e40f112f822fffede1c9561fe388cbea280eda0"
    "0841c54a5942f3094b06941f55ccf425da6ed476a725417d8325b93ba3b7529044080a434fe7a42b130eefc198701912ce66"
    "65d22d121139e862467cac796a2125a7720ac0acde765fa7244337809942b3516096c4f2a08cc8fdd19a650e8ab740376167"
    "1d4e468437e25baccb5b50c63e7b05851d08d19ed43d7818de1c19a78bcd18fef648848d0f586b708ea6e50f2ef14706d78a"
    "abffa313cb936fc0b8a70addb5dfde0a2383179af005c0348dd8018e989b39011b93db23f8c799f6d03c621c97da8d1c687d"
    "b7abf2899fcc46bb8d3ea160f1b45392b0447723b4737332d3aa65c2b37dfe87cb83961152741b8cf1a332e41012e0cd180f"
    "33829e61003504270ca709cbd3c2da126cd7ae9eda29f55f1cf32ea4e95e6b12ebd5a6c78873baae0144d5df14833dfd7b72"
    "6f7d7350a237b237214709eb82e0096281c1bfc096ce5c55749107928623d8ba9c1f22b1e5ee17aa824b876f490f5c0c5a00"
    "7bc67c40d748630a4a064efb6566e12a597dfbf42c49a78813d348f259aa2694f1bfabf3a56cd0700c0cc76c7141ab4ded3e"
    "f1d35aa1730c3bdcfcb76e66bdb03311d4aca5cee9b2b4be3f17181909fac41f84694b60d3060616b0d3a6384dd15a6b3266"
    "544a36f2feaa366b7e9484ec2144a5851304b0378c0d7201ac1d7dccdb239474cdf745235ddc79ecce8b93a70ff3061e57c3"
    "142202e6f8ba4920f6e41641c3ebe9e71d6e90348efbf0a216f171afda8e31e2f1124c0d1d553fb5fa6bade8be22e50ae42a"
    "96e9c46eb63d4b1a8f97d90beb5b0bb3dc365539bfcd7cf5e736165498b6829ea39e0906950f2e6459e279f08d7004caf4b8"
    "3fdbc51245da3b806a2fa817253e3951597d20d9586191d8f04e1360d5bac1a8a75f940b1c8061d32391a79440b16ea54ebb"
    "9c7ec365e2ee2f74ccd8b098674ce4e2c569f2fc02c62e61358b6b349cec13ff18f00112a4a1f86476886ae4389f370319b9"
    "a96e45266a185b26cf693de01e96379e0f5b7bd1ff478feab6c77d5d8f3a2febfb1d5a478c15697768e2417630f4891f9bee"
    "d4290d66c9b312a92bd1a6f50f646207c4cfa58fc00afcb5f008c616b808411b47e03d94d84fc85d802ae9b6aa60c7b7779e"
    "0ee95d06b437972b4a5b94bb66ea2c01f68de7a3bfa60526bc55300ec2352452344e899243a62c1e45b0bfa8c21599c13a63"
    "37ecca74181eba4d141fb744a61bb68050602877cf0c867ba374307230120603551d130101ff040830060101ff020103300e"
    "0603551d0f0101ff040403020106301d0603551d0e041604140575d15a041b8b573635522018f2d25d0cc1c1d63017060355"
    "1d200410300e300c060a2b0601040184855902013014060a2b06010401848559030404060c04726f6f74300b060960864801"
    "650304031203820cee00fc51aae620562212223807bbb49355c0da8b989a2bd58b050437d8075a912727ac5d3e4605c3570f"
    "40e470d57fe4fc867d6b313669a865710bceb49e1e0c5c23851c391eb86cc8af420ce76668838483243a5d9815c21b472553"
    "d637bec783bf947c019f8081ab70b1fd0a5410228c59095404adfe06c7a465a94711358dbd62d3a5af4127a7099d5c2c9628"
    "bf282e1c2afbb6cf1860518dc7ae04d28ec3fc6977f48d98c7182d632271c187e3e96d1da70cca99eeb48a18d8d32dffaed4"
    "5dcb388a3154a06e1a5b838d25abd3b3007e023d94f48664f78a7adfac40d00a380d9d33a4cdf25b4b175b0757c302a07707"
    "ebb60c7d4711a6fa5de2511e58258515c4c1202d266a23675b375a1a13138318f2ca43490cf5c0d0717e16ff80dcfc351b92"
    "bf1ba8e59bf7f342029a07be84244fcc0ba73d79e578832cd8d884e9a240556f1b2f512f529614c489d647a67cb944d6b7d7"
    "4dc90f57838f18738136088da57f9ae15f08b6b9117989c0dfa584fee75406bef548a810ba91d421f419deb4bee989a3c519"
    "3213b4d1cd4bb28c1b1f3fde9fd948da0a5964bdc5df2c9544284a70f7b3cd357f8ec8d532467eeaf04b7313266bc297b5a1"
    "36a4bc736e6ac66564818b92be8f71a9aed156e900d9c2845d792497b6fe0748bea515712220df4b01159427e5abf6144976"
    "81ddc1bd9b7b0f88386dc35b6bf322b60df5f2fe31d61a74bd1d8bab32709a28dcf4ec7a66288a8a3c19b1ed5c52da150268"
    "a1676965b5520bc6c46dc19efc8eb09c1ce5657403a02ed3887a481c496202c68c67b5793f964add2cb8c183daac7c2e5674"
    "70444dfb5a67e8a54b022b98a16a5b330104b506c7d2820783c5d456134cbe214cfeb47cea283dec11956a3a0065f31e1b56"
    "69652e8fe9b70616c7a2eef4368717f35e7c316aca6231ed4827c3211f61e254f22a13f7b80d59762a4d857a96d125963691"
    "3448fa51f2ac2858d645f4d0718f264c98a11c775f03e70be73f1a2f8e6b1a3895b7f4f7294a989f61760143e3ed05a7b777"
    "50d0df590dc4408482fa1f034eed57cac8f6507dc607d0863cf2a811c139361b814029d952601f9391212d402be557d00f8e"
    "41867dcda0a5aaa6d24a1ccc8f740ad2d29bb2f2cd2de390979615f9c21a33fa7f5fe2a2235144c687d94aea1b80aff3045f"
    "d86d382b780ddaa3e1ef749e9f07970faa71d8dcb61b5885d0fc0fb6966e4dfcba32111ac182df33500a598a9c2dafd6b978"
    "6ab13cc11f7a670f32f525be80049758ef35b4a9582958897ff927fd8bb4867708d304ec46ae0eb9068ea58c4aa30ac9ec5c"
    "a260e4e6e164e5499b6a29f3d1ba55916d61b0ba819a6e77528b7361417c79e44e5dcfac5f8114e440822fa2ddbbd70f8d86"
    "bb5a0d3f74498b92a1502ef1113e0e247403ae9458b968c970ca1fd53f3450d285aa874f747ed39a221276b017260e55c023"
    "346fef813e9f55e40ca20c4dd8f5f0ba62c631f6528e92d4cdeccf54288fddd28e082674b3a3dbb748882b38c7cad27871ad"
    "ad45e93b655321dcf746c30ba6f373ae222543db92df85c9ddf18ac1fe57009217a1fafc3e2c4f4099583c418025778d9c7a"
    "6f9595bef896b6ef1c6124d487f1a0498b2bf4f05cc94cf24427166969dc367cc0b5b08c79ec7f034b50d3b7c315b306f24f"
    "6b921ac3e98599aa6bf89187a912a6b06c974ee23287d3fd35fae7540095caa1b04f149eea1a4efe9bb49987abe45a1d3e33"
    "131a572da2b14773ac43a7eb4bf9e48ed1afc68515bec7dc954812fc742c663bca9c48820bdccab4f7133d599ead14ad79d7"
    "22b608a58033ad945db2bddd0ffc07d1bb5d4223ad2bcf4c9e4c1e6e906d70f9691cdbdf40f9c5ddcebb8b2f7f90ec326994"
    "7fa628a21d1facaa0965acabbaa59fbcc0e809e8c4b4edff8e43e1e2f6d9866fd81a220361eda01896c0b427c4c654959b48"
    "6a4ff9616591b9c4df9c89b58f2de63b7afa44ed6cf26916caae5a64e0b1d69ae841907bf42b7e4e0bb3ab60992abdeb37aa"
    "d9ce5c98fced5250d4c694645065d7e9b0d3ca1e4c809ea545efbe58488e74eff33ec1279fcffd1a2f07f892bced80b1615f"
    "8fd3010ef4dc1e89dd79bc84c5c0951b10dc028fd6533ed94174a361d4042342003e54e34e58790e87cfcc551810cedf90ff"
    "625681195763cc0866b7146916d09be07c6a4436003a2a5b4077b94ed7005dbe5a58eb15a17efcb817b3dd7c218514016683"
    "48e9d59e013ebf9c6f48cf96090bcc819a1f24c72828d5e55aaf2fdc1dd6b2781d9c23e41812a9f0834d5a2ed058e3478985"
    "75bfb94bb70b12053c190b4b042828d2ea04080badd479be455623446306a9ba2206f29c35a4bf4e924a4adda530c0201237"
    "f8cbcf07c90dce20f80ddccc59b479ecfcd7976573730631f60aea1bfaf04ad8e287b2586a5865a680b4d66a69d2db3f7f1c"
    "9ffb1dd414e35c431c284a29d2c664d6f6f5af0caf3e5fbfa29cc6eb0056864b6d98c277a658d8290f5e23455312dc26731c"
    "4c31d984f8347ac039d309680f8a637b45acbb67f786d5a0c5fbe6d8c5a0d4066dbd02910e59fa78cdb0ee9a85a52791c951"
    "7850a41ad7465ff2616fd693b53e606415c9931f99964e2da75b8f95f33339a0af30f2910f733bfd14aa88460b76e7659cec"
    "cbc7061d0dd7e63b0aa8c40016e305cf435c03f4af4da8e06033304a430b56474906d7f3047bf11c913b76c8b1e4e949dab7"
    "fd6b53626c3ceaa1ab39a25fc4cb0a100cac8f3be8dc101005fd7445a5f9067c401c08f0ca0d52a86744a53c93f6fbce9309"
    "058754a721ac0edac8811a6f734f7d760d081d463c326278a19c95917508d6934d6c77c749ff2f9f8d3093ee5dcaababfdce"
    "6d104c0535af1b53c0fc098c9fab21e7533fa44bdd935774ad1f4913dcf56db2d91a401e114c52b75ff165de6e619ee7ab6e"
    "a7b3cb882c4830e44106a119ff5331c0b767cedf722f0f1ef068da41a2b64840340abc9b35fa09c03cb5c1e28e27e63984a0"
    "c437dd2e6fa27324788f87d7d24c15ab777b3d6217c8f4844c3b6fcaaa0e4a0a5049a1f60dada3c17f6bf855541f6c522638"
    "228ef7883d51b7b8ac047097d156cc36f7b7c48d6bbcfed878b340e25cbd9b9da2e5054cb11d21700a6dc7b0e38449caaf18"
    "d446e37ac9232b293812b0b46addfeef555eaa18c3379f58d1686944fac84a8afb1ed14ad9fedf9c5e54d974d494431a8eb8"
    "5825af2eda6ab9c5b2afea482ce6220510c9cb7ed5597f6bcdc104929ccb0018ebf94326cbe6c06bfe2ef3d9d049f90240fd"
    "1e1f11b88081cd1619d13ea6c4a4d23cae4095be5c2ddc147689fc70a1a2db4a91d90397b892fe69d6a15eae53cf7b7ff33d"
    "d1f2a7f97f688d0ed6226ea7e72909da7e2d25395cf640aa7d0bbf9040ff54b8b4d0831ed2fa1d9489df3a0f605e2376bb10"
    "5098581f1e873c4532dafb912a4a413af38282b1198f90daa676ed64655afbb3d1484ea6674bb14d163e0122c42615a877c0"
    "ff28570075adde17870fa013b253d3ab2187a24c540a899b139cb0d9173c1c230f006d655dbe0261cfbdca565d3c4f599238"
    "d3d946bfdfacc956d9fb3961da9b3a0dc2308459014ed2deebcb2e0ae53c35878033b9f043dadb1fc14dfa90697a9f8fbb1f"
    "a78474e050683eba7ae9b4e82fca9ffd24e51b2b488188f3ba520c4978c3d8a0b10081a1a7c4ed8bd395ce880cc8365a25be"
    "e99d958d85b2d6d182e5b76020b162ba85b2b7b5f785c24fafa082054aacaed963ee2b2a140872a5dd812e9d57c65d145f85"
    "8703ed9131672d2580291c74793b5981b1f463cebc3c70467b5577efa5db1c1c6a9c116d5f49445236902fc24b27a8f1d9f9"
    "58189f16bb7120dac3903aa1af2156ef6485c033d4bb77d159ab1694d273e79f12e45e1fd847fe856e3c172d1df94ad17c73"
    "5940dd84f4f7db37d36071c4b0596170c3f9464aad6389afa55d2f2cd4819fe671ea6e6d7fe7f3eb911d4072aa92e1b902a8"
    "73c9d84859630a8efb22c5f37af2afd766b2a892d3bc60e0a6d94de464288b0645c827687ade1c4e5ff07061e68d7fa6be14"
    "749d1df13a4cbad6d3c3af1c384a14a826a216c3d125716cbe07c86ea99aaff1d88fe308ecfac08d074f994ceefadece41f2"
    "65278e79f89e4fc5286a67b1ecd6e1f8b15a1a1bf95472427d52632d7b1e9f9b64b6ea237f6fdeb144023b7648bc470350fa"
    "3e1424d80cc078b22905f11c2e63419a043c544196bb65bc2a7f6b8071a1dc14298030b58e92693d186a18ea53f91c0f7680"
    "d02655efaf2d5f262df2c8af53740fc5585f19ae7dd280c9db74b99f2ea9948ea87a6c9cb364de795f5979bfad1109a8d05f"
    "dd2b0fe7df4d3ce82dfbde410854c9320710522b86f3c3505187d4f3d696275491fab56b300fa81b813d938727f45784d7ee"
    "b6fbb83f375972139765ed5c36cec11477bcc5efd2e60bafee08d6a1160405f8f15262a6438a6af74f906ce227486f564d08"
    "aa4f12363707689136e79fdcbc5671f093140d6855ee5120e5582aaa5225c348d996ab57989046ada3e29cb4055f4219d42f"
    "6056f35f9530ca3e7f9bc7cce2f7fb86b2e5eaf20e315b9ddc86a6a7c1c2dd355384b3e0f702133d4a5a76a1aec6eb000000"
    "00000000000000000000000000070c11171d27"
)
_DEPUTY_CSR_DER_HEX = (
    "308214ea308207e7020100302a31173015060355040a0c0e536576656e20466f7274756e6173310f300d06035504030c0664"
    "6570757479308207b2300b0609608648016503040312038207a10010d9590958e058a8f015bcfc4e6c6d5b990f5f16048719"
    "976354156e9b46e02efa84332b74ad696a600b9b48e716a8a6df36f9cbf21428ef03cd366043ba03cc8aac6e13b3ebe16a7e"
    "22f2b0c8de0c6b2c4448f3fbc33aebc0cd9baec0751c66bb5323ec3274208f256d0becb682d1fcf2fe9d4963aa1f0cb2c6b2"
    "1a544c7161b11455a44f7a1832b082919f6b3007447c1baf2b57a60662282192da2aacb0f39e0daeb28f7f6ba26aba42729b"
    "090b1c0c3259756bda2755d96749b766978b86e0867e793c6908b2d804efe9a2c36670554ebd8166505afe21b925c9646c4f"
    "c64272e5346e6748555886996725090b59732075a09d773d4dcbd8d6f17f26612f77bd21eb331c01fba8fc92a60a0e7782f0"
    "42e0312846755cc0c59ac3985a95cbc7aa8922758401a1750b7a733cbae2b7530c35a573e237c0cb6bc0a28f793fae1a94aa"
    "6acb172ee6be59d6b6bc018cb5efd728f5535123ba40bb230213038cc1ca7377ca8ac30fc76a1fe6bc650ef873814433e2d0"
    "dc822686639c87f9f79dc8c2b54b1609dbc3799ab95bda41d249287ff1630627514dec17c48b4d32b47ec07b20685cc9a8c7"
    "9bd73a5ab51965cccc35f675f73be324e1790dc9a2ce87c7f2ea6a75d96607fb521ff8df34cc0e0016bb2a1323b32c3b48b3"
    "81c9b9cd0a8c3d84b5855174ef6598fdc0ec8fb2ca903468c56c9c3b1a888d32679d15cb6b2935f9435dcfd6306c5c1d3ee9"
    "cd3c58b4ee8ba2870b322d9cd3e6e16d22bb132ee28938ee118462a1611999ecb44b862442a492c80dad2b986433598b7529"
    "abac216abb5856074ea942356646a7c61e8d1d01cd28b02f9081347289e4c46c43a1e2fb56e816dfb70f6a7dff79e6dfe731"
    "761b2bc2c86e2b78efd7977b62b607d2b5e6d23a79eb964f0071aa10045e13674afd0ed27dcf5a0aeec42dde8e53251c77c1"
    "8e8464a3bab95aabdb7efb25856063a54553a1688ef3138cf969490c0f39a4bbfcf4c99471f671b6f4d15b421c86fe74464f"
    "8b19ac40663d28dc4182606febdce23597b37aff2e032d28633b42172d964a2abbc82b7628ebec853b9c720706fd6dfa8696"
    "2420f7dc6587f8e4f6df835ab70c95eb9f2fd76a4ea781345737d0d2812663d1ff9a5b273c253604587c46d0d3784b60c97d"
    "7db9d09ba2fd0a4fccc3b0d1276ca263a1e34dba2d637f9536d8b48c36fd1dc5695d39eaa8d2ef984fe68c422baf3e7ec9c6"
    "d4c8c16e58768bcb2d74fc02bae842bb4cfdf01c14fb1d52a4eb459435a32b8c673329634e793efeb5116b9081ddc827cb1a"
    "067d43d049f88cedf32bd4cd565eb53b32833212da6bbec5b23b183244294b416e69255b081a38ee81bec46a4fb8ce4b36ce"
    "f91f0743d0d4e2934811cd8ce3d2a37e132e4aaaaf68aa2663642f5ef1f17c175f0b481bbded7ea1624189294f95b60951c1"
    "74720029a7176d164a4500b3722c201a4cf85e9d155d7a95ef6d0d9a333cd0288b05bdf2326f4afa4c02f5ec193bd2f75fd7"
    "363d6f9c78b875b25a7dbe82065c73c43a523fd124f2c9043244cee68f93be7586dd1399c484c1c41ec5f2c2335920d31a4a"
    "037e7de74fcfbcb96a38e0186b57533124407840dff45923abc86810d50e8899bcbb7e5d99b45ea8ce9e5a2e3321d6114d5a"
    "1135f40a379079c645be51ab19f69df784020c9149ef3714cb474fccf10a0b28c52f74efc8bec3d7be070b414ddefa8738ec"
    "b146c40820c94985ff481c32c2d856eb2be8c9d5bcf74f678137170e4849a8027e15f79cdd989ffb034bfe6ced349a9a4e65"
    "3e3b656f5e240352342046e18da159df09d90ec4500c931aeeb2ce6f7de57d5f5c2e8412b3365e4dfa60b7412c73b5c9f7fa"
    "5418c416960c4c8a95a9fdfbea0980589e04604be9b59ad1e0830fb0c6c6559ad5d38cff66ee9ac1785308ddd61b540914fa"
    "674708da31dffd24ce510844bc680836f89f3b39e8a48ec53ac42682704b0c81f1bb9d95b8cded6a74b6b60c94566082e661"
    "87820ffc7b9c56760aa8152ee9c78884971bac3d3f2de476276f479c4a660489fce2dd95ac5e018482ca995e861ff53b9e29"
    "56735ffdb8886bbfe8a80f2149016c8ca908c7b096aabe88be3113d073f0ecfd757a4571cd022e2b7bc857ff186899ee0fad"
    "d9a4a6b070cf2cfee332ed2f9b36b2d27c4706aac9764476f2ba58535e7e3a99a82c18e35297978e0f8c1de2ea076960246d"
    "57d6159f22f03da208398b2a2b4438a0dfac5aa6ea5c7578c0763fb637d5a8479437323d239a45d0d6bad59cbce142263f6e"
    "827f4636e949386928fe7636ccc1ac448d19a0e3c4379a16228eee49aede288c1902583a4d7371e39daea5870f4f1b0c850e"
    "993417455a93dd75746566889ded857bac18a810b1f4b783ed085ee4eabcba7f8b79e17cb2d4988e39f8fc0de78a0ce0f98c"
    "0724854195a337c7522f2b8683a1a884fb74f3053c5e86170d1e3298766219d2f1ade4287903f4238d95224fdc53b9e7979e"
    "2e32b0355deca43c0a56d1044958794524c48555adb9ca9fd5034ab609a5fac11a55579dfa4946c5a3824e45083b5110fbee"
    "b8eacb17e15e2cb137f333b001e52840388acdff3ad2b772a000906ed42fd2dfd16101d13a6ed66cb347715a7b06d02eaff2"
    "807c8582e3d34fe40c25fa5be893ecfddccddeb458f769ec740b20b5cf65a27c94a7374b9be579c1237e53e4bb39df071b8f"
    "368714df669a9bf427f989e90bcc7489040d7a074f98f81bdeaeb12ab2a000300b060960864801650304031203820cee005a"
    "8b5f46b69c456187bb4211ba268f9e527ac6f81288871c78a26a1434e10d629b94085a3dd63d83bd2132dad5a77a3f8e2bd3"
    "c01277d8501a81cec6af7756b2d62ad636002f735c0f74c9080eac6996c93e9cc14e37bee4e03688f1783bf79728ed1791bc"
    "4d3682c60559ee0401587735ad87417b7fa8db745b7165eec14e6b63a4f276c48765b1f2758eb8de1b59c421c224caec218e"
    "d2265497c049ff962d08d647e052acd5dceddc3b6429d9909162949efe5ad17ff2195774e2d2589106440d9ed0568bc52d33"
    "9a3803d27cc2c17804ccff732eb7b0dfb1fb45ca4484b626c10c6f54314906cc62e68ec21109832eec38efa79cb800495600"
    "2c5626fe840f16aa318b25363515777ae7c7a07a7b2799c61969fb6006af5d9807532576db505aa003b82ba5c413e34f6f54"
    "5b58e7ffdb855c84050536824a2296aed97fba69ede28370b772a949f6b5d76bd7a84be207017de7b565441ee0aee1ee77e2"
    "77947b3dcbc48386e40c70884271ffab793f466ba22af2ff15c223b8264a58d46c5712ab342c46ef734948ae0bdbdf9f0464"
    "2c6f2cf8020c9d8d0897bbbd872f565cbd1b80f90618423db4ed26df96462bf5c06d439902a13aee50b528e44c17c49e1bf1"
    "a23185a6d4e15d78bfc737ab9ac1dbb4eeda711658e724a5c4860332b7e5ae11b84ed97e5d3207c73ba4ef478495274370eb"
    "a93436f1a9faaa280250d4abd06281da0b783277a457628afc8ec4c617717fb7f57d17965bb98d9de41cf4f0fa64a4193f06"
    "d549e5e50b58b2fbe5bae3c042475be063e2a3087d93542da0cc2d2783bdb1d3b6ba5c4997c20cd906bfbde26b697f8a3a20"
    "9fa2cde78207e46711f2fffa588037cfe0d498d834839c0644bf8e598cff1e2a5fa1117d9fbf0e691f676858d5624c1fdf0d"
    "74f989969ae6a29412ba9cad19fb8746d8472deae01a04b11073f9b87d08e300f87f018238ec9564e62c781a58cae9da07ea"
    "01800268bd091d6fd5feffdb1a5a0f8296957d41a50f0ed234e7b7f5a67e14f6035c0668964a4795e9e4d9bb3a48b8c9aa78"
    "360b2682919173e25810468eeaf1799b7bbf77a834e710cd9f94d71f6186591381f532677a5f01880dd1e6f4697b4dd09463"
    "315008dc372aa56c2b18a36ab081c26974f17d801d66690979367798890b0867642ae5b0e72c56c8f5a35e90982812c67631"
    "4e829e5d47af3a03701c68d94cc240c1ca5057b34b481e39ba517daa0fe8634def39ba07c31f9090ac2da62bc923ee9d1174"
    "6e5edb5fa469871d0de11c3049910f6cc4591aaa5182a2955899e350584d2a9f71ad75ef6de09ae6e4e1c1d6164639908919"
    "bada78152871c672262ebc5d60e161b58d70418eda8ff6e4534f3213612829c03d81525aaac1571d61df1a0078b0060b1a6f"
    "bd7fd80b44bceb9a51ee9773f3bccc752e3809011f3df17b0ff9724d1d5171e9e0c4b9a02f2d664ff2e3dc1d49289955d11a"
    "48b68ef1371a6da59a6b1c63838a8acdeb87b20b3257fa36c653d7765bb9beabe7cf5567f1189a72b5b9b5703f5375a7796c"
    "86cd8bc011744e3c63446b942f7c25f75caea36bb34e7b880d6c786d9de179ffe47755862cd8f033b07f52e4c66e4f9d61d2"
    "e45ccf91ff71080c1b328003117af7b9425d52c9bf65b67b42c93317eebb10184e5fab74ee6131d94412dd0acdfdfe6a870e"
    "58ebce547fea9aa2034d3dda690d7e73c8385b65e93205d596baff188303486c5948b657e8c5b9593302fd93b852b18d45a6"
    "d7d0a2e62797102118a2805a903c4e4629c41f000dc7e76df7e90f700c52df914d81012ba6bb536b9888bf914717553e1639"
    "a66eac9aba14d20147f0f5a72a9ee42106a8f0518b409cefd06da1d5e2a132ccf853d3f4ec36722a786fc5f2ef0abca46fa6"
    "f6804cafe0959c759d6cda9c051df65e4a4fc5fc3ede8519ca827dd1b4a0e4d503f9800a860c0f5e59bcec320e6ae4785976"
    "27a0a4e326df6b1f1daf4c9fd14aed5f8b11d0cf9b8443bbdc2798e6e94d8f3f87f063469ba257723fe1f7494cb8ab0f6977"
    "9b842adde49d8af1af6c7867166b5697c48221950350c8cfdab7868f150b30edee92a3e33b231a38459469c0546590d8dcfe"
    "bb30d23f69f1885489b1ba111b3fc6ddea6869d10e8f51f5ec29dc14dc9b7fcd5f65c1bf4b982a4db58db76ff6147ea10c7e"
    "0122bb6723dc83baad5d836dd6f0e99b06ad1513df80518c9227e3bed1b6ebf2162c2e2f1720f857be4daa0fa4da9327aef5"
    "c89e85e4522aabc5b4c56ff324e2918de5e7f4a06b03038bf935d3460b9e41f1e8fad9904e40ceb1d06ada96c9d206921899"
    "73acf40678fd2dcbef547090ddd91cb299c4205fcac282cf20648b78a672d6a95e63aaa48fc3ba6a46af4dea4247ed9463f8"
    "28811b6d886d4b0647e14bde2586816d64b716b46be23306475d54322a279a14704be2df916bacb865a8ff8dac7e7d2a7517"
    "934ede9d9ed8862eab855185bf5267eb931d9d03a8a91e6709bc3652592d3bdf7b87e750523ed15e9b1343247c5a990a7cbf"
    "64c2fc4bce526abaca12f535cbad8b33aba446e1e9cfc9dc6e9db1cf7760efe9e9ceb8699624e9942198b65e230769e5ac98"
    "a812c4c92cf1ca0954a05cfff923ac1692dbadab5fc271027dc85cee257317549c29f722d0ec03c4335b2b8f75cd9fdfefc2"
    "910e8c5366ba1766fbaf7e16201486d48e8fb6b8669e0caa93cb9b973de89c233dfa5334a1324ffa3e3c10fb9885e66d4a88"
    "0bb5cfb14e29a4f998605e30fa0fb01d1a95ad60704afc3b5caa5db0ab74ea06a245a1b4b570a26f7c9afbd50ce88bcafc25"
    "d11f581983f57e9b4609dd9646660a5bfb2f056ae1da1a251bc456dde6cfecfb9c5b58c9e53bcb28eec639534c8c8477943a"
    "4753dc03bcee0cd20ca0733ffac83d4db444727425af2043b74db639f160698cd370752f311b143123048e435dd953074ef2"
    "914e3ea221452fd3d6a7055b096e706db595b0ad67b0911e4833d5a530144717a2e6138acf0c70aab66b40568a4639ef0e7a"
    "8e3bcb54fc3b7f4b54a412f9bc25a79442e89a1d64f6e5746cd323263969db2b01dc65a8395848f9223e92814253f261a860"
    "fcc66c70fbe90dfed09d255a79a3a8b676cdd51f939cf69deb10b326c7efc68eb1622d97903c17f934e931f29374b749c9ec"
    "10412e892b043b65cad94fc10a1dc93f5901304337aa024d1e8ba67adfb267bb5754914ff5f4ff8726fe0c3f4db5cca452a3"
    "752a9d15e3ccd08643242b474c7728fa5d2297e3ce4c8311baebb9d33204f5c5a2b8d4b9e97a3b75a049d0101b3bbff98080"
    "b6b4e1e35884cd611691e9f72c4f0990ac1a004a62f1a1b3c7edd3c7ec09d588312e6f5202f68c59431ae70757d3211bad21"
    "6fbbeb86efb22c8a03485c0ec7f0d875260418ef29863c387c4950db48a364e65cc506fbd3a71d3e05a873c1b76049a5533a"
    "48b43a32c8531a25a8eaee583b5ebf26bb0c2e85f1c083f33d2cb2f489738226de340b4fd2b3618aace6200bf581e8e2e6e5"
    "16794d1ec2fed848dd6cbef70161e4ff0756837a9d0cff45d7d5d066a8e10952a7ee1419fff13e409654f8999a660d76671b"
    "93f3f7c4de972674b34c29199ed97a80ff035abacd060185db2ad51b9e6b3b32c7ea77c52ecacc6990da83481ff9507c1a6b"
    "89fc9d711bdc9a1e210d0b6c7be52f60b32d5ad984d040f83c3cdedd0dac01f604e6cc017e0b1e1a61090c670f2ac7e9bcac"
    "f771a02e4fde4bd123de6d6d7308d617abb00c5eefffc10c749aa4eafe28ea2c71c1e01421844aef51b307004bdb17eb4369"
    "f5e3a6e8c379dc1562f7e1fa59ea695c33ce6f1c6b482ab42d45c0b2adf8694f7c5f5c8f9919832c37df400f9a732a67773f"
    "f57c6e8c99992c54459bf20d5c2314bf8282e8b1cc8551325eebac6ed1a12626a66094a6fe152ae717c4dd1bb3cbf80ff1c5"
    "f039c07592c21b09e6c274ca27fad239e59cf632620a4dd24f979f8f4ea4d2fb9cf3f95fa9828e801fd012b4aad7916b0692"
    "011ea35d4c5ac4c52eb5aa9bd1304e58d3abef752167fa07af8b229827b2a484dfd23804da1c421c419832b16a489b65b091"
    "a6fc7922819176d2b27c310a42ccd05ae62a0207152a17d4a6ec59538e2dcb6015448fd947be99459dae54ee42bc38cdac66"
    "1f47dddd2129da1245a4f1417588c9ed3d7f727ea85924f541c6d920ebab79bb7ae88ac1b39227eba5781e1aab1c0ba05e80"
    "ff4c53c872d14c086a80a8bd303cbdd382c7926eeb07533acdb6815bda8b1833884c649b5748ff3d9de0b2cab35893623854"
    "426016ca5512b0e9b8652823eca6b5b99dfb3078a96c97daa8142ffb7bbb7c7e2e0cd8677727de9b59c948a8b248f71035b3"
    "6d85c13ecdc33b6eb2ab8d6f20895031a7d84004fda2f4a576112b323ac5a1f76b5cf15797d7f19d45426a6636861ae5dff1"
    "1b04e88f9093c51a9d5615e2d908d8760578deba69d073cfc08621a25ed1fb9896e4be26ac6398c207653f4816eecb26ac13"
    "94e6ed8f3dad3d22c9145129e0a2122d178c4133fcd19cf00dd57fe646686bf7e6139a47c1e5e6af40d7a102809c8d313b95"
    "c9454f6aafbbc45b6487bcc1edef0d5272777a9a4156bc112032587b7ca0cd00000000000000000000000000000000000000"
    "0000040a11171a22"
)
_DEPUTY_SUBJECT_VK_HEX = (
    "10d9590958e058a8f015bcfc4e6c6d5b990f5f16048719976354156e9b46e02efa84332b74ad696a600b9b48e716a8a6df36"
    "f9cbf21428ef03cd366043ba03cc8aac6e13b3ebe16a7e22f2b0c8de0c6b2c4448f3fbc33aebc0cd9baec0751c66bb5323ec"
    "3274208f256d0becb682d1fcf2fe9d4963aa1f0cb2c6b21a544c7161b11455a44f7a1832b082919f6b3007447c1baf2b57a6"
    "0662282192da2aacb0f39e0daeb28f7f6ba26aba42729b090b1c0c3259756bda2755d96749b766978b86e0867e793c6908b2"
    "d804efe9a2c36670554ebd8166505afe21b925c9646c4fc64272e5346e6748555886996725090b59732075a09d773d4dcbd8"
    "d6f17f26612f77bd21eb331c01fba8fc92a60a0e7782f042e0312846755cc0c59ac3985a95cbc7aa8922758401a1750b7a73"
    "3cbae2b7530c35a573e237c0cb6bc0a28f793fae1a94aa6acb172ee6be59d6b6bc018cb5efd728f5535123ba40bb23021303"
    "8cc1ca7377ca8ac30fc76a1fe6bc650ef873814433e2d0dc822686639c87f9f79dc8c2b54b1609dbc3799ab95bda41d24928"
    "7ff1630627514dec17c48b4d32b47ec07b20685cc9a8c79bd73a5ab51965cccc35f675f73be324e1790dc9a2ce87c7f2ea6a"
    "75d96607fb521ff8df34cc0e0016bb2a1323b32c3b48b381c9b9cd0a8c3d84b5855174ef6598fdc0ec8fb2ca903468c56c9c"
    "3b1a888d32679d15cb6b2935f9435dcfd6306c5c1d3ee9cd3c58b4ee8ba2870b322d9cd3e6e16d22bb132ee28938ee118462"
    "a1611999ecb44b862442a492c80dad2b986433598b7529abac216abb5856074ea942356646a7c61e8d1d01cd28b02f908134"
    "7289e4c46c43a1e2fb56e816dfb70f6a7dff79e6dfe731761b2bc2c86e2b78efd7977b62b607d2b5e6d23a79eb964f0071aa"
    "10045e13674afd0ed27dcf5a0aeec42dde8e53251c77c18e8464a3bab95aabdb7efb25856063a54553a1688ef3138cf96949"
    "0c0f39a4bbfcf4c99471f671b6f4d15b421c86fe74464f8b19ac40663d28dc4182606febdce23597b37aff2e032d28633b42"
    "172d964a2abbc82b7628ebec853b9c720706fd6dfa86962420f7dc6587f8e4f6df835ab70c95eb9f2fd76a4ea781345737d0"
    "d2812663d1ff9a5b273c253604587c46d0d3784b60c97d7db9d09ba2fd0a4fccc3b0d1276ca263a1e34dba2d637f9536d8b4"
    "8c36fd1dc5695d39eaa8d2ef984fe68c422baf3e7ec9c6d4c8c16e58768bcb2d74fc02bae842bb4cfdf01c14fb1d52a4eb45"
    "9435a32b8c673329634e793efeb5116b9081ddc827cb1a067d43d049f88cedf32bd4cd565eb53b32833212da6bbec5b23b18"
    "3244294b416e69255b081a38ee81bec46a4fb8ce4b36cef91f0743d0d4e2934811cd8ce3d2a37e132e4aaaaf68aa2663642f"
    "5ef1f17c175f0b481bbded7ea1624189294f95b60951c174720029a7176d164a4500b3722c201a4cf85e9d155d7a95ef6d0d"
    "9a333cd0288b05bdf2326f4afa4c02f5ec193bd2f75fd7363d6f9c78b875b25a7dbe82065c73c43a523fd124f2c9043244ce"
    "e68f93be7586dd1399c484c1c41ec5f2c2335920d31a4a037e7de74fcfbcb96a38e0186b57533124407840dff45923abc868"
    "10d50e8899bcbb7e5d99b45ea8ce9e5a2e3321d6114d5a1135f40a379079c645be51ab19f69df784020c9149ef3714cb474f"
    "ccf10a0b28c52f74efc8bec3d7be070b414ddefa8738ecb146c40820c94985ff481c32c2d856eb2be8c9d5bcf74f67813717"
    "0e4849a8027e15f79cdd989ffb034bfe6ced349a9a4e653e3b656f5e240352342046e18da159df09d90ec4500c931aeeb2ce"
    "6f7de57d5f5c2e8412b3365e4dfa60b7412c73b5c9f7fa5418c416960c4c8a95a9fdfbea0980589e04604be9b59ad1e0830f"
    "b0c6c6559ad5d38cff66ee9ac1785308ddd61b540914fa674708da31dffd24ce510844bc680836f89f3b39e8a48ec53ac426"
    "82704b0c81f1bb9d95b8cded6a74b6b60c94566082e66187820ffc7b9c56760aa8152ee9c78884971bac3d3f2de476276f47"
    "9c4a660489fce2dd95ac5e018482ca995e861ff53b9e2956735ffdb8886bbfe8a80f2149016c8ca908c7b096aabe88be3113"
    "d073f0ecfd757a4571cd022e2b7bc857ff186899ee0fadd9a4a6b070cf2cfee332ed2f9b36b2d27c4706aac9764476f2ba58"
    "535e7e3a99a82c18e35297978e0f8c1de2ea076960246d57d6159f22f03da208398b2a2b4438a0dfac5aa6ea5c7578c0763f"
    "b637d5a8479437323d239a45d0d6bad59cbce142263f6e827f4636e949386928fe7636ccc1ac448d19a0e3c4379a16228eee"
    "49aede288c1902583a4d7371e39daea5870f4f1b0c850e993417455a93dd75746566889ded857bac18a810b1f4b783ed085e"
    "e4eabcba7f8b79e17cb2d4988e39f8fc0de78a0ce0f98c0724854195a337c7522f2b8683a1a884fb74f3053c5e86170d1e32"
    "98766219d2f1ade4287903f4238d95224fdc53b9e7979e2e32b0355deca43c0a56d1044958794524c48555adb9ca9fd5034a"
    "b609a5fac11a55579dfa4946c5a3824e45083b5110fbeeb8eacb17e15e2cb137f333b001e52840388acdff3ad2b772a00090"
    "6ed42fd2dfd16101d13a6ed66cb347715a7b06d02eaff2807c8582e3d34fe40c25fa5be893ecfddccddeb458f769ec740b20"
    "b5cf65a27c94a7374b9be579c1237e53e4bb39df071b8f368714df669a9bf427f989e90bcc7489040d7a074f98f81bdeaeb1"
    "2ab2"
)

ROOT_CERT_DER = bytes.fromhex(_ROOT_CERT_DER_HEX)
DEPUTY_CSR_DER = bytes.fromhex(_DEPUTY_CSR_DER_HEX)
DEPUTY_SUBJECT_VK = bytes.fromhex(_DEPUTY_SUBJECT_VK_HEX)
ROOT_CERT_NOT_BEFORE = 1_800_000_000
ROOT_CERT_NOT_AFTER = 1_800_000_000 + 7_300 * 86400  # ROOT_DAYS (7_300) * DAY, confirmed against cert_request.rs


def _flip_byte(data: bytes, offset: int) -> bytes:
    mutated = bytearray(data)
    mutated[offset] ^= 0xFF
    return bytes(mutated)


# --- parse_root_certificate_der ---

def test_parse_root_certificate_der_matches_the_real_reference_vector():
    parsed = parse_root_certificate_der(ROOT_CERT_DER)
    assert len(parsed.subject_vk) == ML_DSA_PK_LEN
    assert parsed.not_before == ROOT_CERT_NOT_BEFORE
    assert parsed.not_after == ROOT_CERT_NOT_AFTER
    assert parsed.chain_kind == ChainKind.TESTNET


def test_parse_root_certificate_der_rejects_garbage_der():
    with pytest.raises(CertRequestError):
        parse_root_certificate_der(b"not a certificate at all" * 20)


def test_parse_root_certificate_der_failure_message_names_plausible_causes():
    """ Regression test for 7f-review-parse-failure-messages-not-
        actionable: this used to be the same generic "couldn't parse the
        Root certificate" boilerplate regardless of cause. """
    with pytest.raises(CertRequestError) as exc_info:
        parse_root_certificate_der(b"not a certificate at all" * 20)
    assert "ERR_CERT_PARSE_FAILED" in str(exc_info.value)
    assert "X.509" in str(exc_info.value)


def test_parse_root_certificate_der_rejects_truncated_der():
    with pytest.raises(CertRequestError):
        parse_root_certificate_der(ROOT_CERT_DER[: len(ROOT_CERT_DER) // 2])


def test_parse_root_certificate_der_rejects_empty_input():
    with pytest.raises(CertRequestError):
        parse_root_certificate_der(b"")


# --- verify_and_parse_csr_der ---

def test_verify_and_parse_csr_der_matches_the_real_reference_vector():
    csr = verify_and_parse_csr_der(DEPUTY_CSR_DER)
    assert csr.subject_vk == DEPUTY_SUBJECT_VK


def test_verify_and_parse_csr_der_rejects_garbage_der():
    with pytest.raises(CertRequestError):
        verify_and_parse_csr_der(b"not a csr at all" * 20)


def test_verify_and_parse_csr_der_failure_message_names_plausible_causes():
    """ Mirrors test_parse_root_certificate_der_failure_message_names_
        plausible_causes for the CSR verification path. """
    with pytest.raises(CertRequestError) as exc_info:
        verify_and_parse_csr_der(b"not a csr at all" * 20)
    assert "ERR_CSR_VERIFY_FAILED" in str(exc_info.value)
    assert "PKCS#10" in str(exc_info.value)


def test_verify_and_parse_csr_der_rejects_truncated_der():
    with pytest.raises(CertRequestError):
        verify_and_parse_csr_der(DEPUTY_CSR_DER[: len(DEPUTY_CSR_DER) // 2])


def test_verify_and_parse_csr_der_rejects_empty_input():
    with pytest.raises(CertRequestError):
        verify_and_parse_csr_der(b"")


def test_verify_and_parse_csr_der_rejects_a_tampered_signature():
    """ Flips a byte near the end of the DER, inside the CSR's trailing
        ML-DSA-65 signature bytes -- proof-of-possession must fail closed
        when the signature itself has been altered in transit. """
    tampered = _flip_byte(DEPUTY_CSR_DER, len(DEPUTY_CSR_DER) - 50)
    with pytest.raises(CertRequestError):
        verify_and_parse_csr_der(tampered)


def test_verify_and_parse_csr_der_rejects_a_tampered_subject_key():
    """ Flips a byte inside the CSR's embedded subject public key (well
        before the signature bytes) -- the self-signature covers the whole
        CertificationRequestInfo, including the subject key, so this must
        fail closed exactly like a tampered signature. """
    tampered = _flip_byte(DEPUTY_CSR_DER, 200)
    with pytest.raises(CertRequestError):
        verify_and_parse_csr_der(tampered)


def test_verify_and_parse_csr_der_returned_vk_is_the_same_bytes_the_signature_covers():
    """ Binding property: the subject_vk this function hands back is exactly
        the bytes whose possession the verified signature just proved -- not
        a value re-extracted or re-parsed from anywhere else. Calling twice
        on the same real CSR must yield byte-identical output. """
    first = verify_and_parse_csr_der(DEPUTY_CSR_DER)
    second = verify_and_parse_csr_der(DEPUTY_CSR_DER)
    assert first.subject_vk == second.subject_vk == DEPUTY_SUBJECT_VK


# --- generate_serial ---

def test_generate_serial_default_length_and_positive():
    serial = generate_serial()
    assert len(serial) == 16
    assert serial[0] & 0x80 == 0


def test_generate_serial_respects_custom_length():
    serial = generate_serial(length=8)
    assert len(serial) == 8


def test_generate_serial_handles_the_single_byte_edge_case():
    """ Adversarial review follow-up: the high-bit-clearing mask (serial[0]
        &= 0x7F) must still leave a non-empty, positive single-byte serial
        rather than producing an edge-case bug at the smallest valid length. """
    serial = generate_serial(length=1)
    assert len(serial) == 1
    assert serial[0] & 0x80 == 0


def test_generate_serial_is_not_constant():
    # Not a statistical randomness test -- just confirms this isn't a stub
    # that always returns the same bytes.
    samples = {generate_serial() for _ in range(10)}
    assert len(samples) == 10


# --- build_deputy_tbs_v2 ---

def test_build_deputy_tbs_v2_succeeds_against_the_real_reference_vectors():
    serial = bytes([0x11]) * 16
    tbs = build_deputy_tbs_v2(ROOT_CERT_DER, DEPUTY_CSR_DER, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, serial)
    assert len(tbs) > 0


def test_build_deputy_tbs_v2_is_deterministic_for_the_same_inputs():
    serial = bytes([0x22]) * 16
    a = build_deputy_tbs_v2(ROOT_CERT_DER, DEPUTY_CSR_DER, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, serial)
    b = build_deputy_tbs_v2(ROOT_CERT_DER, DEPUTY_CSR_DER, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, serial)
    assert a == b


def test_build_deputy_tbs_v2_rejects_a_chain_kind_mismatch_against_the_real_root_cert():
    """ The real root certificate's own embedded chain_kind is Testnet --
        an operator-selected chain_kind of Mainnet must be refused, never
        silently overridden by whichever value the certificate carries. """
    serial = bytes([0x33]) * 16
    with pytest.raises(CertRequestError):
        build_deputy_tbs_v2(ROOT_CERT_DER, DEPUTY_CSR_DER, ChainKind.MAINNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, serial)


def test_build_deputy_tbs_v2_rejects_now_before_the_roots_own_not_before():
    serial = bytes([0x44]) * 16
    with pytest.raises(CertRequestError):
        build_deputy_tbs_v2(ROOT_CERT_DER, DEPUTY_CSR_DER, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE - 1, DEPUTY_DAYS, serial)


def test_build_deputy_tbs_v2_rejects_now_at_or_after_the_roots_own_not_after():
    serial = bytes([0x55]) * 16
    with pytest.raises(CertRequestError):
        build_deputy_tbs_v2(ROOT_CERT_DER, DEPUTY_CSR_DER, ChainKind.TESTNET, ROOT_CERT_NOT_AFTER, DEPUTY_DAYS, serial)


def test_build_deputy_tbs_v2_rejects_a_truncated_root_certificate():
    """ The device does not cryptographically verify the Root certificate's
        own signature (no CA root store on-device -- trust is established
        by the operator's enrollment-fingerprint cross-check instead, per
        the Gate-1 plan's §8). A bit-flip within the certificate body is
        therefore not guaranteed to be caught here; a structurally broken
        DER document must still be, since re-parsing happens on every call. """
    truncated = ROOT_CERT_DER[: len(ROOT_CERT_DER) // 2]
    serial = bytes([0x66]) * 16
    with pytest.raises(CertRequestError):
        build_deputy_tbs_v2(truncated, DEPUTY_CSR_DER, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, serial)


def test_build_deputy_tbs_v2_rejects_a_tampered_deputy_csr():
    tampered = _flip_byte(DEPUTY_CSR_DER, len(DEPUTY_CSR_DER) - 50)
    serial = bytes([0x77]) * 16
    with pytest.raises(CertRequestError):
        build_deputy_tbs_v2(ROOT_CERT_DER, tampered, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, serial)


def test_build_deputy_tbs_v2_rejects_an_empty_serial():
    """ ffi.rs's own doc comment: the caller must always supply a serial --
        this function never silently falls back to a different source of
        randomness. An empty serial must be refused, not substituted. """
    with pytest.raises(CertRequestError):
        build_deputy_tbs_v2(ROOT_CERT_DER, DEPUTY_CSR_DER, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, b"")


def test_build_deputy_tbs_v2_gives_a_different_message_per_distinct_failure_cause():
    """ Regression test for 7f-review-parse-failure-messages-not-
        actionable: mldsa7f_cert_deputy_tbs_v2 (ffi.rs) genuinely
        distinguishes a bad Root certificate (ERR_CERT_PARSE_FAILED) from
        a bad Deputy CSR (ERR_CSR_VERIFY_FAILED) from a chain/window
        mismatch in the TBS-build step itself (ERR_CERT_BUILD_FAILED) --
        this used to collapse all three into the same generic "couldn't
        build the Deputy certificate body" text, discarding a
        differentiation the FFI boundary already provides for free. """
    serial = bytes([0x33]) * 16
    truncated_root = ROOT_CERT_DER[: len(ROOT_CERT_DER) // 2]
    tampered_csr = _flip_byte(DEPUTY_CSR_DER, len(DEPUTY_CSR_DER) - 50)

    with pytest.raises(CertRequestError) as root_exc:
        build_deputy_tbs_v2(truncated_root, DEPUTY_CSR_DER, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, serial)
    with pytest.raises(CertRequestError) as csr_exc:
        build_deputy_tbs_v2(ROOT_CERT_DER, tampered_csr, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, serial)
    with pytest.raises(CertRequestError) as window_exc:
        build_deputy_tbs_v2(ROOT_CERT_DER, DEPUTY_CSR_DER, ChainKind.MAINNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, serial)

    root_msg, csr_msg, window_msg = str(root_exc.value), str(csr_exc.value), str(window_exc.value)
    assert "Root certificate" in root_msg
    assert "Deputy certificate request" in csr_msg
    assert "chain or validity window" in window_msg
    # All three really are distinct messages, not the same generic text three times.
    assert len({root_msg, csr_msg, window_msg}) == 3


# --- deputy_cross_cert_v2_review_fields: the no-blind-signing screen content ---

def test_deputy_cross_cert_v2_review_fields_includes_root_and_deputy_context():
    root_cert = parse_root_certificate_der(ROOT_CERT_DER)
    csr = verify_and_parse_csr_der(DEPUTY_CSR_DER)
    serial = bytes([0x88]) * 16
    fields = deputy_cross_cert_v2_review_fields(root_cert, csr, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, serial)
    assert all(isinstance(f, ReviewField) for f in fields)
    labels = [f.label for f in fields]
    assert labels == [
        "Issuing Root: Subject key id", "Issuing Root: Valid from", "Issuing Root: Valid until",
        "Chain", "Deputy: Subject key id", "Deputy: Valid from", "Deputy: Valid for",
        "Deputy: Valid until", "Deputy: Serial",
    ]
    by_label = {f.label: f.value for f in fields}
    assert by_label["Chain"] == "testnet"
    assert by_label["Deputy: Valid for"] == f"{DEPUTY_DAYS} days"
    assert str(ROOT_CERT_NOT_BEFORE + DEPUTY_DAYS * 86_400) in by_label["Deputy: Valid until"]
    assert by_label["Deputy: Serial"] == serial.hex()
    assert str(ROOT_CERT_NOT_BEFORE) in by_label["Issuing Root: Valid from"]


def test_deputy_cross_cert_v2_review_fields_valid_until_is_clamped_to_the_roots_own_window():
    """ Regression test for the clamp the display must mirror
        (cert_request.rs's own deputy_tbs_der_from_root_cert() clamps
        not_after to the issuing Root's own window) -- a naive
        now + days*DAY projection would overstate the real signed
        validity whenever the requested Deputy window outlives the Root's
        remaining one. """
    root_cert = parse_root_certificate_der(ROOT_CERT_DER)
    csr = verify_and_parse_csr_der(DEPUTY_CSR_DER)
    serial = bytes([0x77]) * 16
    # A deputy window of ROOT_DAYS*10 from the Root's own not_before
    # unclamped would run far past the Root's own ROOT_CERT_NOT_AFTER.
    fields = deputy_cross_cert_v2_review_fields(root_cert, csr, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, ROOT_DAYS * 10, serial)
    by_label = {f.label: f.value for f in fields}
    assert str(ROOT_CERT_NOT_AFTER) in by_label["Deputy: Valid until"]
    assert by_label["Deputy: Valid until"] == by_label["Issuing Root: Valid until"]


def test_deputy_cross_cert_v2_review_fields_key_ids_use_the_ski_convention():
    from seedsigner.models.sevenf.review_format import group_hex_for_display, ski
    root_cert = parse_root_certificate_der(ROOT_CERT_DER)
    csr = verify_and_parse_csr_der(DEPUTY_CSR_DER)
    serial = bytes([0x99]) * 16
    fields = deputy_cross_cert_v2_review_fields(root_cert, csr, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, serial)
    by_label = {f.label: f.value for f in fields}
    assert by_label["Issuing Root: Subject key id"] == group_hex_for_display(ski(root_cert.subject_vk.hex()))
    assert by_label["Deputy: Subject key id"] == group_hex_for_display(ski(csr.subject_vk.hex()))


def test_deputy_cross_cert_v2_review_fields_warnings_name_the_subject_key_id_not_a_fingerprint():
    """ 7fchain 3b39588/ce04ae9: what a holder reports by voice is the subject
        key id; "fingerprint" now names only the 8-hex transport-blob check, so
        telling the operator to compare against a "fingerprint" points them at
        the wrong value. """
    root_cert = parse_root_certificate_der(ROOT_CERT_DER)
    csr = verify_and_parse_csr_der(DEPUTY_CSR_DER)
    fields = deputy_cross_cert_v2_review_fields(root_cert, csr, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, bytes([0x99]) * 16)
    for f in fields:
        if f.is_warning:
            assert "fingerprint" not in f.warning_detail.lower()
            assert "subject key id" in f.warning_detail.lower()


def test_deputy_cross_cert_v2_review_fields_subject_key_id_fields_are_flagged_as_warning_fields():
    """ Mirrors test_root_self_cert_review_fields_subject_key_id_is_flagged_
        as_a_warning_field: both the Issuing Root's and the Deputy's own
        "Subject key id" fields are compensating controls (confirming the
        correct Root is trusted, and the correct Deputy is being
        certified, respectively) and must render distinctly. """
    root_cert = parse_root_certificate_der(ROOT_CERT_DER)
    csr = verify_and_parse_csr_der(DEPUTY_CSR_DER)
    serial = bytes([0x99]) * 16
    fields = deputy_cross_cert_v2_review_fields(root_cert, csr, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, serial)
    by_field = {f.label: f for f in fields}
    assert by_field["Issuing Root: Subject key id"].is_warning is True
    assert by_field["Issuing Root: Subject key id"].warning_detail
    assert by_field["Deputy: Subject key id"].is_warning is True
    assert by_field["Deputy: Subject key id"].warning_detail
    assert not by_field["Chain"].is_warning
    assert not by_field["Deputy: Serial"].is_warning


# --- Root self-certification: real-certificate assembly (PKCS#10-era rework) ---

def test_root_days_matches_the_real_reference_constant():
    # Confirmed directly against 7fchain's x509_ceremony.rs:42 (20 years),
    # distinct from DEPUTY_DAYS (10 years) -- see that constant's own
    # comment for the same cross-check applied there.
    assert ROOT_DAYS == 7_300


def _derive_root_keypair(chain_kind: ChainKind) -> bytes:
    """ A minimal, test-only key derivation (no Seed/root_ceremony fixture
        needed) -- just enough to exercise assemble_root_cert_der's full
        pipeline against a real ML-DSA-65 keypair. """
    from seedsigner.models.sevenf import mldsa
    from seedsigner.models.sevenf.path_lexicon import root_path
    master_seed = bytes([0x07]) * 64
    vk, _address = mldsa.derive_pubkey(master_seed, root_path(chain_kind))
    return vk, master_seed


def test_assemble_root_cert_der_full_pipeline_round_trip():
    """ No ASN.1 tooling exists in this Python environment to split the
        real captured reference certificate into its TBS/signature halves
        (that byte-exact round-trip is already proven at the Rust level,
        test_sevenf_cert_request.rs's own
        assemble_root_cert_der_matches_the_real_reference_certificate_exactly)
        -- this test instead exercises the full Python-bridge pipeline
        end to end against a real derived keypair: build -> sign ->
        assemble -> parse back, confirming the ctypes wiring itself is
        correct, not just the underlying Rust logic. """
    from seedsigner.models.sevenf import mldsa
    from seedsigner.models.sevenf.path_lexicon import root_path

    chain_kind = ChainKind.TESTNET
    vk, master_seed = _derive_root_keypair(chain_kind)
    serial = generate_serial()
    not_before = 1_750_000_000
    days = ROOT_DAYS

    tbs = build_root_tbs(vk, chain_kind, not_before, days, serial)
    _, signature = mldsa.derive_and_sign(master_seed, root_path(chain_kind), tbs)

    cert_der = assemble_root_cert_der(tbs, signature, vk)
    parsed = parse_root_certificate_der(cert_der)
    assert parsed.subject_vk == vk
    assert parsed.chain_kind == chain_kind
    assert parsed.not_before == not_before
    assert parsed.not_after == not_before + days * 86_400


def test_assemble_root_cert_der_rejects_a_tampered_signature():
    from seedsigner.models.sevenf import mldsa
    from seedsigner.models.sevenf.path_lexicon import root_path

    chain_kind = ChainKind.TESTNET
    vk, master_seed = _derive_root_keypair(chain_kind)
    tbs = build_root_tbs(vk, chain_kind, 1_750_000_000, ROOT_DAYS, generate_serial())
    _, signature = mldsa.derive_and_sign(master_seed, root_path(chain_kind), tbs)
    tampered = bytearray(signature)
    tampered[-1] ^= 0xFF

    with pytest.raises(CertRequestError):
        assemble_root_cert_der(tbs, bytes(tampered), vk)


def test_assemble_root_cert_der_rejects_garbage_tbs():
    with pytest.raises(CertRequestError):
        assemble_root_cert_der(b"not a tbs at all", bytes(3309), bytes(1952))


def test_assemble_root_cert_der_rejects_a_subject_vk_not_matching_the_tbs():
    from seedsigner.models.sevenf import mldsa
    from seedsigner.models.sevenf.path_lexicon import root_path

    chain_kind = ChainKind.TESTNET
    vk, master_seed = _derive_root_keypair(chain_kind)
    tbs = build_root_tbs(vk, chain_kind, 1_750_000_000, ROOT_DAYS, generate_serial())
    _, signature = mldsa.derive_and_sign(master_seed, root_path(chain_kind), tbs)
    other_vk = bytes([0xEE]) * 1952

    with pytest.raises(CertRequestError):
        assemble_root_cert_der(tbs, signature, other_vk)


def test_root_self_cert_review_fields_includes_subject_chain_dates_and_serial():
    vk = bytes([0xAB]) * 1952
    serial = bytes([0x11]) * 16
    not_before = 1_700_000_000
    not_after = not_before + ROOT_DAYS * 86_400
    fields = root_self_cert_review_fields(vk, ChainKind.TESTNET, not_before, not_after, serial)
    assert [f.label for f in fields] == ["Subject key id", "Chain", "Valid from", "Valid until", "Serial"]
    by_label = {f.label: f.value for f in fields}
    assert by_label["Chain"] == "testnet"
    assert by_label["Serial"] == serial.hex()
    assert str(not_before) in by_label["Valid from"]
    assert str(not_after) in by_label["Valid until"]


def test_root_self_cert_review_fields_key_id_uses_the_ski_convention():
    from seedsigner.models.sevenf.review_format import group_hex_for_display, ski
    vk = bytes([0xCD]) * 1952
    fields = root_self_cert_review_fields(vk, ChainKind.MAINNET, 1_700_000_000, 1_900_000_000, bytes([0x22]) * 16)
    by_label = {f.label: f.value for f in fields}
    assert by_label["Subject key id"] == group_hex_for_display(ski(vk.hex()))


def test_root_self_cert_review_fields_warning_names_the_subject_key_id_not_a_fingerprint():
    fields = root_self_cert_review_fields(bytes([0xCD]) * 1952, ChainKind.MAINNET, 1_700_000_000, 1_900_000_000, bytes([0x22]) * 16)
    warning = next(f for f in fields if f.is_warning)
    assert "fingerprint" not in warning.warning_detail.lower()
    assert "subject key id" in warning.warning_detail.lower()


def test_root_self_cert_review_fields_subject_key_id_is_flagged_as_a_warning_field():
    """ Regression test for 7f-review-enrollment-fingerprint-no-visual-
        distinction: "Subject key id" is the ENTIRE compensating control
        for the removed device-side Wrong-Key check, so it must render
        distinctly (is_warning=True) with real instruction text, not
        pixel-identical to the adjacent FYI fields. """
    vk = bytes([0xCD]) * 1952
    fields = root_self_cert_review_fields(vk, ChainKind.MAINNET, 1_700_000_000, 1_900_000_000, bytes([0x22]) * 16)
    by_field = {f.label: f for f in fields}
    assert by_field["Subject key id"].is_warning is True
    assert by_field["Subject key id"].warning_detail
    assert not by_field["Chain"].is_warning
    assert not by_field["Serial"].is_warning


# --- Deputy cross-certification: real-certificate assembly (closes the
# Deputy half of 7f-signing-support-detached-sig-export-unreconstructable) ---

def _fresh_root_cert(chain_kind: ChainKind, not_before: int = 1_800_000_000, seed_byte: int = 0x07) -> tuple[bytes, bytes, bytes]:
    """ A freshly derived Root keypair, assembled into a real, complete,
        self-signed certificate -- mirrors _derive_root_keypair() above but
        goes one step further (assemble, not just derive), since
        build_deputy_tbs_v2 needs a complete `root_cert_der` as its issuer
        context, not a bare key. No CSR-building capability exists in this
        codebase (see 7f-signing-support-hardware-test-tooling-pkcs10-staleness),
        so this is the one Deputy-flow input this test CAN build fresh;
        the Deputy's own CSR below instead reuses the real reference
        vector. `seed_byte` varies the derived identity (distinct from
        _derive_root_keypair's own hardcoded 0x07) so a "different Root"
        test case gets a genuinely different key, not the same one twice.
        Returns (root_cert_der, root_vk, root_master_seed). """

    master_seed = bytes([seed_byte]) * 64
    vk, _address = mldsa.derive_pubkey(master_seed, root_path(chain_kind))
    serial = generate_serial()
    tbs = build_root_tbs(vk, chain_kind, not_before, ROOT_DAYS, serial)
    _, signature = mldsa.derive_and_sign(master_seed, root_path(chain_kind), tbs)
    cert_der = assemble_root_cert_der(tbs, signature, vk)
    return cert_der, vk, master_seed


def test_assemble_deputy_cert_der_full_pipeline_round_trip():
    """ End to end against the ctypes bridge: a freshly derived+assembled
        Root certificate (this test's own, since no CSR-builder exists to
        make a fresh Deputy CSR -- see _fresh_root_cert's own docstring)
        issuing over the REAL reference Deputy CSR (DEPUTY_CSR_DER,
        self-signed by the real Deputy's own key, D12) -> build -> sign
        under the Root's key -> assemble -> parse back, confirming the
        final certificate's subject is the DEPUTY's key (not the Root's --
        the Root only ever signs, per cert_request.rs's own doc comment on
        the self-signed-vs-CA-issued distinction), and that the granted
        window/chain match what this ceremony run chose. """
    chain_kind = ChainKind.TESTNET
    not_before = 1_800_000_000
    root_cert_der, _root_vk, root_master_seed = _fresh_root_cert(chain_kind, not_before)
    deputy_csr = verify_and_parse_csr_der(DEPUTY_CSR_DER)
    serial = generate_serial()
    now = not_before + 86_400

    tbs = build_deputy_tbs_v2(root_cert_der, DEPUTY_CSR_DER, chain_kind, now, DEPUTY_DAYS, serial)
    _, signature = mldsa.derive_and_sign(root_master_seed, root_path(chain_kind), tbs)

    cert_der = assemble_deputy_cert_der(tbs, signature, root_cert_der)
    parsed = __import__('tools_helpers').parse_issued_cert(cert_der)  # a Deputy cert
    assert parsed.subject_vk == deputy_csr.subject_vk
    assert parsed.chain_kind == chain_kind
    assert parsed.not_before == now
    assert parsed.not_after == now + DEPUTY_DAYS * 86_400


def test_assemble_deputy_cert_der_rejects_a_tampered_signature():
    chain_kind = ChainKind.TESTNET
    not_before = 1_800_000_000
    root_cert_der, _root_vk, root_master_seed = _fresh_root_cert(chain_kind, not_before)
    tbs = build_deputy_tbs_v2(root_cert_der, DEPUTY_CSR_DER, chain_kind, not_before + 86_400, DEPUTY_DAYS, generate_serial())
    _, signature = mldsa.derive_and_sign(root_master_seed, root_path(chain_kind), tbs)
    tampered = bytearray(signature)
    tampered[-1] ^= 0xFF

    with pytest.raises(CertRequestError):
        assemble_deputy_cert_der(tbs, bytes(tampered), root_cert_der)


def test_assemble_deputy_cert_der_rejects_a_wrong_signer():
    """ A different Root's signature over the same TBS must not verify --
        confirms assemble_deputy_cert_der checks against THIS
        `root_cert_der`'s own embedded key, not merely "some valid
        ML-DSA-65 signature". """
    chain_kind = ChainKind.TESTNET
    not_before = 1_800_000_000
    root_cert_der, _root_vk, _root_master_seed = _fresh_root_cert(chain_kind, not_before)
    tbs = build_deputy_tbs_v2(root_cert_der, DEPUTY_CSR_DER, chain_kind, not_before + 86_400, DEPUTY_DAYS, generate_serial())

    _other_root_cert_der, _other_vk, other_master_seed = _fresh_root_cert(chain_kind, not_before, seed_byte=0x09)
    _, wrong_signature = mldsa.derive_and_sign(other_master_seed, root_path(chain_kind), tbs)

    with pytest.raises(CertRequestError):
        assemble_deputy_cert_der(tbs, wrong_signature, root_cert_der)


def test_assemble_deputy_cert_der_rejects_garbage_root_cert_der():
    with pytest.raises(CertRequestError):
        assemble_deputy_cert_der(bytes(2_368), bytes(3309), b"not a certificate at all")


def test_assemble_deputy_cert_der_rejects_garbage_tbs():
    chain_kind = ChainKind.TESTNET
    root_cert_der, _root_vk, _root_master_seed = _fresh_root_cert(chain_kind)
    with pytest.raises(CertRequestError):
        assemble_deputy_cert_der(b"not a tbs at all", bytes(3309), root_cert_der)


# --- PKCS#10 CSR building: test/tooling-only (closes
# 7f-signing-support-hardware-test-tooling-pkcs10-staleness) ---

def _derive_csr_keypair(seed_byte: int = 0x52) -> tuple[bytes, bytes]:
    """ A minimal, test-only key derivation -- mirrors _derive_root_keypair
        above (same master_seed/derive_pubkey shape), just under a distinct
        default seed byte so a CSR identity doesn't collide with a Root
        one in a test that builds both. """
    from seedsigner.models.sevenf import mldsa
    from seedsigner.models.sevenf.path_lexicon import root_path
    master_seed = bytes([seed_byte]) * 64
    vk, _address = mldsa.derive_pubkey(master_seed, root_path(ChainKind.TESTNET))
    return vk, master_seed


def test_csr_tooling_lib_fails_closed_when_the_library_lacks_the_feature():
    """ Regression test for an adversarial-review finding on
        7f-review-csr-tooling-ships-in-production-cdylib (2026-10-04): the
        fail-closed except-AttributeError branch in _csr_tooling_lib() was
        previously verified only by reading the code, never by a test that
        actually exercises it -- this runs unconditionally (not behind
        _csr_tooling_skipif), using a fake lib object that raises
        AttributeError for every attribute, the same failure ctypes itself
        raises for a real missing symbol, so it proves the fail-closed
        behavior regardless of whether this build happens to have
        --features test-tooling. """
    from seedsigner.models.sevenf import cert_request

    class _FakeLibMissingCsrTooling:
        def __getattr__(self, name):
            raise AttributeError(name)

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(mldsa, "_lib_handle", lambda: _FakeLibMissingCsrTooling())
        with pytest.raises(CertRequestError) as exc_info:
            cert_request._csr_tooling_lib()
    assert "test-tooling" in str(exc_info.value)


@_csr_tooling_skipif
def test_csr_info_der_and_assemble_csr_der_round_trip_through_verify_and_parse_csr():
    from seedsigner.models.sevenf import mldsa
    from seedsigner.models.sevenf.path_lexicon import root_path

    vk, master_seed = _derive_csr_keypair()
    info_der = csr_info_der(vk)
    _, signature = mldsa.derive_and_sign(master_seed, root_path(ChainKind.TESTNET), info_der)
    csr_der = assemble_csr_der(info_der, signature)
    parsed = verify_and_parse_csr_der(csr_der)
    assert parsed.subject_vk == vk


@_csr_tooling_skipif
def test_csr_info_der_round_trips_over_several_distinct_keys():
    from seedsigner.models.sevenf import mldsa
    from seedsigner.models.sevenf.path_lexicon import root_path

    for seed_byte in (0x61, 0x62, 0x63):
        vk, master_seed = _derive_csr_keypair(seed_byte)
        info_der = csr_info_der(vk)
        _, signature = mldsa.derive_and_sign(master_seed, root_path(ChainKind.TESTNET), info_der)
        csr_der = assemble_csr_der(info_der, signature)
        parsed = verify_and_parse_csr_der(csr_der)
        assert parsed.subject_vk == vk


@_csr_tooling_skipif
def test_csr_info_der_rejects_a_wrong_length_key():
    with pytest.raises(CertRequestError):
        csr_info_der(bytes([0x01]) * 100)


@_csr_tooling_skipif
def test_assemble_csr_der_rejects_a_tampered_signature():
    from seedsigner.models.sevenf import mldsa
    from seedsigner.models.sevenf.path_lexicon import root_path

    vk, master_seed = _derive_csr_keypair()
    info_der = csr_info_der(vk)
    _, signature = mldsa.derive_and_sign(master_seed, root_path(ChainKind.TESTNET), info_der)
    tampered = bytearray(signature)
    tampered[-1] ^= 0xFF

    with pytest.raises(CertRequestError):
        assemble_csr_der(info_der, bytes(tampered))


@_csr_tooling_skipif
def test_assemble_csr_der_rejects_a_wrong_signer():
    from seedsigner.models.sevenf import mldsa
    from seedsigner.models.sevenf.path_lexicon import root_path

    subject_vk, _subject_seed = _derive_csr_keypair(0x64)
    _impostor_vk, impostor_seed = _derive_csr_keypair(0x65)
    info_der = csr_info_der(subject_vk)
    _, wrong_signature = mldsa.derive_and_sign(impostor_seed, root_path(ChainKind.TESTNET), info_der)

    with pytest.raises(CertRequestError):
        assemble_csr_der(info_der, wrong_signature)


@_csr_tooling_skipif
def test_assemble_csr_der_rejects_garbage_info_der():
    with pytest.raises(CertRequestError):
        assemble_csr_der(b"not a csr info at all", bytes(3309))


def test_generated_serials_match_7fchains_masking():
    """ shared-crypto x509 masks b[0] = (b[0] & 0x7f) | 0x40: positive, and no
        leading zero byte, so the serial shown on review is exactly the one
        the DER INTEGER encodes (a 00 lead byte would be dropped). """
    from seedsigner.models.sevenf.cert_request import generate_serial
    for _ in range(2000):
        s = generate_serial()
        assert len(s) == 16 and 0x40 <= s[0] <= 0x7F


def test_a_csr_requesting_extensions_is_refused():
    """ sign-deputy-cert refuses a CSR that asks for extensions ("may not carry
        extension 2.5.29.19"); this one asks for CA:TRUE, pathlen 9 (built in
        the 2026-10-07 end-to-end run). The device must not certify it. """
    from pathlib import Path
    der = (Path(__file__).parent / "fixtures" / "deputy_csr_requesting_ca_pathlen9.der").read_bytes()
    with pytest.raises(CertRequestError, match="extension"):
        verify_and_parse_csr_der(der)


def test_a_real_sf_wallet_gov_csr_is_still_accepted():
    from pathlib import Path
    from seedsigner.models.sevenf.export_envelope import pem_to_der
    pem = (Path(__file__).parent / "fixtures" / "sf_wallet_gov_deputy_csr.pem").read_text()
    der = pem_to_der(pem.replace("CERTIFICATE REQUEST", "CERTIFICATE"))
    assert verify_and_parse_csr_der(der).subject_vk


# The extensionRequest walk is in the library now (cert_request.rs
# verify_and_parse_csr, sf-ca's issuing-CA policy), with its own tests there
# (csr_policy_tests); hostile DER is refused by the same Rust parser.


def test_the_deputy_tbs_builder_names_a_policy_refusal():
    """ Execution-stage review 2026-10-08: the library's -29 from the Deputy
        certificate builder was described as a chain or validity mismatch. """
    from pathlib import Path
    der = (Path(__file__).parent / "fixtures" / "deputy_csr_requesting_ca_pathlen9.der").read_bytes()
    with pytest.raises(CertRequestError, match="must ask for no extensions") as e:
        build_deputy_tbs_v2(ROOT_CERT_DER, der, ChainKind.TESTNET, ROOT_CERT_NOT_BEFORE, DEPUTY_DAYS, generate_serial())
    assert "validity window" not in str(e.value)
    with pytest.raises(CertRequestError, match="must ask for no extensions"):
        verify_and_parse_csr_der(der)
