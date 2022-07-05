// EDHOC Test Vectors
//
// These test vectors are based on the -11 version of the draft
// https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-11
//
// Copyright (c) 2021, Ericsson and John Preuß Mattsson <john.mattsson@ericsson.com>
//
// This software may be distributed under the terms of the 3-Clause BSD License.

#include <iostream>
#include <iomanip>
#include <vector>
#include <variant>
#include <psa/crypto.h>
#include <mbedtls/ccm.h>

using namespace std;
using vec = vector<uint8_t>;
using intVec = std::variant<int, vec>;

enum EDHOCKeyType { sig, sdh };
enum COSECred { cred_uccs, cred_cwt, cred_x509, cred_c509 };
enum COSEHeader { kid = 4, x5bag = 32, x5chain = 33, x5t = 34, x5u = 35, cwt = 42, uccs = 43 }; // cwt / uccs is TDB, 42 and 43 are just examples
enum COSEAlgorithm { SHA_256 = -16, SHA_256_64 = -15, EdDSA = -8, ES256 = -7, AES_CCM_16_64_128 = 10, AES_CCM_16_128_128 = 30 };
enum COSECurve { P_256 = 1, X25519 = 4, Ed25519 = 6 };
enum COSECommon { kty = 1 };
enum COSEKCP { kcp_kid = 2 };
enum COSEKTP { x = -2, y = -3, crv = -1, OKP = 1, EC2 = 2 };
enum CWTClaims { sub = 2, cnf = 8 };
enum ConfMethod { COSE_Key = 1 };

const bool isjson = true;
int vector_nr = 1;

// Concatenates two vectors
vec operator+( vec a, vec b ) {
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}


// Fatal error
void syntax_error( string s ) {
    cout << "Syntax Error: " << s;
    exit(-1);
}

// Print an int to cout
void print( string s, int i ) {
    cout << endl << dec << s << " (int)" << endl << i << endl;
}

// Print a vec to cout
void print( string s, vec v ) {
    cout << endl << dec << s << " (" << v.size() << " bytes)";
    if  ( v.size() )
        cout << endl;
    for ( int i = 1; i <= v.size(); i++ ) {
        cout << hex << setfill('0') << setw( 2 ) << (int)v[i-1];
        if ( i < v.size() ) {
            if ( i % 23 == 0 ) {
                cout << endl;
            } else {
                cout << " ";
            }
        }
    }
    cout << endl;
}

// Print an int to cout
void print_json( string s, int i, bool comma = true ) {
    cout << endl << dec << "      \"" << s << "\": " << i;
    if ( comma == true )
        cout << ",";
}

// Print a vec to cout
void print_json( string s, vec v, bool comma = true  ) {
    cout << endl << dec << "      \"" << s << "\": \"";
    for ( int i = 1; i <= v.size(); i++ ) {
        cout << hex << setfill('0') << setw( 2 ) << (int)v[i-1];
    }
    cout << "\"";
    if ( comma == true )
        cout << ",";
}

// Helper funtion for CBOR encoding
vec cbor_unsigned_with_type( uint8_t type, int i ) {
    type = type << 5;
    if ( i < 0 || i > 0xFFFF )
        syntax_error( "cbor_unsigned_with_type()" );
    if ( i < 24 )
        return { (uint8_t) (type | i) };
    else if ( i < 0x100 )
        return { (uint8_t) (type | 0x18), (uint8_t) i };
    else
        return { (uint8_t) (type | 0x19), (uint8_t) (i >> 8), (uint8_t) (i & 0xFF) };
}

// CBOR encodes an int
vec cbor( int i ) {
    if ( i < 0 )
        return cbor_unsigned_with_type( 1, -(i + 1) );
    else
        return cbor_unsigned_with_type( 0, i );
}

// CBOR encodes a bstr
 vec cbor( vec v ) {
    return cbor_unsigned_with_type( 2, v.size() ) + v;
}

// CBOR encodes a tstr
vec cbor( string s ) {
    return cbor_unsigned_with_type( 3, s.size() ) + vec( s.begin(), s.end() );
}

vec cbor_arr( int length ) {
    return cbor_unsigned_with_type( 4, length );
}

vec cbor_map( int length ) {
    return cbor_unsigned_with_type( 5, length );
}

vec cbor_tag( int value ) {
    return cbor_unsigned_with_type( 6, value );
}

// Compress ID_CRED_x if it contains a single 'kid' parameter
vec compress_id_cred( vec v ) {
    if ( vec{ v[0], v[1] } == cbor_map( 1 ) + cbor( kid ) )
        return vec( v.begin() + 2, v.end() );
    else
        return v;
}

// OSCORE id from EDHOC connection id
// This function does not work with bstr with length 24 or more
vec OSCORE_id( vec v ) {
    if ( v[0] >= 0x40 && v[0] <= 0x57 ) {
        return vec( v.begin() + 1, v.end() );
    } else {
        return v;
    }
}

// Calculates the hash of m
vec HASH( int alg, vec m ) {
    if ( alg != SHA_256 && alg != SHA_256_64 )
        syntax_error( "hash()" );

    vec digest( PSA_HASH_LENGTH(PSA_ALG_SHA_256) );
    
    size_t length = 0;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, m.data(), m.size(), digest.data() + 0, digest.size(), &length);

    if (status != PSA_SUCCESS)
        syntax_error( "hash()" );

    if ( alg == SHA_256_64 )
        digest.resize( 8 );
    
    return digest;
}

vec hmac( int alg, vec k, vec m ) {
    if ( alg != SHA_256 )
        syntax_error( "hmac()" );
    
    psa_algorithm_t algorithm = PSA_ALG_SHA_256;
    
    vec out( PSA_HASH_LENGTH(algorithm) );

    psa_key_id_t key = PSA_KEY_HANDLE_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags( &attributes, PSA_KEY_USAGE_SIGN_HASH );
    psa_set_key_algorithm( &attributes, PSA_ALG_HMAC(algorithm) );
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_import_key( &attributes, k.data(), k.size(), &key);
    
    size_t length = 0;
    psa_status_t status = psa_mac_compute(key, PSA_ALG_HMAC(algorithm), m.data(), m.size(), out.data() + 0, out.size(), &length);
    
    psa_destroy_key(key);
    
    if (status != PSA_SUCCESS)
        syntax_error( "hmac()" );

    return out;
}

vec hkdf_expand( int alg, vec PRK, vec info, int L ) {
    vec out, T;
    for ( int i = 0; i <= L / 32; i++ ) {
        vec m = T + info + vec{ uint8_t( i + 1 ) };
        T = hmac( alg, PRK, m );
        out = out + T;
    }
    out.resize( L );
    return out;
}

vec xor_encryption( vec K, vec P ) {
    for( int i = 0; i < P.size(); ++i )
        P[i] ^= K[i];
    return P;
}

vec random_vector( int len ) {
    vec out( len );
    for( auto& i : out )
        i = rand();
    return out;
}

vec sequence_vector( int len ) {
    vec out( len );
    for( int i = 0; i < len; i++ )
        out[i] = i;
    return out;
}

vec random_ead() {
    vec out;
    int len = rand() % 5;
    for( int i = 0; i < len; i++ ) {
        int ead_type = rand() % 6;
        if ( ead_type == 0 ) {
            out = out + cbor( rand() % 100 ) + vec{ 0xf5 };
        } else if ( ead_type == 1 ) {
            out = out + cbor( rand() % 100 ) + cbor( sequence_vector( 5 + rand() % 15 ) );
        } else if ( ead_type == 2 ) {
            out = out + cbor( rand() % 100 ) + vec{ 0xfb, 0x40, 0x09, 0x1E, 0xB8, 0x51, 0xEB, 0x85, 0x1F };
        } else if ( ead_type == 3 ) {
            out = out + cbor( rand() % 100 ) + cbor( rand() % 10000 );
        } else if ( ead_type == 4 ) {
            out = out + cbor( rand() % 100 ) + cbor_arr(2) + cbor( sequence_vector( 5 + rand() % 5 ) ) + cbor( sequence_vector( 5 + rand() % 5 ) );
        } else if ( ead_type == 5 ) {
            out = out + cbor( rand() % 100 ) + cbor_map(1) + vec{ 0xf6 } + cbor( sequence_vector( 5 + rand() % 5 ) );
        }
    }
    return out;
}

// TODO other COSE algorithms like ECDSA, P-256, SHA-384, P-384, AES-GCM, ChaCha20-Poly1305
void test_vectors( EDHOCKeyType type_I, COSECred credtype_I, COSEHeader attr_I,
                   EDHOCKeyType type_R, COSECred credtype_R, COSEHeader attr_R,
                   int selected_suite, int seed, bool complex = false, bool comma = true ) {
    
    if ( psa_crypto_init() != PSA_SUCCESS )
        syntax_error( "psa_crypto_init()" );
    
    // METHOD and seed random number generation
    int method = 2 * type_I + type_R;
    vec METHOD = cbor( method );
    srand( seed );

    // EDHOC and OSCORE algorithms
    int edhoc_hash_alg;
    int edhoc_ecdh_curve;
    int edhoc_sign_alg;
    int edhoc_sign_curve;
    int oscore_aead_alg = AES_CCM_16_64_128;
    int oscore_hash_alg = SHA_256;

    int edhoc_aead_alg, edhoc_mac_length_2 = 32, edhoc_mac_length_3 = 32;
    vec SUITES_I;
    
    // supported suites = 0, 2, 1, 3, 4, 5
    if ( selected_suite == 0 ) {
        SUITES_I = cbor( 0 );
        
        edhoc_hash_alg = SHA_256;
        edhoc_ecdh_curve = X25519;
        edhoc_sign_alg = EdDSA;
        edhoc_sign_curve = Ed25519;
        
        edhoc_aead_alg = AES_CCM_16_64_128;
        if ( type_R == sdh )
            edhoc_mac_length_2 = 8;
        if ( type_I == sdh )
            edhoc_mac_length_3 = 8;
    } else
    if ( selected_suite == 1 ) {
        SUITES_I = cbor_arr( 3 ) + cbor( 0 ) + cbor( 2 ) + cbor( 1 );
        
        edhoc_hash_alg = SHA_256;
        edhoc_ecdh_curve = X25519;
        edhoc_sign_alg = EdDSA;
        edhoc_sign_curve = Ed25519;
       
        edhoc_aead_alg = AES_CCM_16_128_128;
        if ( type_R == sdh )
            edhoc_mac_length_2 = 16;
        if ( type_I == sdh )
            edhoc_mac_length_3 = 16;
    } else
    if ( selected_suite == 2 ) {
        SUITES_I = cbor_arr( 2 ) + cbor( 6 ) + cbor( 2 );
        
        edhoc_hash_alg = SHA_256;
        edhoc_ecdh_curve = P_256;
        edhoc_sign_alg = ES256;
        edhoc_sign_curve = P_256;
        
        edhoc_aead_alg = AES_CCM_16_64_128;
        if ( type_R == sdh )
            edhoc_mac_length_2 = 8;
        if ( type_I == sdh )
            edhoc_mac_length_3 = 8;
    } else
    if ( selected_suite == 3 ) {
        SUITES_I = cbor_arr( 2 ) + cbor( 2 ) + cbor( 3 );
        
        edhoc_hash_alg = SHA_256;
        edhoc_ecdh_curve = P_256;
        edhoc_sign_alg = ES256;
        edhoc_sign_curve = P_256;
        
        edhoc_aead_alg = AES_CCM_16_128_128;
        if ( type_R == sdh )
            edhoc_mac_length_2 = 16;
        if ( type_I == sdh )
            edhoc_mac_length_3 = 16;
    }
    

    // Calculate Ephemeral keys
    auto key_pair = [=] (psa_algorithm_t alg, psa_ecc_family_t ecc_family, size_t key_bits) {

        psa_key_id_t key = PSA_KEY_HANDLE_INIT;
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_SIGN_HASH);
        psa_set_key_algorithm(&attributes, alg);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(ecc_family));
        psa_set_key_bits(&attributes, key_bits);

        psa_status_t status = psa_generate_key(&attributes, &key);

        if (status != PSA_SUCCESS)
            syntax_error("key_pair()");

        size_t key_len = 0;
        size_t public_key_len = 0;

        uint8_t key_data[PSA_EXPORT_KEY_PAIR_MAX_SIZE];
        uint8_t public_key_data[PSA_EXPORT_KEY_PAIR_MAX_SIZE];

        psa_export_key(key, key_data, sizeof(key_data), &key_len );
        psa_export_public_key(key, public_key_data, sizeof(public_key_data), &public_key_len );

        vec G_Z(&public_key_data[0], &public_key_data[public_key_len]);
        vec Z(&key_data[0], &key_data[key_len]);

        return make_tuple( key, Z, G_Z );
    };

    auto key_pair2 = [=] (psa_algorithm_t alg, psa_ecc_family_t ecc_family, size_t key_bits, vec K) {

        psa_key_id_t key = PSA_KEY_HANDLE_INIT;
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_SIGN_HASH);
        psa_set_key_algorithm(&attributes, alg);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(ecc_family));
        psa_set_key_bits(&attributes, key_bits);

        psa_status_t status = psa_import_key(&attributes, K.data(), K.size(), &key);

        if (status != PSA_SUCCESS)
            syntax_error("key_pair()");
        
        size_t key_len = 0;
        size_t public_key_len = 0;
        
        uint8_t key_data[PSA_EXPORT_KEY_PAIR_MAX_SIZE];
        uint8_t public_key_data[PSA_EXPORT_KEY_PAIR_MAX_SIZE];
        
        psa_export_key(key, key_data, sizeof(key_data), &key_len );
        psa_export_public_key(key, public_key_data, sizeof(public_key_data), &public_key_len );
        
        vec G_Z(&public_key_data[0], &public_key_data[public_key_len]);
        vec Z(&key_data[0], &key_data[key_len]);
        
        return make_tuple( key, Z, G_Z );
    };

    auto shared_secret = [=] ( psa_key_id_t A, vec G_B ) {
        
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_get_key_attributes(A, &attributes);
        psa_key_type_t type = psa_get_key_type(&attributes);
        size_t bits = psa_get_key_bits(&attributes);
        
        vec G_AB( PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(type, bits) );
        
        size_t length = 0;
        psa_status_t status = psa_raw_key_agreement(PSA_ALG_ECDH, A, G_B.data(), G_B.size(), G_AB.data() + 0, G_AB.size(), &length);
        
        if (status != PSA_SUCCESS)
            syntax_error("shared_secret()");
            
        return G_AB;
    };
    
    auto compress_PK = [=] ( vec PK_X, int curve) {
        if (curve != P_256)
            return make_tuple( PK_X, PK_X );
        
        vec PK_X_x;
        // https://github.com/lake-wg/edhoc/pull/256
        // PK_X_compressed.insert(PK_X_compressed.begin(), 1, 0x02 );
        PK_X_x.insert(PK_X_x.begin(), PK_X.begin() + 1, PK_X.begin() + 33);
        
        vec PK_X_y;
        // https://github.com/lake-wg/edhoc/pull/256
        // PK_X_compressed.insert(PK_X_compressed.begin(), 1, 0x02 );
        PK_X_y.insert(PK_X_y.begin(), PK_X.begin() + 33, PK_X.begin() + 65);
        
        return make_tuple( PK_X_x, PK_X_y );
    };
    
        
    int family;
    size_t bits;
    
    switch (edhoc_ecdh_curve) {
        case X25519:
            family = PSA_ECC_FAMILY_TWISTED_EDWARDS;
            bits = 255;
            break;
        case P_256:
            family = PSA_ECC_FAMILY_SECP_R1;
            bits = 256;
            break;
        default:
            family = -1;
            bits = -1;
            break;
    }

    // auto [ key_x, X, G_X ] = key_pair(PSA_ALG_ECDH, family, bits);
    // auto [ key_y, Y, G_Y ] = key_pair(PSA_ALG_ECDH, family, bits);

    // PRKs
    vec SK_X = vec { 0x36, 0x8E, 0xC1, 0xF6, 0x9A, 0xEB, 0x65, 0x9B, 0xA3, 0x7D, 0x5A, 0x8D, 0x45, 0xB2, 0x1B, 0xDC, 0x02, 0x99, 0xDC, 0xEA, 0xA8, 0xEF, 0x23, 0x5F, 0x3C, 0xA4, 0x2C, 0xE3, 0x53, 0x0F, 0x95, 0x25 };
    vec SK_Y = vec { 0xE2, 0xF4, 0x12, 0x67, 0x77, 0x20, 0x5E, 0x85, 0x3B, 0x43, 0x7D, 0x6E, 0xAC, 0xA1, 0xE1, 0xF7, 0x53, 0xCD, 0xCC, 0x3E, 0x2C, 0x69, 0xFA, 0x88, 0x4B, 0x0A, 0x1A, 0x64, 0x09, 0x77, 0xE4, 0x18 };
    
    auto [ key_x, X, G_X ] = key_pair2(PSA_ALG_ECDH, family, bits, SK_X);
    auto [ key_y, Y, G_Y ] = key_pair2(PSA_ALG_ECDH, family, bits, SK_Y);
    
    vec G_XY = shared_secret( key_x, G_Y );
            
    auto [ G_X_x, G_X_y ] = compress_PK(G_X, edhoc_sign_curve);
    auto [ G_Y_x, G_Y_y ] = compress_PK(G_Y, edhoc_sign_curve);
    
    // Responder Keys
    vec SK_R = vec{ 0x72, 0xCC, 0x47, 0x61, 0xDB, 0xD4, 0xC7, 0x8F, 0x75, 0x89, 0x31, 0xAA, 0x58, 0x9D, 0x34, 0x8D, 0x1E, 0xF8, 0x74, 0xA7, 0xE3, 0x03, 0xED, 0xE2, 0xF1, 0x40, 0xDC, 0xF3, 0xE6, 0xAA, 0x4A, 0xAC };

    vec PK_R = vec{ 0x04, 0xBB, 0xC3, 0x49, 0x60, 0x52, 0x6E, 0xA4, 0xD3, 0x2E, 0x94, 0x0C, 0xAD, 0x2A, 0x23, 0x41, 0x48, 0xDD, 0xC2, 0x17, 0x91, 0xA1, 0x2A, 0xFB, 0xCB, 0xAC, 0x93, 0x62, 0x20, 0x46, 0xDD, 0x44, 0xF0, 0x45, 0x19, 0xE2, 0x57, 0x23, 0x6B, 0x2A, 0x0C, 0xE2, 0x02, 0x3F, 0x09, 0x31, 0xF1, 0xF3, 0x86, 0xCA, 0x7A, 0xFD, 0xA6, 0x4F, 0xCD, 0xE0, 0x10, 0x8C, 0x22, 0x4C, 0x51, 0xEA, 0xBF, 0x60, 0x72};
    
    // Initiator Keys
    vec SK_I = vec{  0xFB, 0x13, 0xAD, 0xEB, 0x65, 0x18, 0xCE, 0xE5, 0xF8, 0x84, 0x17, 0x66, 0x08, 0x41, 0x14, 0x2E, 0x83, 0x0A, 0x81, 0xFE, 0x33, 0x43, 0x80, 0xA9, 0x53, 0x40, 0x6A, 0x13, 0x05, 0xE8, 0x70, 0x6B };

    vec PK_I = vec{ 0x04, 0xAC, 0x75, 0xE9, 0xEC, 0xE3, 0xE5, 0x0B, 0xFC, 0x8E, 0xD6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5C, 0x47, 0xBF, 0x16, 0xDF, 0x96, 0x66, 0x0A, 0x41, 0x29, 0x8C, 0xB4, 0x30, 0x7F, 0x7E, 0xB6, 0x6E, 0x5D, 0xE6, 0x11, 0x38, 0x8A, 0x4B, 0x8A, 0x82, 0x11, 0x33, 0x4A, 0xC7, 0xD3, 0x7E, 0xCB, 0x52, 0xA3, 0x87, 0xD2, 0x57, 0xE6, 0xDB, 0x3C, 0x2A, 0x93, 0xDF, 0x21, 0xFF, 0x3A, 0xFF, 0xC8};
    
    auto [ key_r, R, G_R ] = key_pair2(PSA_ALG_ECDH, family, bits, SK_R);
    auto [ key_i, I, G_I ] = key_pair2(PSA_ALG_ECDH, family, bits, SK_I);

    vec G_RX = shared_secret( key_r, G_X );
    vec G_IY = shared_secret( key_i, G_Y );
    
    auto [ G_R_x, G_R_y ] = compress_PK(G_R, edhoc_sign_curve);
    auto [ G_I_x, G_I_y ] = compress_PK(G_I, edhoc_sign_curve);

    // Raw Keys
    G_R = G_R_x;
    G_I = G_I_x;
    
    // Raw Keys
    G_X = G_X_x;
    G_Y = G_Y_x;
    
    // PRKs
    auto [ sing_key_r, SK_R_gen, PK_R_gen ] = key_pair2(PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256), family, bits, SK_R);
    auto [ sing_key_i, SK_I_gen, PK_I_gen ] = key_pair2(PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256), family, bits, SK_I);
    
    auto hkdf_extract = [=] ( vec salt, vec IKM ) { return hmac( edhoc_hash_alg, salt, IKM ); };
    
    // Functions for kid and connection IDs.
    auto identifier = [=] () {
        if ( complex == true )
            if ( rand() % 2 == 0 ) {
                vec v = random_vector( 2 + rand() % 2 );
                return make_tuple( cbor( v ), (intVec)v );
            } else {
                int j = rand() % 16777216;
                return make_tuple( cbor( j ), (intVec)j );
            }
        else {
            int i = rand() % 49;
            if ( i == 48 ) {
                vec v = vec{};
                return make_tuple( cbor( v ), (intVec)v );
            } else {
                int j = i - 24;
                return make_tuple( cbor( j ), (intVec)j );
            }
        }
    };
 
    // Calculate C_I, C_R
    auto [ C_I, C_I_raw ] = identifier();
    auto [ C_R, C_R_raw ] = identifier();
    if ( seed == 34400 ) {
        vec v = vec{};
        C_R =  cbor( v );
        C_R_raw = (intVec)v;
    }
    if ( C_I == C_R ) { // Not allowed for OSCORE
        syntax_error( "C_I == C_R" );
    }

    // Calculate ID_CRED_x and CRED_x
    auto gen_CRED = [=] ( EDHOCKeyType type, COSECred credtype, COSEHeader attr, vec PK_sig, vec PK_sdh, string name, string uri, vec X509, int edhoc_sign_curve ) {
        auto [ kid_id, kid_id_raw ] = identifier();
        vec uccs_map = cbor_map( 2 )
        + cbor( sub ) + cbor( name )
        + cbor( cnf ) + cbor_map( 1 )
        + cbor( COSE_Key ) + cbor_map( 5 )
        + cbor( kty ) + cbor( EC2 )
        + cbor( kcp_kid ) + kid_id
        + cbor( crv );
        
        auto [ PK_x, PK_y ] = compress_PK(( type == sdh ) ? PK_sdh : ( type == sig ) ? PK_sig: vec {} , edhoc_sign_curve);
        
        uccs_map = uccs_map + cbor( edhoc_sign_curve ) + cbor( x ) + cbor( PK_x ) + cbor( y ) + cbor( PK_y );

        vec CRED, ID_CRED = cbor_map( 1 ) + cbor( attr );
        if ( credtype == cred_uccs && attr == kid ) {
            CRED = uccs_map;
            ID_CRED = ID_CRED + kid_id;
        } else if ( credtype == cred_uccs && attr == uccs ) {
            CRED = uccs_map;
            ID_CRED = ID_CRED + uccs_map;
        } else if ( credtype == cred_cwt && attr == cwt ) {  // TODO TODO, this is UCCS in -10 test vectors
            CRED = uccs_map;
            ID_CRED = ID_CRED + uccs_map;
        } else if ( credtype == cred_x509 ) {  // TODO TODO, this is UCCS in -10 test vectors
            CRED = cbor( X509 );
            ID_CRED = cbor_map( 1 ) + cbor( attr );
            if ( attr == x5bag ||  attr == x5chain )
                ID_CRED = ID_CRED + cbor( X509 );
            if ( attr == x5t )
                ID_CRED = ID_CRED + cbor_arr( 2 ) + cbor( SHA_256_64 ) + cbor( HASH( SHA_256_64, X509 ) );
            if ( attr == x5u )
                ID_CRED = ID_CRED + cbor_tag( 32 ) + cbor( uri );
        } else {
            syntax_error( "ID_CRED_x, CRED_x combination not supported" );
        }
        return make_tuple( ID_CRED, CRED );
    };

    // Responders Certificate
    vec cred_r = vec{ 0x30, 0x82, 0x01, 0x1E, 0x30, 0x81, 0xC5, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x61, 0xE9, 0x98, 0x1E, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0A, 0x45, 0x44, 0x48, 0x4F, 0x43, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x31, 0x32, 0x30, 0x31, 0x37, 0x31, 0x33, 0x30, 0x32, 0x5A, 0x17, 0x0D, 0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x1A, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x45, 0x44, 0x48, 0x4F, 0x43, 0x20, 0x52, 0x65, 0x73, 0x70, 0x6F, 0x6E, 0x64, 0x65, 0x72, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xBB, 0xC3, 0x49, 0x60, 0x52, 0x6E, 0xA4, 0xD3, 0x2E, 0x94, 0x0C, 0xAD, 0x2A, 0x23, 0x41, 0x48, 0xDD, 0xC2, 0x17, 0x91, 0xA1, 0x2A, 0xFB, 0xCB, 0xAC, 0x93, 0x62, 0x20, 0x46, 0xDD, 0x44, 0xF0, 0x45, 0x19, 0xE2, 0x57, 0x23, 0x6B, 0x2A, 0x0C, 0xE2, 0x02, 0x3F, 0x09, 0x31, 0xF1, 0xF3, 0x86, 0xCA, 0x7A, 0xFD, 0xA6, 0x4F, 0xCD, 0xE0, 0x10, 0x8C, 0x22, 0x4C, 0x51, 0xEA, 0xBF, 0x60, 0x72, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x30, 0x19, 0x4E, 0xF5, 0xFC, 0x65, 0xC8, 0xB7, 0x95, 0xCD, 0xCD, 0x0B, 0xB4, 0x31, 0xBF, 0x83, 0xEE, 0x67, 0x41, 0xC1, 0x37, 0x0C, 0x22, 0xC8, 0xEB, 0x8E, 0xE9, 0xED, 0xD2, 0xA7, 0x05, 0x19, 0x02, 0x21, 0x00, 0xB5, 0x83, 0x0E, 0x9C, 0x89, 0xA6, 0x2A, 0xC7, 0x3C, 0xE1, 0xEB, 0xCE, 0x00, 0x61, 0x70, 0x7D, 0xB8, 0xA8, 0x8E, 0x23, 0x70, 0x9B, 0x4A, 0xCC, 0x58, 0xA1, 0x31, 0x3B, 0x13, 0x3D, 0x05, 0x58 };
    
    // Initiator Certificate
    vec cred_i = vec{ 0x30, 0x82, 0x01, 0x1E, 0x30, 0x81, 0xC5, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x62, 0x32, 0xEF, 0x6F, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0A, 0x45, 0x44, 0x48, 0x4F, 0x43, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x33, 0x31, 0x37, 0x30, 0x38, 0x32, 0x31, 0x30, 0x33, 0x5A, 0x17, 0x0D, 0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x1A, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x45, 0x44, 0x48, 0x4F, 0x43, 0x20, 0x49, 0x6E, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6F, 0x72, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xAC, 0x75, 0xE9, 0xEC, 0xE3, 0xE5, 0x0B, 0xFC, 0x8E, 0xD6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5C, 0x47, 0xBF, 0x16, 0xDF, 0x96, 0x66, 0x0A, 0x41, 0x29, 0x8C, 0xB4, 0x30, 0x7F, 0x7E, 0xB6, 0x6E, 0x5D, 0xE6, 0x11, 0x38, 0x8A, 0x4B, 0x8A, 0x82, 0x11, 0x33, 0x4A, 0xC7, 0xD3, 0x7E, 0xCB, 0x52, 0xA3, 0x87, 0xD2, 0x57, 0xE6, 0xDB, 0x3C, 0x2A, 0x93, 0xDF, 0x21, 0xFF, 0x3A, 0xFF, 0xC8, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0x8C, 0x32, 0x3A, 0x1F, 0x33, 0x21, 0x38, 0xAA, 0xB9, 0xD0, 0xBE, 0xAF, 0xB8, 0x5F, 0x8D, 0x5A, 0x44, 0x07, 0x3C, 0x58, 0x0F, 0x59, 0x5B, 0xC5, 0x21, 0xEF, 0x91, 0x3F, 0x6E, 0xF4, 0x8D, 0x11, 0x02, 0x20, 0x6C, 0x0A, 0xF1, 0xA1, 0x85, 0xA4, 0xE4, 0xDE, 0x06, 0x35, 0x36, 0x99, 0x23, 0x1C, 0x73, 0x3A, 0x6E, 0x8D, 0xD2, 0xDF, 0x65, 0x13, 0x96, 0x6C, 0x91, 0x30, 0x15, 0x2A, 0x07, 0xA2, 0xBE, 0xDE };

    auto [ ID_CRED_I, CRED_I ] = gen_CRED( type_I, credtype_I, attr_I, PK_I, PK_I, "42-50-31-FF-EF-37-32-39", "https://example.edu/2716057",cred_i, edhoc_sign_curve );
    auto [ ID_CRED_R, CRED_R ] = gen_CRED( type_R, credtype_R, attr_R, PK_R, PK_R, "example.edu", "https://example.edu/3370318", cred_r, edhoc_sign_curve );

    // External Authorization Data
    vec EAD_1, EAD_2, EAD_3, EAD_4;
    if ( complex == true ) {
        EAD_1 = random_ead();
        EAD_2 = random_ead();
        EAD_3 = random_ead();
        EAD_4 = random_ead();
    }
 
    vec message_1 = METHOD + SUITES_I + cbor( G_X ) + C_I + EAD_1;

    // Helper funtions using local variables ////////////////////////////////////////////////////////////////////////////

    auto H = [=] ( vec input ) { return HASH( edhoc_hash_alg, input ); };
    auto A = [] ( vec protect, vec external_aad ) { return cbor_arr( 3 ) + cbor( "Encrypt0" ) + protect + external_aad; };
    auto M = [] ( vec protect, vec external_aad, vec payload ) { return cbor_arr( 4 ) + cbor( "Signature1" ) + protect + external_aad + payload; };

    auto AEAD = [=] ( vec K, vec N, vec P, vec A ) {
        if( A.size() > (42 * 16 - 2) )
            syntax_error( "AEAD()" );
        
        int tag_length = ( edhoc_aead_alg == AES_CCM_16_64_128 ) ? 8 : 16;
        vec C( P.size() + tag_length );
        vec C2( P.size() + tag_length );
        
        psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, tag_length);
        
        psa_key_id_t key = PSA_KEY_HANDLE_INIT;
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&attributes, alg);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&attributes, 128);
                
        psa_status_t status = psa_import_key(&attributes, K.data(), K.size(), &key);
        
        size_t length = 0;
        status = psa_aead_encrypt(key, alg, N.data(), N.size(), A.data(), A.size(), P.data(), P.size(), C.data() + 0, C.size(), &length);
        
        if (status != PSA_SUCCESS)
            syntax_error("shared_secret()");
        
        return C;
    };

    auto sign = [=] ( psa_key_id_t key, vec M ) {
        
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_get_key_attributes(key, &attributes);
        psa_algorithm_t algorithm = psa_get_key_algorithm(&attributes);
            
        uint8_t signature_data[PSA_SIGNATURE_MAX_SIZE];
        size_t length = 0;
        psa_status_t status = psa_sign_message(key, algorithm, M.data(), M.size(), signature_data, sizeof(signature_data), &length);
                
        if (status != PSA_SUCCESS)
            syntax_error("sign()");
        
        vec signature(&signature_data[0], &signature_data[length]);
        
        return signature;
    };

    // message_2 ////////////////////////////////////////////////////////////////////////////

    // Calculate data_2 and TH_2
    vec hash_message_1 = H( message_1 );
    vec TH_2_input = cbor( hash_message_1 ) + cbor( G_Y ) + C_R;
    vec TH_2 = H( TH_2_input );

    // Creates the info parameter and derives output key matrial with HKDF-Expand
    auto EDHOC_KDF = [=] ( vec PRK, int label, vec context, int length ) {
        vec info = cbor( label ) + cbor( context ) + cbor( length );
        vec OKM = hkdf_expand( edhoc_hash_alg, PRK, info, length );
        return make_tuple( info, OKM );
    };
        
    vec salt(PSA_HASH_LENGTH(PSA_ALG_SHA_256)), PRK_2e;
    PRK_2e = hkdf_extract( salt, G_XY );
    
    auto [ info_SALT_3e2m, SALT_3e2m ] = EDHOC_KDF(PRK_2e, 1, TH_2, PSA_HASH_LENGTH(PSA_ALG_SHA_256));
    
    vec PRK_3e2m = PRK_2e;
    if ( type_R == sdh )
        PRK_3e2m = hkdf_extract( SALT_3e2m, G_RX );
        
    // Calculate MAC_2
    vec MAC_2_context = ID_CRED_R + TH_2 + CRED_R + EAD_2;
    auto [ info_MAC_2, MAC_2 ] = EDHOC_KDF( PRK_3e2m, 2, MAC_2_context, edhoc_mac_length_2 );

    // Calculate Signature_or_MAC_2
    vec protected_2 = cbor( ID_CRED_R ); // bstr wrap
    vec external_aad_2 = cbor( cbor( TH_2 ) + CRED_R + EAD_2 ); // bstr wrap
    vec M_2 = M( protected_2, external_aad_2, cbor( MAC_2 ) );
    vec signature_or_MAC_2 = MAC_2;
    if ( type_R == sig )
        signature_or_MAC_2 = sign( sing_key_r, M_2 );

    // Calculate CIPHERTEXT_2
    vec PLAINTEXT_2 = compress_id_cred( ID_CRED_R ) + cbor( signature_or_MAC_2 ) + EAD_2;
    auto [ info_KEYSTREAM_2, KEYSTREAM_2 ] = EDHOC_KDF( PRK_2e, 0, TH_2, (int)PLAINTEXT_2.size() );
    vec CIPHERTEXT_2 = xor_encryption( KEYSTREAM_2, PLAINTEXT_2 );

    // Calculate message_2
    vec G_Y_CIPHERTEXT_2 = cbor( G_Y + CIPHERTEXT_2 );
    vec message_2 = G_Y_CIPHERTEXT_2 + C_R;

   // message_3 ////////////////////////////////////////////////////////////////////////////

    // Calculate data_3 and TH_3
    vec TH_3_input = cbor( TH_2 ) + cbor( CIPHERTEXT_2 );
    vec TH_3 = H( TH_3_input );

    auto [ info_SALT_4e3m, SALT_4e3m ] = EDHOC_KDF(PRK_3e2m, 5, TH_3, PSA_HASH_LENGTH(PSA_ALG_SHA_256));
    
    vec PRK_4e3m = PRK_3e2m;
    if ( type_I == sdh )
        PRK_4e3m = hkdf_extract( SALT_4e3m, G_IY );
    
    // Calculate MAC_3
    vec MAC_3_context = ID_CRED_I + CRED_I + EAD_3;
    auto [ info_MAC_3, MAC_3 ] = EDHOC_KDF( PRK_4e3m, 6, MAC_3_context, edhoc_mac_length_3 );

    // Calculate Signature_or_MAC_3
    vec protected_3 = cbor( ID_CRED_I ); // bstr wrap
    vec external_aad_3 = cbor( cbor( TH_3 ) + CRED_I + EAD_3 ); // bstr wrap
    vec M_3 = M( protected_3, external_aad_3, cbor( MAC_3 ) );
    vec signature_or_MAC_3 = MAC_3;
    if ( type_I == sig )
        signature_or_MAC_3 = sign( sing_key_i, M_3 );

    // Calculate CIPHERTEXT_3
    vec P_3 = compress_id_cred( ID_CRED_I ) + cbor( signature_or_MAC_3 ) + EAD_3;
    vec A_3 = A( cbor( vec{} ), cbor( TH_3 ) );
    auto [ info_K_3,   K_3 ] = EDHOC_KDF( PRK_3e2m, 3, TH_3, 16 );
    auto [ info_IV_3, IV_3 ] = EDHOC_KDF( PRK_3e2m, 4, TH_3, 13 );
    vec CIPHERTEXT_3 = AEAD( K_3, IV_3, P_3, A_3 );

    // Calculate message_3
    vec message_3 = cbor( CIPHERTEXT_3 );

    // message_4 and Exporter ////////////////////////////////////////////////////////////////////////////

    // Calculate TH_4
    vec TH_4_input = cbor( TH_3 ) + message_3;
    vec TH_4 = H( TH_4_input );

    auto [ info_PRK_out, PRK_out ] = EDHOC_KDF( PRK_4e3m, 7, TH_4, PSA_HASH_LENGTH(PSA_ALG_SHA_256));
    
    auto [ info_PRK_exporter, PRK_exporter ] = EDHOC_KDF( PRK_out, 10, vec{}, PSA_HASH_LENGTH(PSA_ALG_SHA_256));
    
    // Export funtion
    auto EDHOC_Export = [ PRK_exporter = PRK_exporter, EDHOC_KDF] ( int label, vec context, int length ) { return EDHOC_KDF( PRK_exporter, label, context, length ); };

    // Calculate message_4
    vec P_4 = EAD_4;
    vec A_4 = A( cbor( vec{} ), cbor( TH_4 ) );
    auto [ info_K_4,   K_4 ] = EDHOC_KDF( PRK_4e3m, 8, TH_4, 16 );
    auto [ info_IV_4, IV_4 ] = EDHOC_KDF( PRK_4e3m, 9, TH_4, 13 );
    vec CIPHERTEXT_4 = AEAD( K_4, IV_4, P_4, A_4 );
    vec message_4 = cbor( CIPHERTEXT_4 );

    // Derive OSCORE Master Secret and Salt
    auto [ info_OSCORE_secret, OSCORE_secret ] = EDHOC_Export( 0, vec {}, 16 );
    auto [ info_OSCORE_salt,   OSCORE_salt ]   = EDHOC_Export( 1, vec {},  8 );

    // KeyUpdate funtion
    auto [ info_PRK_out_new, PRK_out_new ] = EDHOC_KDF( PRK_out, 11, vec{}, PSA_HASH_LENGTH(PSA_ALG_SHA_256) );
    auto [ info_PRK_exporter_new, PRK_exporter_new ] = EDHOC_KDF( PRK_out_new, 10, vec{}, PSA_HASH_LENGTH(PSA_ALG_SHA_256));
    
    // Export funtion
    auto EDHOC_Export2 = [PRK_exporter_new = PRK_exporter_new, EDHOC_KDF] ( int label, vec context, int length ) { return EDHOC_KDF( PRK_exporter_new, label, context, length ); };
    
    auto [ info_OSCORE_secretFS, OSCORE_secretFS ] = EDHOC_Export2( 0, vec{}, 16 );
    auto [ info_OSCORE_saltFS,   OSCORE_saltFS ]   = EDHOC_Export2( 1, vec{},  8 );

    // Print stuff ////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////

    if ( isjson == true ) {
        cout << endl << "   \"test_vector_" << dec << vector_nr++ << "\": {";
        // message_1
        print_json( "method", METHOD );
        print_json( "SUITES_I", SUITES_I );
        print_json( "x_raw", X );
        print_json( "g_x_raw", G_X );
        print_json( "g_x_raw_y_coordinate", G_X_y );
        print_json( "g_x", cbor( G_X ) );
        if ( C_I_raw.index() == 0 ) {
            print_json( "c_i_raw", std::get<0>(C_I_raw) );
        } else {
            print_json( "c_i_raw", std::get<1>(C_I_raw) );
        }
        print_json( "c_i", C_I );
        print_json( "ead_1", EAD_1 );
        print_json( "message_1", message_1 );

        // message_2
        print_json( "y_raw", Y );
        print_json( "g_y_raw", G_Y );
        print_json( "g_y_raw_y_coordinate", G_Y_y );
        print_json( "g_y", cbor( G_Y ) );
        print_json( "g_xy_raw", G_XY );
        print_json( "salt_raw", salt );
        print_json( "prk_2e_raw", PRK_2e );
        print_json( "salt_3e2m", SALT_3e2m );
        if ( type_R == sig ) {
            print_json( "sk_r_raw", SK_R );
            print_json( "pk_r_raw", PK_R );
        }
        if ( type_R == sdh ) {
            print_json( "r_raw", R );
            print_json( "g_r_raw", G_R );
            print_json( "g_r_raw_y_coordinate", G_R_y );
            print_json( "g_rx_raw", G_RX );
        }
        print_json( "prk_3e2m_raw", PRK_3e2m );
        if ( C_R_raw.index() == 0 ) {
            print_json( "c_r_raw", std::get<0>(C_R_raw) );
        } else {
            print_json( "c_r_raw", std::get<1>(C_R_raw) );
        }
        print_json( "c_r", C_R );
        print_json( "h_message_1_raw", hash_message_1 );
        print_json( "h_message_1", cbor( hash_message_1 ) );
        print_json( "input_th_2", TH_2_input );
        print_json( "th_2_raw", TH_2 );
        print_json( "th_2", cbor( TH_2 ) );
        print_json( "id_cred_r", ID_CRED_R );
        print_json( "cred_r", CRED_R );
        print_json( "ead_2", EAD_2 );
        print_json( "info_mac_2", info_MAC_2 );
        print_json( "mac_2_raw", MAC_2 );
        print_json( "mac_2", cbor( MAC_2 ) );
        if ( type_R == sig )
            print_json( "m_2", M_2 );
        print_json( "sig_or_mac_2_raw", signature_or_MAC_2 );
        print_json( "sig_or_mac_2", cbor( signature_or_MAC_2 ) );
        print_json( "plaintext_2", PLAINTEXT_2 );
        print_json( "info_keystream_2", info_KEYSTREAM_2 );
        print_json( "keystream_2_raw", KEYSTREAM_2 );
        print_json( "ciphertext_2_raw", CIPHERTEXT_2 );
        print_json( "ciphertext_2", cbor( CIPHERTEXT_2 ) );
        print_json( "message_2", message_2 );

        // message_3
        if ( type_I == sig ) {
            print_json( "sk_i_raw", SK_I );
            print_json( "pk_i_raw", PK_I );
        }
        if ( type_I == sdh ) {
            print_json( "i_raw", I );
            print_json( "g_i_raw", G_I );
            print_json( "g_i_raw_y_coordinate", G_I_y );
            print_json( "g_iy_raw", G_IY );
        }
        print_json( "salt_4e3m", SALT_4e3m );
        print_json( "prk_4e3m_raw", PRK_4e3m );
        print_json( "input_TH_3", TH_3_input );
        print_json( "th_3_raw", TH_3);
        print_json( "th_3", cbor( TH_3) );
        print_json( "id_cred_i", ID_CRED_I );
        print_json( "cred_i", CRED_I );
        print_json( "ead_3", EAD_3 );
        print_json( "info_mac_3", info_MAC_3 );
        print_json( "mac_3_raw", MAC_3 );
        print_json( "mac_3", cbor( MAC_3 ) );
        if ( type_I == sig )
            print_json( "m_3", M_3 );
        print_json( "sig_or_mac_3_raw", signature_or_MAC_3 );
        print_json( "sig_or_mac_3", cbor( signature_or_MAC_3 ) );
        print_json( "p_3", P_3 );
        print_json( "a_3", A_3 );
        print_json( "info_k_3", info_K_3 );
        print_json( "k_3_raw", K_3 );
        print_json( "info_iv_3", info_IV_3 );
        print_json( "iv_3_raw", IV_3 );
        print_json( "ciphertext_3_raw", CIPHERTEXT_3 );
        print_json( "ciphertext_3", cbor( CIPHERTEXT_3 ) );
        print_json( "message_3", message_3 );

        // message_4 and exporter
        print_json( "input_th_4", TH_4_input );
        print_json( "th_4_raw", TH_4 );
        print_json( "th_4", cbor( TH_4 ) );

        print_json( "ead_4", EAD_4 );
        print_json( "p_4", P_4 );
        print_json( "a_4", A_4 );
        print_json( "info_k_4", info_K_4 );
        print_json( "k_4_raw", K_4 );
        print_json( "info_iv_4", info_IV_4 );
        print_json( "iv_4_raw", IV_4 );
        print_json( "ciphertext_4_raw", CIPHERTEXT_4 );
        print_json( "ciphertext_4", cbor( CIPHERTEXT_4 ) );
        print_json( "message_4", message_4 );

        print_json( "prk_out", PRK_out );
        print_json( "prk_exporter", PRK_exporter );
        
        print_json( "oscore_aead_alg", oscore_aead_alg );
        print_json( "oscore_hash_alg", oscore_hash_alg );
        print_json( "client_sender_id_raw", OSCORE_id( C_R ) );
        print_json( "server_sender_id_raw", OSCORE_id( C_I ) );
        print_json( "info_oscore_secret", info_OSCORE_secret );
        print_json( "oscore_secret_raw", OSCORE_secret );
        print_json( "info_oscore_salt", info_OSCORE_salt );
        print_json( "oscore_salt_raw", OSCORE_salt );

        print_json( "prk_out_updated", PRK_out_new );
        print_json( "prk_exporter_update", PRK_exporter_new );
        
        print_json( "oscore_secret_key_update_raw", OSCORE_secretFS );
        print_json( "oscore_salt_key_update_raw", OSCORE_saltFS, false ); // No comma in JSON

        cout << endl << "   }";
        if ( comma == true )
            cout << ",";
    } else {
        cout << endl << "---------------------------------------------------------------" << endl;
        cout << "Test Vector " << dec << vector_nr++;
        cout << endl << "---------------------------------------------------------------" << endl;

        // message_1 ////////////////////////////////////////////////////////////////////////////

        print( "METHOD (CBOR Data Item)", METHOD );
        print( "SUITES_I (CBOR Data Item)", SUITES_I );
        print( "X (Raw Value) (Initiator's ephemeral private key)", X );
        print( "G_X (Raw Value) (Initiator's ephemeral public key, 'x'-coordinate)", G_X );
        print( "Initiator's ephemeral public key ('y'-coordinate)", G_X_y );
        print( "G_X (CBOR Data Item) (Initiator's ephemeral public key)", cbor( G_X ) );
        if ( C_I_raw.index() == 0 ) {
            print( "C_I (Raw Value) (Connection identifier chosen by Initiator)", std::get<0>(C_I_raw) );
        } else {
            print( "C_I (Raw Value) (Connection identifier chosen by Initiator)", std::get<1>(C_I_raw) );
        }
        print( "C_I (CBOR Data Item) (Connection identifier chosen by Initiator)", C_I );
        print( "EAD_1 (CBOR Sequence)", EAD_1 );
        print( "message_1 (CBOR Sequence)", message_1 );
        cout << endl  << endl << endl  << endl;
    
        // message_2 ////////////////////////////////////////////////////////////////////////////

        print( "Y (Raw Value) (Responder's ephemeral private key)", Y );
        print( "G_Y (Raw Value) (Responder's ephemeral public key, 'x'-coordinate)", G_Y );
        print( "Responder's ephemeral public key ('y'-coordinate)", G_Y_y );
        print( "G_Y (CBOR Data Item) (Responder's ephemeral public key)", cbor( G_Y ) );
        print( "G_XY (Raw Value) (ECDH shared secret)", G_XY );
        print( "salt (Raw Value)", salt );
        print( "PRK_2e (Raw Value)", PRK_2e );
        if ( type_R == sig ) {
            print( "SK_R (Raw Value) (Responders's private authentication key)", SK_R );
            print( "PK_R (Raw Value) (Responders's public authentication key)", PK_R );
        }
        if ( type_R == sdh ) {
            print( "R (Raw Value) (Responder's private authentication key)", R );
            print( "G_R (Raw Value) (Responder's public authentication key, 'x'-coordinate)", G_R );
            print( "Responder's public authentication key ('y'-coordinate)", G_R_y );
            print( "G_RX (Raw Value) (ECDH shared secret)", G_RX );
        }
        print( "SALT_3e2m (Raw Value)", SALT_3e2m );
        print( "PRK_3e2m (Raw Value)", PRK_3e2m );
        if ( C_R_raw.index() == 0 ) {
            print( "C_R (Raw Value) (Connection identifier chosen by Responder)", std::get<0>(C_R_raw) );
        } else {
            print( "C_R (Raw Value) (Connection identifier chosen by Responder)", std::get<1>(C_R_raw) );
        }
        print( "C_R (CBOR Data Item) (Connection identifier chosen by Responder)", C_R );
        print( "H(message_1) (Raw Value)", hash_message_1 );
        print( "H(message_1) (CBOR Data Item)", cbor( hash_message_1 ) );
        print( "Input to calculate TH_2 (CBOR Sequence)", TH_2_input );
        print( "TH_2 (Raw Value)", TH_2 );
        print( "TH_2 (CBOR Data Item)", cbor( TH_2 ) );
        print( "ID_CRED_R (CBOR Data Item)", ID_CRED_R );
        print( "CRED_R (CBOR Data Item)", CRED_R );
        print( "EAD_2 (CBOR Sequence)", EAD_2 );
        print( "info for MAC_2 (CBOR Sequence)", info_MAC_2 );
        print( "MAC_2 (Raw Value)", MAC_2 );
        print( "MAC_2 (CBOR Data Item)", cbor( MAC_2 ) );
        if ( type_R == sig )
            print( "Message to be signed 2 (CBOR Data Item)", M_2 );
        print( "Signature_or_MAC_2 (Raw Value)", signature_or_MAC_2 );
        print( "Signature_or_MAC_2 (CBOR Data Item)", cbor( signature_or_MAC_2 ) );
        print( "PLAINTEXT_2 (CBOR Sequence)", PLAINTEXT_2 );
        print( "info for KEYSTREAM_2 (CBOR Sequence)", info_KEYSTREAM_2 );
        print( "KEYSTREAM_2 (Raw Value)", KEYSTREAM_2 );
        print( "CIPHERTEXT_2 (Raw Value)", CIPHERTEXT_2 );
        print( "CIPHERTEXT_2 (CBOR Data Item)", cbor( CIPHERTEXT_2 ) );
        print( "message_2 (CBOR Sequence)", message_2 );
        cout << endl  << endl << endl  << endl;

        // message_3 ////////////////////////////////////////////////////////////////////////////

        if ( type_I == sig ) {
            print( "SK_I (Raw Value) (Initiator's private authentication key)", SK_I );
            print( "PK_I (Raw Value) (Responders's public authentication key)", PK_I );
        }
        if ( type_I == sdh ) {
            print( "I (Raw Value) (Initiator's private authentication key)", I );
            print( "G_I (Raw Value) (Initiator's public authentication key, 'x'-coordinate)", G_I );
            print( "Initiator's public authentication key ('y'-coordinate)", G_I_y );
            print( "G_IY (Raw Value) (ECDH shared secret)", G_IY );
        }
        print( "SALT_4e3m (Raw Value)", SALT_4e3m );
        print( "prk_4e3m (Raw Value)", PRK_4e3m );
        print( "Input to calculate TH_3 (CBOR Sequence)", TH_3_input );
        print( "TH_3 (Raw Value)", TH_3);
        print( "TH_3 (CBOR Data Item)", cbor( TH_3) );
        print( "ID_CRED_I (CBOR Data Item)", ID_CRED_I );
        print( "CRED_I (CBOR Data Item)", CRED_I );
        print( "EAD_3 (CBOR Sequence)", EAD_3 );
        print( "info for MAC_3 (CBOR Sequence)", info_MAC_3 );
        print( "MAC_3 (Raw Value)", MAC_3 );
        print( "MAC_3 (CBOR Data Item)", cbor( MAC_3 ) );
        if ( type_I == sig )
            print( "Message to be signed 3 (CBOR Data Item)", M_3 );
        print( "Signature_or_MAC_3 (Raw Value)", signature_or_MAC_3 );
        print( "Signature_or_MAC_3 (CBOR Data Item)", cbor( signature_or_MAC_3 ) );
        print( "P_3 (CBOR Sequence)", P_3 );
        print( "A_3 (CBOR Data Item)", A_3 );
        print( "info for K_3 (CBOR Sequence)", info_K_3 );
        print( "K_3 (Raw Value)", K_3 );
        print( "info for IV_3 (CBOR Sequence)", info_IV_3 );
        print( "IV_3 (Raw Value)", IV_3 );
        print( "CIPHERTEXT_3 (Raw Value)", CIPHERTEXT_3 );
        print( "CIPHERTEXT_3 (CBOR Data Item)", cbor( CIPHERTEXT_3 ) );
        print( "message_3 (CBOR Sequence)", message_3 );
        cout << endl  << endl << endl  << endl;

        // message_4 and Exporter ////////////////////////////////////////////////////////////////////////////

        print( "Input to calculate TH_4 (CBOR Sequence)", TH_4_input );
        print( "TH_4 (Raw Value)", TH_4 );
        print( "TH_4 (CBOR Data Item)", cbor( TH_4 ) );

        print( "EAD_4 (CBOR Sequence)", EAD_4 );
        print( "P_4 (CBOR Sequence)", P_4 );
        print( "A_4 (CBOR Data Item)", A_4 );
        print( "info for K_4 (CBOR Sequence)", info_K_4 );
        print( "K_4 (Raw Value)", K_4 );
        print( "info for IV_4 (CBOR Sequence)", info_IV_4 );
        print( "IV_4 (Raw Value)", IV_4 );
        print( "CIPHERTEXT_4", CIPHERTEXT_4 );
        print( "CIPHERTEXT_4 (CBOR Data Item)", cbor( CIPHERTEXT_4 ) );
        print( "message_4 (CBOR Sequence)", message_4 );
        
        print( "PRK_out (Raw Value)", PRK_out );
        print( "PRK_exporter (Raw Value)", PRK_exporter );

        print( "OSCORE AEAD Algorithm", oscore_aead_alg );
        print( "OSCORE Hash Algorithm", oscore_hash_alg );
        print( "Client's OSCORE Sender ID (Raw Value)", OSCORE_id( C_R ) );
        print( "Server's OSCORE Sender ID (Raw Value)", OSCORE_id( C_I ) );
        print( "info for OSCORE Master Secret (CBOR Sequence)", info_OSCORE_secret );
        print( "OSCORE Master Secret (Raw Value)", OSCORE_secret );
        print( "info for OSCORE Master Salt (CBOR Sequence)", info_OSCORE_salt );
        print( "OSCORE Master Salt (Raw Value)", OSCORE_salt );

        print( "PRK_out after KeyUpdate (Raw Value)", PRK_out_new );
        print( "PRK_exporter after KeyUpdate (Raw Value)", PRK_exporter_new );
        print( "OSCORE Master Secret after KeyUpdate (Raw Value)", OSCORE_secretFS );
        print( "OSCORE Master Salt after KeyUpdate (Raw Value)", OSCORE_saltFS );
        cout << endl  << endl << endl  << endl;
    }
    
    // Cleanup
    mbedtls_psa_crypto_free();
}

int main( void ) {
    
    if ( isjson == true ) {
        cout << "{";
    } else {
        // Error ////////////////////////////////////////////////////////////////////////////

        cout << endl << "---------------------------------------------------------------" << endl;
        cout << "Example EDHOC error messages";
        cout << endl << "---------------------------------------------------------------" << endl;

        vec error0 = cbor( 0 ) + cbor_map( 3 ) + cbor( "sub" ) + cbor( "Skynet" )
                                            + cbor( "time" ) + cbor( "1997-08-29T02:14:00+05:00" )
                                            + cbor( "cert hash" ) + cbor( vec{ 0x57, 0xe9, 0xc0, 0x28, 0x0a, 0x85, 0x90, 0xe0, 0x51, 0xa7, 0xd3, 0x24, 0x1b, 0x82, 0x40, 0xfe } );
        vec error11 = cbor( 1 ) + cbor( "COSE header parameter x5u not supported" );
        vec error12 = cbor( 1 ) + cbor( "CA not trusted" );
        vec error13 = cbor( 1 ) + cbor( "Malformed message_2" );
        vec error14 = cbor( 1 ) + cbor( "Comic Sans MUST be used!" );
        vec error21 = cbor( 2 ) + cbor( 3 );
        vec error22 = cbor( 2 ) + cbor_arr( 2 ) + cbor( 25 ) + cbor( 24 );

        print( "Example error message with ERR_CODE = 0 (Success)", error0 );
        print( "Example error message with ERR_CODE = 1 (Unspecified)", error11 );
        print( "Example error message with ERR_CODE = 1 (Unspecified)", error12 );
        print( "Example error message with ERR_CODE = 1 (Unspecified)", error13 );
        print( "Example error message with ERR_CODE = 1 (Unspecified)", error14 );
        print( "Example error message with ERR_CODE = 2 (Wrong selected cipher suite)", error21 );
        print( "Example error message with ERR_CODE = 2 (Wrong selected cipher suite)", error22 );
        cout << endl  << endl << endl  << endl;
    }

    test_vectors( sdh, cred_uccs, kid, sdh, cred_uccs, kid, 2, 37400 );
//    test_vectors( sdh, cred_x509, x5bag, sdh, cred_x509, x5bag, 2, 37400, false, false );


//    // The four methods with COSE header parameters kid and x5t
//    test_vectors( sdh, cred_uccs, kid, sdh, cred_uccs, kid, 2, 34400 ); // Table 1, column 1
//    test_vectors( sdh, cred_uccs, kid, sig, cred_x509, x5t, 2, 27400 );
//    test_vectors( sig, cred_x509, x5t, sdh, cred_uccs, kid, 2, 44400 );
//    test_vectors( sig, cred_x509, x5t, sig, cred_x509, x5t, 2, 37400 ); // Table 1, column 4
//
//    // Other COSE header parameters
//    test_vectors( sdh, cred_x509, x5u, sdh, cred_x509, x5u, 0, 68500 );
//    test_vectors( sdh, cred_x509, x5chain, sig, cred_x509, x5bag, 0, 56200 );
//    test_vectors( sdh, cred_uccs, uccs, sig, cred_cwt, cwt, 0, 67200 ); // cwt not implemented
//
//    // Cipher suite 1
//    test_vectors( sdh, cred_uccs, kid, sdh, cred_uccs, kid, 1, 34410 );
//    test_vectors( sig, cred_x509, x5t, sig, cred_x509, x5t, 1, 37410 );
//
//    // More complex, long ids, EAD
//    test_vectors( sdh, cred_uccs, kid, sdh, cred_uccs, kid, 0, 34401, true );
//    test_vectors( sig, cred_x509, x5t, sig, cred_x509, x5t, 0, 37401, true );
//
//    // signature keys in UCCS and static DH keys in X.509, // Table 1, columns 2 and 3
//    test_vectors( sdh, cred_x509, x5t, sdh, cred_x509, x5t, 0, 2716057 );
//    test_vectors( sig, cred_uccs, kid, sig, cred_uccs, kid, 0, 3370318, false, false ); // No comma in JSON

    if ( isjson == true ) {
        cout << endl << "}";
    }
}
