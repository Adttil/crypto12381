#ifndef CRYPTO12381_TESTS_MHAC_BBS_MHAC_BBS_HPP
#define CRYPTO12381_TESTS_MHAC_BBS_MHAC_BBS_HPP
#include <vector>
#include <crypto12381/interface.hpp>

#include "bbs.hpp"

namespace crypto12381::mhac_bbs
{
    using namespace crypto12381;

    using bbs::PublicParameters;
    using bbs::PublicKey;
    using bbs::PrivateKey;
    using bbs::Keys;

    struct IssSetupResult
    {
        PublicParameters pp;
        Keys keys;
    };

    struct CredStructure
    {
        size_t t;
        std::span<const size_t> Prv;
    };

    // (A, e_share, D)
    struct Creds
    {
        serialized_field<G1> A;
        std::vector<serialized_field<Zp>> e_share;
        std::vector<serialized_field<G1>> D;
    };

    struct AttributesInfo
    {
        std::vector<serialized_field<Zp>> attributes;
        std::vector<std::vector<serialized_field<Zp>>> private_attributes_share;
        std::vector<serialized_field<G1>> commitments;
    };

    IssSetupResult iss_setup(size_t m, RandomEngine& random) noexcept;

    AttributesInfo generate_attributes(
        const PublicParameters& pp, 
        size_t t, 
        size_t n, 
        std::span<const size_t> Prv,
        RandomEngine& random
    );

    std::vector<serialized_field<G1>> vss_of_private_attributes(
        const PublicParameters& pp,
        size_t t,
        size_t n,
        std::span<const size_t> private_indexes,
        std::span<const serialized_field<Zp>> attributes, 
        RandomEngine& random
    );
    
    Creds cred_iss(
        const PublicParameters& pp, 
        const PrivateKey& sk, 
        size_t t, 
        size_t n, 
        std::span<const serialized_field<Zp>> attributes, 
        RandomEngine& random
    );
    
    Creds cred_iss(
        const PublicParameters& pp, 
        const PrivateKey& sk, 
        size_t t, 
        std::span<const serialized_field<G1>> commitment,
        std::span<const size_t> public_indexes,
        std::span<const serialized_field<Zp>> attributes, 
        RandomEngine& random
    );    

    struct Request
    {
        std::array<char, 32> T;
        std::array<char, 32> nonce;
        
    };

    struct Pres{};

    Pres cred_pres(
        const PublicParameters& pp, 
        const PublicKey& pk, 
        const Creds& creds,
        std::span<size_t> party_indexes,
        std::span<const serialized_field<Zp>> attributes,
        std::span<size_t> Rev,
        std::span<size_t> Prv,
        RandomEngine& random
    );
}

#endif