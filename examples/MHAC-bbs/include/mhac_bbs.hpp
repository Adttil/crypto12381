#ifndef CRYPTO12381_EXAMPLES_MHAC_BBS_MHAC_BBS_HPP
#define CRYPTO12381_EXAMPLES_MHAC_BBS_MHAC_BBS_HPP
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

    struct AttributesStructure
    {
        size_t m;
        std::span<const size_t> Pub;
        std::span<const size_t> Prv;
    };

    struct AttributesInfo
    {
        std::vector<serialized_field<Zp>> public_attributes;
        std::vector<std::vector<serialized_field<Zp>>> private_attributes_share;
        std::vector<serialized_field<G1>> commitments;
    };

    struct PresGroup
    {
        std::span<const size_t> S;
        std::vector<serialized_field<Zp>> λ;
        serialized_field<G1> D;
    };
    
    struct PresType
    {
        std::span<const size_t> Rev;
        serialized_field<G1> C_rev;
        serialized_field<G1> C_pub;
    };

    struct Pres
    {
        //(A_, B_, ch, zr, ze)
        serialized_field<G1^2, Zp^3> fixed_part;
        std::vector<serialized_field<Zp>> z;
        std::vector<serialized_field<Zp>> z_hid_pub;
    };

    IssSetupResult iss_setup(size_t m, RandomEngine& random) noexcept;

    AttributesInfo generate_attributes(
        const PublicParameters& pp, 
        size_t t, 
        size_t n, 
        std::span<const size_t> Prv,
        RandomEngine& random
    );
    
    Creds cred_iss(
        const PublicParameters& pp, 
        const PrivateKey& sk, 
        size_t t, 
        std::span<const serialized_field<G1>> commitment,
        std::span<const size_t> public_indexes,
        std::span<const serialized_field<Zp>> public_attributes, 
        RandomEngine& random
    );

    PresGroup make_pres_group(const Creds& creds, std::span<const size_t> party_indexes);

    PresType make_pres_type(
        const PublicParameters& pp, 
        std::span<const size_t> Rev,
        std::span<const size_t> Prv,
        std::span<const serialized_field<Zp>> public_attributes
    );

    Pres cred_pres(
        const PublicParameters& pp, 
        const Creds& creds,
        const PresGroup& group,
        const PresType& type,
        std::span<const size_t> Prv,
        std::span<const serialized_field<Zp>> public_attributes,
        std::span<const std::vector<serialized_field<Zp>>> attr_shares,
        RandomEngine& random
    );

    bool verify_pres(
        const PublicParameters& pp, 
        const PublicKey& pk,
        const PresType& type,
        std::span<const size_t> Prv,
        std::span<const serialized_field<Zp>> public_attributes,
        const Pres& pres
    );
}

#endif