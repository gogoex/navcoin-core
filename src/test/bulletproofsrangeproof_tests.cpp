// Copyright (c) 2020 The Navcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blsct/bulletproofs.h"
#include "test/test_navcoin.h"

#include <map>

#include <boost/test/unit_test.hpp>
#include "boost/assign.hpp"

BOOST_FIXTURE_TEST_SUITE(bulletproofsrangeproof, BasicTestingSetup)

void PrintG1(const char* name, bls::G1Element& p)
{
    printf("%s: %s\n", name, HexStr(p.Serialize()).c_str());
}

void PrintScalar(const char* name, Scalar& s)
{
    printf("%s: %s\n", name, HexStr(s.GetVch()).c_str());
}

bool TestRange(std::vector<Scalar> values, bls::G1Element nonce)
{
    std::vector<Scalar> gammas;
    std::vector<bls::G1Element> nonces;

    auto gamma = HashG1Element(nonce, 100);
    gammas.push_back(gamma);
    nonces.push_back(nonce);

    BulletproofsRangeproof rp;
    rp.Prove(values, nonce, {1, 2, 3, 4});

    PrintG1("A", rp.A);
    PrintG1("S", rp.S);
    PrintG1("T1", rp.T1);
    PrintG1("T2", rp.T1);
    PrintScalar("tau_x", rp.taux);
    PrintScalar("mu", rp.mu);
    PrintScalar("a", rp.a);
    PrintScalar("b", rp.b);
    PrintScalar("t_hat", rp.t);

    std::vector<std::pair<int, BulletproofsRangeproof>> proofs;
    proofs.push_back(std::make_pair(0, rp));

    std::vector<RangeproofEncodedData> data;
    bool ret = VerifyBulletproof(proofs, data, nonces);
    if (!ret)
        return ret;

    if (data[0].amount != values[0].GetInt64()) return false;
    if (!(data[0].gamma == gammas[0])) return false;
    if (data[0].message[0] != 1) return false;
    if (data[0].message[1] != 2) return false;
    if (data[0].message[2] != 3) return false;
    if (data[0].message[3] != 4) return false;
    return true;
}

// make -j32 && ./src/test/test_navcoin --run_test=bullet*
BOOST_AUTO_TEST_CASE(RangeProofTest)
{
    std::vector<Scalar> vs;

    bls::G1Element nonce = bls::G1Element::Generator();

    auto buf = nonce.Serialize();
    printf("G: %s\n", HexStr(buf).c_str());

    Scalar one;
    one = 1;
    vs.push_back(one);

    for (Scalar v: vs) {
        std::vector<Scalar> values;
        bn_print(v.bn);
        values.push_back(v);
        BOOST_CHECK(TestRange(values, nonce));
    }
}

BOOST_AUTO_TEST_SUITE_END()
