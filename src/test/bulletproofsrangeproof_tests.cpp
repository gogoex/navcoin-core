// Copyright (c) 2020 The Navcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blsct/bulletproofs.h"
#include "test/test_navcoin.h"

#include <map>

#include <boost/test/unit_test.hpp>
#include "boost/assign.hpp"

BOOST_FIXTURE_TEST_SUITE(bulletproofsrangeproof, BasicTestingSetup)

bool TestRange(std::vector<Scalar> values, bls::G1Element nonce)
{
    std::vector<Scalar> gamma;
    std::vector<bls::G1Element> nonces;

    for (unsigned int i = 0; i < values.size(); i++)
    {
        gamma.push_back(HashG1Element(nonce, 100+i));
        nonces.push_back(nonce);
    }

    BulletproofsRangeproof bprp;
    bprp.Prove(values, nonce, {1, 2, 3, 4});

    std::vector<std::pair<int, BulletproofsRangeproof>> proofs;
    proofs.push_back(std::make_pair(0,bprp));

    std::vector<RangeproofEncodedData> data;

    bool ret = VerifyBulletproof(proofs, data, nonces);

    if (!ret)
        return ret;

    if (values.size() == 1)
    {
        for (unsigned int i = 0; i < values.size(); i++)
        {
            if(data[i].amount != values[i].GetInt64())
                return false;
            if(!(data[i].gamma == gamma[i]))
                return false;
            if(data[i].message[0] != 1)
                return false;
            if(data[i].message[1] != 2)
                return false;
            if(data[i].message[2] != 3)
                return false;
            if(data[i].message[3] != 4)
                return false;
        }
    }

    return true;
}

bool TestRangeBatch(std::vector<Scalar> values, bls::G1Element nonce)
{
    std::vector<std::pair<int, BulletproofsRangeproof>> proofs;
    std::vector<bls::G1Element> nonces;
    std::vector<Scalar> gamma;
    Scalar mask = HashG1Element(nonce, 100);

    for (unsigned int i = 0; i < values.size(); i++)
    {
        std::vector<Scalar> v;
        v.push_back(values[i]);

        gamma.push_back(mask);

        BulletproofsRangeproof bprp;
        bprp.Prove(v, nonce, {1,2,3,4});

        nonces.push_back(nonce);

        proofs.push_back(std::make_pair(i, bprp));
    }

    std::vector<RangeproofEncodedData> data;

    bool ret = VerifyBulletproof(proofs, data, nonces);

    if (!ret)
        return ret;

    for (unsigned int i = 0; i < values.size(); i++)
    {
        if(data[i].amount != values[i].GetInt64())
            return false;
        if(!(data[i].gamma == gamma[i]))
            return false;
        if(data[i].message[0] != 1)
            return false;
        if(data[i].message[1] != 2)
            return false;
        if(data[i].message[2] != 3)
            return false;
        if(data[i].message[3] != 4)
            return false;
    }

    return true;
}

// make -j32 && ./src/test/test_navcoin --run_test=bullet*
BOOST_AUTO_TEST_CASE(RangeProofTest)
{
    std::vector<Scalar> vs;

    bls::G1Element nonce = bls::G1Element::Generator();

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
