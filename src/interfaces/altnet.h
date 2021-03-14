// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_ALTNET_H
#define BITCOIN_INTERFACES_ALTNET_H

#include <altnet/context.h>
#include <interfaces/validation.h>

#include <memory>

namespace interfaces {
class Altnet
{
public:
    virtual ~Altnet() {}

    //virtual bool starttransport(interfaces::Validation& validation);
};
std::unique_ptr<Altnet> MakeAltnet(interfaces::Validation& validation);
}

#endif // BITCOIN_INTERFACES_ALTNET_H
