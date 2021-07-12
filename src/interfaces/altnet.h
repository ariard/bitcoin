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

    virtual void sendgenesis() = 0;

    virtual void startdriver(const std::string& driver_name) = 0;

    virtual void stop() = 0;

};
std::unique_ptr<Altnet> MakeAltnet(AltnetContext* altnet, std::unique_ptr<interfaces::Validation>);
}

#endif // BITCOIN_INTERFACES_ALTNET_H
