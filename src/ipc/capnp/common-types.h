// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_IPC_CAPNP_COMMON_TYPES_H
#define BITCOIN_IPC_CAPNP_COMMON_TYPES_H

#include <clientversion.h>
#include <ipc/capnp/validation.capnp.proxy.h>
#include <mp/proxy-types.h>
#include <serialize.h>
#include <streams.h>

namespace ipc {
namespace capnp {
//! Deserialize bitcoin value.
template <typename T>
T Unserialize(T& value, const kj::ArrayPtr<const kj::byte>& data)
{
    // Could optimize, it unnecessarily copies the data into a temporary vector.
    CDataStream stream(CSerializeData{data.begin(), data.end()}, SER_NETWORK, CLIENT_VERSION);
    value.Unserialize(stream);
    return value;
}

//! Deserialize bitcoin value.
template <typename T>
T Unserialize(const kj::ArrayPtr<const kj::byte>& data)
{
    T value;
    Unserialize(value, data);
    return value;
}

template <typename T>
using Deserializable = std::is_constructible<T, ::deserialize_type, ::CDataStream&>;

template <typename T>
struct Unserializable
{
private:
    template <typename C>
    static std::true_type test(decltype(std::declval<C>().Unserialize(std::declval<C&>()))*);
    template <typename>
    static std::false_type test(...);

public:
    static constexpr bool value = decltype(test<T>(nullptr))::value;
};

template <typename T>
struct Serializable
{
private:
    template <typename C>
    static std::true_type test(decltype(std::declval<C>().Serialize(std::declval<C&>()))*);
    template <typename>
    static std::false_type test(...);

public:
    static constexpr bool value = decltype(test<T>(nullptr))::value;
};
} // namespace capnp
} // namespace ipc

namespace mp {
template <typename LocalType, typename Input, typename ReadDest>
decltype(auto) CustomReadField(
    TypeList<LocalType>, Priority<1>, InvokeContext& invoke_context, Input&& input, ReadDest&& read_dest,
    typename std::enable_if<ipc::capnp::Deserializable<LocalType>::value>::type* enable = nullptr)
{
    assert(input.has());
    auto data = input.get();
    // Note: stream copy here is unnecessary, and can be avoided in the future
    // when `VectorReader` from #12254 is added.
    CDataStream stream({data.begin(), data.end()}, SER_NETWORK, CLIENT_VERSION);
    return read_dest.construct(deserialize, stream);
}

template <typename LocalType, typename Input, typename ReadDest>
decltype(auto) CustomReadField(
    TypeList<LocalType>, Priority<1>, InvokeContext& invoke_context, Input&& input, ReadDest&& read_dest,
    // FIXME instead of always preferring Deserialize implementation over Unserialize should prefer Deserializing when
    // emplacing, unserialize when updating
    typename std::enable_if<ipc::capnp::Unserializable<LocalType>::value &&
                            !ipc::capnp::Deserializable<LocalType>::value>::type* enable = nullptr)
{
    return read_dest.update([&](auto& value) {
        if (!input.has()) return;
        auto data = input.get();
        // Note: stream copy here is unnecessary, and can be avoided in the future
        // when `VectorReader` from #12254 is added.
        CDataStream stream(CSerializeData{data.begin(), data.end()}, SER_NETWORK, CLIENT_VERSION);
        value.Unserialize(stream);
    });
}

template <typename LocalType, typename Value, typename Output>
void CustomBuildField(
    TypeList<LocalType>, Priority<1>, InvokeContext& invoke_context, Value&& value, Output&& output,
    typename std::enable_if<ipc::capnp::Serializable<
        typename std::remove_cv<typename std::remove_reference<Value>::type>::type>::value>::type* enable = nullptr)
{
    CDataStream stream(SER_NETWORK, CLIENT_VERSION);
    value.Serialize(stream);
    auto result = output.init(stream.size());
    memcpy(result.begin(), stream.data(), stream.size());
}

} // namespace mp

#endif // BITCOIN_IPC_CAPNP_COMMON_TYPES_H
