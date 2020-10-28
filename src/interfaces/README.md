# Internal c++ interfaces

The following interfaces are defined here:

* [`Chain`](chain.h) — used by wallet to access blockchain and mempool state. Added in [#14437](https://github.com/bitcoin/bitcoin/pull/14437), [#14711](https://github.com/bitcoin/bitcoin/pull/14711), [#15288](https://github.com/bitcoin/bitcoin/pull/15288), and [#10973](https://github.com/bitcoin/bitcoin/pull/10973).

* [`ChainClient`](chain.h) — used by node to start & stop `Chain` clients. Added in [#14437](https://github.com/bitcoin/bitcoin/pull/14437).

* [`Node`](node.h) — used by GUI to start & stop bitcoin node. Added in [#10244](https://github.com/bitcoin/bitcoin/pull/10244).

* [`Wallet`](wallet.h) — used by GUI to access wallets. Added in [#10244](https://github.com/bitcoin/bitcoin/pull/10244).

* [`Handler`](handler.h) — returned by `handleEvent` methods on interfaces above and used to manage lifetimes of event handlers.

* [`Init`](init.h) — used by multiprocess code to access interfaces above on startup. Added in [#19160](https://github.com/bitcoin/bitcoin/pull/19160).

* [`Base`](base.h) — base interface class used by multiprocess code for bookkeeping and cleanup. Added in [#19160](https://github.com/bitcoin/bitcoin/pull/19160).

The interfaces above define boundaries between major components of bitcoin code (node, wallet, and gui), making it possible for them to run in [different processes](../../doc/multiprocess.md), and be tested, developed, and understood independently. These interfaces are not currently designed to be stable or to be used externally.

## Process and Interface Architecture in a Multiprocess Setting

```


        process::bitcoin-gui                                                                                       process::bitcoin-node
      _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _                                                       _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
    |                                                     |                                                   |                                                      |

    |        (as Init)                                    |                                                   |      ------------                                    |
                   \                                                                                                 | NodeImpl |
    |               V                                     |                                                   |      ------------                                    |
                -------------                                                                                             ^             -------------
    |           | LocalInit |                             |                                                   |          /              | LocalInit |                |
                -------------         (as Node)                                                                     (as Node)           -------------
    |               /        \              \             |                                                   |        /                  /         \                |
                   /          \              V                                                                        /                  /           \
    |   (as IpcProcess)  (as IpcProtocol) --------------- |                                                   |  ---------------   (as IpcProtocol)  (as IpcProcess) |
                  |             \         | ProxyClient |                                                        | ProxyServer |        |             |
    |             V              \        --------------- |                                                   |  ---------------        |             V              |
        ------------------       |                    |                                                                  |              |       ------------------
    |   | IpcProcessImpl |       |                    |   |                                                   |          |              |       | IpcProcessImpl |   |
        ------------------       |                    |                                                                  |              |       ------------------
    |             |              | thread::capnp-loop |   |                                                   |          |              |  thread::capnp-loop |      |
                  |          _ _ | _ _ _ _ _ _ _ _ _  |                                                                  |         _ _ _| _ _ _ _ _ _ _ _     |
    |             |              |                    |   |                                                   |          |              |                     |      |
                  |         |    V                  | |                                                                  |        |     V                 |   |
    |             |            -------------------    |   |                                                   |          |            ------------------      |      |
                  ------------>| IpcProtocolImpl |  | |                                                                  |        |   | IpcProtocolImpl |<-----
    |                          -------------------    |   |                                                   |          |            -------------------            |
                            |      /                | |                                                                  |        |        /              |
    |                             /                   |   |                                                   |          |                /                          |
                            |    V                  | |                                                                  |        |      V                |
    |                         -----------------       |   |                                                   |          |           -----------------               |
                            | | mp::EventLoop |<-------                                                                  ----------->| mp::EventLoop |    |
    |                         -----------------           |                                                   |                      -----------------               |
                            | _ _ _ ^ _ _ _ _ _ _ _ |                                                                             | _ _  ^ _ _ _ _ _ _ _ _|
    | _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ | _ _ _ _ _ _ _ _ _ _ |                                                   | _ _ _ _ _ _ _ _ _ _ _ _  | _ _ _ _ _ _ _ _ _ _ _ _ _ |
                                    |                           Cap'n Proto serialization+socket                                         |
                                    |----------------------------------------------------------------------------------------------------|

```
