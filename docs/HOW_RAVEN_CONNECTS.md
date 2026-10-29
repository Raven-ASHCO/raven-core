# How Raven connects without a Raven server

Any messenger without a central server has to answer four questions. This page answers each one
directly: how Raven does it, what is in **release builds** today (version 0.1.0, with the features
switched on in October 2026, not independently reviewed) and what is only in **lab** builds (debug
builds with `RAVEN_LAB_*` switches, see [ROADMAP.md](ROADMAP.md)), and the limits. It
describes the code in this repository and points to the specs. Where the
[field test](FIELD_TEST_2026_10.md) measured something, the number is given.

"No Raven server" means Raven runs no server of its own and nothing depends on one. Some paths use
other people's servers: the Tor network, and public STUN servers.

| Question | Short answer | Release builds | Lab builds |
|---|---|---|---|
| How do I find someone with no directory? | You exchange contact cards yourselves, then check security words | yes: a card holds your key and your signed onion address, no IP address; friends' addresses come later, inside encrypted links | also the LAN beacon, and cards with Internet and p2p addresses (the lab unlock) |
| What if both of us are behind NAT? | Every direct path is tried and raced against Tor | yes: LAN, Internet direct, public address discovery, hole punching, a friend's relay, Tor; listening is your choice, so by default it is Tor | also relays over WebSocket on port 443 |
| Who keeps messages while my friend is offline? | Your own computer keeps trying; a friend you both verified can keep a sealed copy | up to 7 days; friends keep sealed copies up to 24 hours, once you both turn it on | also sealed letters, and two friends in a row |
| How do I know it is really my friend? | Ten security words read aloud and compared by Raven | yes | yes |

## 1. Finding someone without a directory

**How.** There is no directory and no lookup by phone number, email or name. Two people who want to
talk exchange **contact cards** out of band: in person, in a message, in a file. A card carries the
person's Raven address (`rvn1...`) and public key, and the address of their Tor onion service,
signed by that key. Then they compare **security words** (section 4), so a card swapped on the way
is caught.

- Release builds: `raven whoami --card` prints a `raven-card/1` line: your key and, once Tor is
  up, your onion address **signed by your Raven key**, which says nothing about where you are. It
  never holds an IP address unless you add a local-network one yourself (`--lan`), and never an
  Internet address, a libp2p PeerId or a relay: nothing signs those fields, so whoever handles a card
  could put their own host there. `raven contact add --card` reads a card and leaves out any such
  field, with a one-line note. Your friends' current addresses arrive later, inside encrypted links
  between verified friends (route hints); the first link can be made over Tor or on a shared
  network. On a local network Raven can also use a friend's address there, from the card (`lan=`,
  dialled only at a local-network address) or typed once (`raven contact set-addr --petname Bob
  --lan <address>`). See the [offline guide](OFFLINE_GUIDE.md) and
  [RAVEN_ROUTE_HINTS_V1](../protocol/RAVEN_ROUTE_HINTS_V1.md) §9.1.
- Lab builds: on a shared local network, the LAN beacon finds a friend's address without typing.
  With the lab unlock, cards still carry Internet and p2p addresses, for the lab test harnesses.
- `raven find` searches your own contacts and the signed alias records this computer holds; there
  is no internet-wide search. Its rule: finding a name is not verifying a person; a result is a
  candidate until you check the words ([RAVEN_DISCOVERY_V1.md](RAVEN_DISCOVERY_V1.md)).

**Limits.**

- You need some channel to exchange the card the first time. Contact requests and introductions by
  a friend are specified ([RAVEN_CONTACT_REQUEST_V1](../protocol/RAVEN_CONTACT_REQUEST_V1.md),
  [RAVEN_INTRODUCTION_V1](../protocol/RAVEN_INTRODUCTION_V1.md)), but sending contact requests over
  the network is on hold, and the field test did not use either.
- A friend who moves gets new addresses. Route hints carry them, but only over a link that still
  works (Tor usually does); a typed LAN address you type again.
- If a friend reinstalls Raven without their old key, they have a new key: exchange cards and check
  words again.

**Specs and docs.** [RAVEN_ADDRESS_V1](../protocol/RAVEN_ADDRESS_V1.md),
[RAVEN_IDENTITY_V1](../protocol/RAVEN_IDENTITY_V1.md),
[RAVEN_ROUTE_HINTS_V1](../protocol/RAVEN_ROUTE_HINTS_V1.md),
[RAVEN_LAN_BEACON_V1](../protocol/RAVEN_LAN_BEACON_V1.md) (lab),
[RAVEN_ONION_CARRIER_V1](../protocol/RAVEN_ONION_CARRIER_V1.md) §3 and §7 (the signed onion
binding and the card field), [OFFLINE_GUIDE.md](OFFLINE_GUIDE.md).

## 2. Reaching each other through NAT

**How.** For each message Raven plans the routes it knows for that friend, in this order, and races
them ([RAVEN_ONION_CARRIER_V1](../protocol/RAVEN_ONION_CARRIER_V1.md) §9):

1. **LAN direct**: the same Wi-Fi, router, hotspot or cable. Noise XX bound to the Raven identity.
   *Release.*
2. **Bluetooth nearby** between laptops, no network needed. *Release on macOS only* (Windows and
   Linux release builds have no Bluetooth backend); you turn it on.
3. **Internet direct** to a public or forwarded address, IPv6 or IPv4. *Release*; listening is off
   until you turn it on.
4. **Public address discovery.** Raven asks two public STUN servers, Cloudflare's and Google's,
   which public address and port they see. The request is a bare 20-byte STUN Binding request:
   no key, no name, no Raven marker. The servers learn that this address asked, and when. Both must
   answer and agree, or the answer is not used. From the answers Raven also learns its NAT type.
   Router port mapping (UPnP, NAT-PMP, PCP) is tried too, once you turn it on. *Release*
   (`raven node stun off` stops the query).
5. **Hole punching between friends.** Two verified friends whose NATs keep the same public port for
   every destination ("endpoint-independent") dial each other's public QUIC endpoint at the same
   moments. The moments come from a schedule both compute from a secret only the pair has, so there
   is no coordinator and nothing to exchange first. Raven never guesses ports. *Release.*
6. **A friend's node as relay** (libp2p Circuit Relay v2), when a friend is reachable from the
   internet and offers it. The relay sees encrypted bytes, timing and both sides' addresses.
   *Release*; offering is your friend's choice.
7. **The Tor onion carrier**, the baseline that works from most networks: each node publishes a
   Tor onion service and dials its verified friends' onion services. Tor relays carry only
   Raven-encrypted bytes. The direct routes get a 1.5-second head start; whichever authenticates
   first carries the message, and a direct path wins as soon as it works. *Release.*
8. If nothing works now: **wait and retry**, or leave a sealed copy with a friend (section 3).

**When both sides are behind a "symmetric" (endpoint-dependent) NAT**, such as many mobile networks,
hole punching cannot work without guessing ports, and Raven does not try. The message goes through
a friend's relay if one is reachable, otherwise over Tor. In the field test the MacBook on a phone
hotspot had exactly this kind of NAT: hole punching never connected, and every message between the
hotspot and the home network went over Tor, 10 / 10 in every direction.

**The cost of Tor.**

- Time: about **11 to 28 seconds per message** in the field test. Each message used a new Tor
  connection, so later messages were not faster.
- Start-up: the onion service became reachable from about 10 seconds to 9 minutes after a start.
- Availability: on a long idle night, two computers' onion services were unreachable for 11 % and
  24 % of the time ("descriptor upload timed out") and came back by themselves. Raven now checks its
  own onion service and shows an outage history in `raven status`; the cause is not fixed.
- Privacy: your friend does not see your IP address on this path, and you do not see theirs. The
  first Tor relay sees your IP address and that you use Tor. Anyone who has your card can tell when
  your computer is online over Tor
  ([design](design/2026-10-tor-fallback.md) §3.8 and §8).

**Status.** Release builds have all seven since October 2026, switched on after the field test and
not independently reviewed. Listening for Internet direct and peer-to-peer stays off until you turn
it on, and a card carries no IP address, so with the defaults two computers on different networks
reach each other over Tor; once linked, each tells the other its direct routes. Relays over
WebSocket on port 443 (for networks that allow only web traffic) stay lab.

**Limits.**

- A network that blocks Tor (some do) leaves only the direct paths; between two such networks with
  hard NATs and no reachable friend, there is no path without someone's server.
- A friend who moved, behind a NAT that filters by address, can only be found again through a link
  that still works (a relay, Tor, the LAN). Without a third party both of you can reach, nothing
  can tell you their new endpoint.
- Clocks more than a few seconds apart make punching miss.
- STUN servers could lie. The worst they can do is make Raven offer a wrong address, which then
  fails; they learn nothing about your contacts.

**Specs and docs.** [RAVEN_ONION_CARRIER_V1](../protocol/RAVEN_ONION_CARRIER_V1.md),
[RAVEN_ROUTE_HINTS_V1](../protocol/RAVEN_ROUTE_HINTS_V1.md),
[RAVEN_PORT_MAPPING_V1](../protocol/RAVEN_PORT_MAPPING_V1.md),
[RAVEN_NEARBY_LINK_V1](../protocol/RAVEN_NEARBY_LINK_V1.md),
[RAVEN_WSS_TRANSPORT_V1](../protocol/RAVEN_WSS_TRANSPORT_V1.md) (relays on TCP 443),
[RAVEN_NAT_CONNECTIVITY_V1](../protocol/RAVEN_NAT_CONNECTIVITY_V1.md) (an older libp2p
experiment); designs [auto-reach](design/2026-10-auto-reach.md) (STUN and hole punching),
[Tor fallback](design/2026-10-tor-fallback.md),
[transports](design/2026-10-transports-internet-mesh-bridge.md);
[NAT_SOFTWARE_SIM.md](NAT_SOFTWARE_SIM.md), [RELAY_KIT.md](RELAY_KIT.md),
[network/raven-swarm-connectivity-matrix.md](network/raven-swarm-connectivity-matrix.md).

## 3. When the recipient is offline

**How, in release builds.** The sender's own `raven-node` keeps the sealed message in its outbox and
tries again regularly, and at once when the network changes. A **first** message to a friend
needs both computers online (any path above: the local network, a direct path or Tor). Both
computers must be on, with Raven running; a sleeping laptop receives nothing. See
[OFFLINE_GUIDE.md](OFFLINE_GUIDE.md) §3. Since October 2026 release builds also have the long
message horizon and friend custody (each friend agrees first), and Bluetooth carry on macOS; sealed
letters and two friends in a row stay lab:

- **Long message horizon:** a message gets one deadline, **7 days** after it was written. When its
  session expires it is parked and re-sealed under the same message id into a fresh session once
  the friend is reachable (at most 8 copies; receivers drop a copy they already have).
- **Friend custody:** Alice can leave a message for Bob with Carol, a friend **both** of them have
  verified, who agreed to keep mail. Carol keeps the **exact sealed envelope**; she cannot read it.
  Bob collects it from the friends he announced as his mail keepers, and Carol deletes it when Bob's
  Raven confirms it, or when it expires. Bob's receipt travels back the same way. Over the internet
  this uses any route that reaches Carol, Tor included.
- **Bluetooth carry** (macOS): a friend's laptop picks up a sealed message and hands it over when it
  is near the recipient (the field test's Bluetooth chain: 10 / 10 both ways).
- **Letters** (lab): for a friend away longer than a day, messages can travel as a sealed letter
  that a friend keeps for up to 7 days.
- **Two friends in a row** (custody handoff, lab) on a local network.

**Limits of friend custody** (from the code: `carrier_admission.rs`, `friend_custody.rs`, and the
consent text of `raven node custody on`):

| | |
|---|---|
| How long | a message at most **24 hours** (plus 5 minutes for clock skew); a letter at most 7 days |
| How much | at most 128 messages per pair, 512 messages or 16 MiB per depositor, 4,096 messages or 64 MiB per keeper, 2 MiB per minute per depositor. Over a limit the deposit is refused; nothing is ever evicted. |
| Who | only between people who are all verified contacts of each other, and only inside an existing session (a first message cannot go through a friend; letters are the exception) |
| What the keeper learns | for every message it keeps: who sent it to whom (both Raven identities), when, how big, when it was collected, and over the internet each friend's IP address (or relay). The envelopes are signed, so what it keeps is proof of who wrote to whom. |
| What it needs | a friend who is online when the sender is and again when the recipient is |

Nothing here makes delivery timely. If neither the sender nor any keeper is online when the
recipient is, the message waits, and after its deadline it is given up and the sender is told.

**Specs and docs.** [RAVEN_FRIEND_CUSTODY_V1](../protocol/RAVEN_FRIEND_CUSTODY_V1.md),
[RAVEN_CUSTODY_HANDOFF_V1](../protocol/RAVEN_CUSTODY_HANDOFF_V1.md),
[RAVEN_ASYNC_LETTER_V1](../protocol/RAVEN_ASYNC_LETTER_V1.md),
[RAVEN_DELIVERY_STATE_V1](../protocol/RAVEN_DELIVERY_STATE_V1.md); designs
[friend custody](design/2026-10-friend-custody.md), [beyond 24 h](design/2026-10-beyond-24h.md);
the custody errata draft
[SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md](SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md);
[SAFETY_OFFLINE.md](SAFETY_OFFLINE.md).

## 4. Knowing it is really your friend

**How.** A Raven identity is an Ed25519 key on your computer. From the **public** key Raven computes
ten everyday English **security words** from a fixed list of 256. Words 1 to 9 carry 72 bits of a
labelled hash of the key; word 10 is a check word that catches a misheard word or two swapped words
(it adds no security). When you add a friend, each of you reads your own ten words to the other, in
person or on a call, and types what you hear. Raven compares all ten, never shows the friend's words
before they match, asks for a fresh confirmation code to save the friend as verified, and stops after
three wrong sets. The older fingerprint code (`If4x-36FU-omFi` style) comes from the same key and is
still accepted.

**What it defends against.** Someone on the path you used to exchange cards (a chat app, an email, a
file) who replaced the key with their own: a man in the middle. Your friend's voice, or your friend in
front of you, is a second channel that person does not control. Forging a key whose words match a
given key takes about 2^72 key generations
([RAVEN_SECURITY_WORDS_V1](../protocol/RAVEN_SECURITY_WORDS_V1.md) §9).

**What it does not defend against.** Words that arrived in the same message as the card (they came
with the key, so they prove nothing); comparing only some of the words; malware on your friend's
computer; a friend who is not who you think they are.

**What verification changes.**

- An **unverified** contact can be reached only at addresses on your local network
  (`raven lan verified-only on` refuses them there too). Every path beyond the LAN (Internet direct,
  peer-to-peer, Tor, friend custody, Bluetooth nearby) needs a verified contact; the field test saw
  Tor links from a not-yet-verified contact refused. A LAN address that came in a card keeps the
  local-network rule even after you verified the friend (only the key is verified, not the card's
  other fields). Agent tasks over the app channel go to, and are taken from, verified contacts only.
- **Key change.** If a verified friend's address or name shows up with a different key, Raven prints
  a key-change warning and refuses to save it (`KEY_CHANGE_REFUSED_WITHOUT_REPIN`). To accept a new
  key you remove the old entry on purpose, then check the new key's words. Nothing overwrites a pin
  silently.
- There is no automatic key rotation or recovery of a lost key yet: a reinstall without the old key
  is a new identity. The identity continuity spec is required but not yet approved
  ([RAVEN_IDENTITY_CONTINUITY_V2](../protocol/RAVEN_IDENTITY_CONTINUITY_V2.md)).

**Status.** Security words, pinning and the key-change refusal are in release builds. The word list
is a draft until a listening test, and is frozen after it.

**Limits.** Verification is per computer: your friend checks you separately. On the live LAN path
the device key is the identity key, so one compromised computer compromises the identity, and
revocation is local only
([WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md)
§4).

**Specs and docs.** [SECURITY_WORDS.md](SECURITY_WORDS.md),
[RAVEN_SECURITY_WORDS_V1](../protocol/RAVEN_SECURITY_WORDS_V1.md),
[RAVEN_IDENTITY_V1](../protocol/RAVEN_IDENTITY_V1.md),
[RAVEN_IDENTITY_CONTINUITY_V2](../protocol/RAVEN_IDENTITY_CONTINUITY_V2.md),
[RAVEN_DEVICE_REVOCATION_V1](../protocol/RAVEN_DEVICE_REVOCATION_V1.md),
[THREAT_MODEL.md](THREAT_MODEL.md) §3.5 (active man in the middle).
