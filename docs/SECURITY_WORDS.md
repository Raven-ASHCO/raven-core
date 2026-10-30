# Security words

Your **security words** are 10 everyday English words that belong to your Raven identity. When you
add a friend, you each read your own words to the other, in person or on a phone call, and type
what you hear. If they match, nobody swapped the key between you.

> **Status: development build.** The word list is a **draft** until an English listening test
> (people reading sets aloud over a phone call). It may still change before it is frozen, and never
> after. The old-style code (below) never changes. The format is specified in
> [`protocol/RAVEN_SECURITY_WORDS_V1.md`](../protocol/RAVEN_SECURITY_WORDS_V1.md).

Commands below use `raven`; `ash` is the same program.

## What they are

```
 1 turtle    2 frog      3 bread     4 wolf      5 paper
 6 laptop    7 funnel    8 mango     9 honey    10 wagon
```

(An example: the words of a published test key. Never verify anyone with words copied from
documentation.)

- Raven computes the words on your computer from your identity's **public** key: the same key your
  `rvn1…` address and your old-style code come from. The same key always gives the same words; a
  different key gives different words.
- Words 1 to 9 come from the key. Word 10 is a **check word**: it lets Raven notice a word that was
  misheard, or two words that were swapped, before comparing anything.
- Nothing new is sent. Invites and contact cards are unchanged; each Raven works the words out from
  the key it already has.

## Where to find yours

- **The terminal app** (`raven` with no arguments): the first-run screen 'Your security words',
  and the verify screen, under 'Your words: read these to *name*'.
- **`raven whoami --words`**: the `words` line. `raven whoami --json --words` has them as
  `security_words`. Plain `raven whoami`, `raven status` and `raven doctor` never show them: that
  output gets pasted into messages and bug reports, and words that travel with the key prove
  nothing.
- **In a chat** (`raven send --contact <name> --chat`): `/verify` shows your words and the command
  that checks your friend's.

## Why compare them

An invite or a `whoami` block reaches you through a message app, an email or a file, and someone
on that path could replace the key with their own. Your friend's voice, or your friend in front of
you, is a second path that person does not control. If the words your friend reads match the key
you saved, it is really their key.

Words that arrived in the same message as the invite (a pasted `whoami` block of an older Raven had
a `words` line) came with the key, so they prove nothing. Only words you hear from your friend count.

## How to compare

1. Call your friend or meet in person.
2. Each of you reads **all 10** of your own words to the other, in order. Comparing only some of
   them is much weaker.
3. Each of you types what you hear. Raven compares; you never have to judge it by eye.
   - The first 3 letters of a word are enough (`tur` is turtle), and a plural is fine (`frogs`).
   - Upper and lower case don't matter. Numbers, commas, dots and dashes between the words are
     ignored, so `1. turtle 2. frog …` works.
4. When they match, Raven says **They match ✓**. In the terminal app and at a terminal prompt you
   then type the short confirmation code shown on the screen to save your friend as verified. It
   is new every time, so pasted text can't confirm by itself.

### In the terminal app

- **Adding a friend:** after you paste their invite and give them a name, the screen 'Check it's
  really *name*' opens.
- **A friend saved without checking:** their conversation on Home says 'You haven't checked this
  is really *name*'. Choose the friend in the list and press `V`, or press `V` on their page.
- **Keys:** `Tab` (or `Space`) picks the word suggested, `Enter` checks, `Ctrl+O` switches to the
  old-style code and back, `Esc` cancels and saves nothing. For a new friend, `Tab` with no word
  being typed is **Later**: save them as not verified and check another time.
- The screen never shows your friend's words before they match. A typed word gets a dot that only
  means "a Raven word", never "right" or "wrong", and the suggestions come from the whole list. So
  the screen can't help anyone guess the words one at a time.
- Once a friend is verified, their page shows their security words and their old-style code. Before
  that it says 'Security words: hidden until you verify *name* (press V)'.

### On the command line

```sh
raven contact verify Bob     # at a terminal: type the 10 words Bob reads to you
raven contact verify Bob --check "<the 10 words Bob reads to you>"     # one step, for scripts
raven contact add --address <address> --pub-hex <pub_hex> --petname Bob \
                  --verify-words "<the 10 words Bob reads to you>"     # check while adding
```

- `contact verify` at a terminal shows nothing of Bob's before the match, then asks for the
  confirmation code. A friend can be named by name, `@tag` or `rvn1…` address.
- `--check` and `--verify-words` save nothing and exit with code 1 when the words are not Bob's.
  `--verify-words` is another name for `--verify-fp`.
- The classic menu (`5`, then `a`): paste the friend's block or invite and answer its questions,
  then press `V` at `[V]erify & pin / [C]ontinue unpinned / [A]bort` and type the words, then the
  confirmation code.

## What Raven tells you

| Raven says | It means | Do this |
|---|---|---|
| 'turtel' isn't one of Raven's words | A typo or a misheard word. It says nothing about the key. | Fix the spelling, or type the first 3 letters. |
| Type at least 3 letters of word 4 | Too few letters to tell which word. | Type more of it. |
| Type the words with English letters | The keyboard is set to another alphabet. | Switch the keyboard to English letters. |
| You typed 9 words. A set has 10 | A word was missed (or one too many). | Ask your friend which one. |
| These 10 words don't fit together | The check word caught a misheard word, or two swapped words. | Ask your friend to read them again, slowly. |
| These are real Raven words, but not *name*'s | **A mismatch.** | Read the next section. |
| They match ✓ | It is the key your friend has. | Type the confirmation code to save them as verified. |

Only the mismatch says anything about your friend's key. Every other message is about what was
typed, and you can simply type again. (`contact add --verify-words` reports a mismatch as
'security words do not match this key: refusing to pin'.)

## If the words don't match

**Do not verify.** Nothing was saved or changed.

A mismatch means the key you have for this friend is not the key on their computer. Common
reasons:

- the wrong invite was pasted (an old one, or someone else's);
- your friend reinstalled Raven or moved to a new computer, so they have a new key and new words;
- someone on the way swapped the key for their own.

What to do:

- Ask your friend to run `raven whoami --words` and read the `words` line again, slowly, from their
  own screen.
- If the words still differ, get a fresh invite from them by another way (in person is best), and
  add them again: remove the old entry first (`X` on their page, or `raven contact remove`).
- Never "fix" a mismatch with words copied from a message.

In the terminal app and in `raven contact verify`, after 3 entries that are not your friend's,
Raven stops checking ('Stop here. Check with *name* another way (in person)…'). That stops anyone
from trying sets until one fits.

## The words are public

- They are **not a password**. Anyone may know them, and reading them aloud in a cafe is fine. What
  matters is that your friend hears them **from you**.
- They are not a seed or a recovery phrase. They can't open your messages or restore your
  identity: they are worked out from your public key, which you share anyway.
- **Raven never asks you for secret words.** If something asks for your "recovery words" in
  Raven's name, it is not Raven.

## The old-style code (for an older Raven)

Before security words, Raven showed a code such as `If4x-36FU-omFi` (the `fingerprint` line of
`raven whoami`). It comes from the same key, so it always agrees with the words. Raven still shows
it and still accepts it everywhere.

- A friend with an **older Raven** can only show and check the code. Read them your old-style
  code, and type theirs.
- Where to find yours: under your words on the first-run screen, the `fingerprint` line of
  `raven whoami`, and `/verify` in a chat.
- The terminal app: `Ctrl+O` on the verify screen switches to the old code, and back.
- The command line: type the code wherever words are asked for. `--verify-fp`, `--verify-words`,
  `contact verify --check` and the classic menu's verify prompt all take either. An entry of 3
  groups or fewer is read as the code.
- The code is **case-sensitive** (`W` is not `w`); dashes and spaces don't matter.
- Some command-line messages still say "fingerprint" (for example the `pinned no` line after
  `contact add`): they mean this code, and the words work there too.

## What verifying does

- It marks the friend as **verified** (pinned) on **this computer only**. Your friend checks you
  separately, on theirs.
- Raven never checks this for you, and never marks a friend as verified by itself.
- A new key can't quietly take a verified friend's place: Raven warns, and refuses until you
  remove the old entry on purpose. Then check the new key. The README's
  [pairing section](../README.md#pairing-two-terminals--two-machines) says what pinning does and
  does not enforce.

## Not in this version

- The word list is a draft until the listening test; it is frozen after it.
- RDAP (the agent tool) shows fingerprints, not security words, so far.
- Raven apps that don't show words yet, and older versions, compare with the old-style code.
