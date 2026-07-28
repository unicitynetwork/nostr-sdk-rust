/**
 * Golden-vector generator for the Rust port (nostr-sdk-rust).
 * Emits deterministic interop vectors from THIS reference SDK so the Rust
 * implementation can assert byte-for-byte parity.
 *
 * Run from the nostr-js-sdk repo:
 *   npx vitest run tests/gen-vectors.test.ts
 * Output: /home/pavelg/unicity/nostr-sdk-rust/tests/vectors/nostr-vectors.json
 */
import { describe, it } from 'vitest';
import { writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { schnorr } from '@noble/curves/secp256k1';
import * as Schnorr from '../src/crypto/schnorr.js';
import * as NIP04 from '../src/crypto/nip04.js';
import * as NIP44 from '../src/crypto/nip44.js';
import * as Bech32 from '../src/crypto/bech32.js';
import { Event } from '../src/protocol/Event.js';
import * as EventKinds from '../src/protocol/EventKinds.js';
import * as NIP17 from '../src/messaging/nip17.js';
import * as Nametag from '../src/nametag/NametagUtils.js';
import { NostrKeyManager } from '../src/NostrKeyManager.js';

const OUT =
  process.env.VECTORS_OUT ||
  '/home/pavelg/unicity/nostr-sdk-rust/tests/vectors/nostr-vectors.json';

const enc = new TextEncoder();
const priv = (label: string): Uint8Array => sha256(enc.encode(label));

describe('gen-vectors', () => {
  it('emits interop vectors', async () => {
    const privA = priv('unicity-test-alice');
    const privB = priv('unicity-test-bob');
    const pubA = Schnorr.getPublicKey(privA); // x-only 32B
    const pubB = Schnorr.getPublicKey(privB);
    const hx = bytesToHex;

    const v: any = {
      note: 'Generated from @unicitylabs/nostr-js-sdk v0.6.0 by tests/gen-vectors.test.ts. Do not edit by hand.',
      keys: {
        alice: { priv: hx(privA), xonly_pub: hx(pubA), npub: Bech32.encodeNpub(pubA), nsec: Bech32.encodeNsec(privA) },
        bob: { priv: hx(privB), xonly_pub: hx(pubB), npub: Bech32.encodeNpub(pubB), nsec: Bech32.encodeNsec(privB) },
      },
      event_ids: [] as any[],
      schnorr: [] as any[],
      nip04: {} as any,
      nip44: {} as any,
      bech32: [] as any[],
    };

    const evCases = [
      { pubkey: hx(pubA), created_at: 1700000000, kind: 1, tags: [] as string[][], content: 'hello world' },
      {
        pubkey: hx(pubA),
        created_at: 1712345678,
        kind: 14,
        tags: [['p', hx(pubB)], ['e', 'abc', '', 'reply']] as string[][],
        content: 'unicode: café 😀 — "quotes" \\ backslash \n newline \t tab',
      },
      { pubkey: hx(pubB), created_at: 0, kind: 30078, tags: [['d', 'x'], ['L', 'unicity:nametag']] as string[][], content: '{"nametag_hash":"deadbeef"}' },
    ];
    for (const c of evCases) {
      const id = Event.calculateId(c.pubkey, c.created_at, c.kind, c.tags as any, c.content);
      v.event_ids.push({ ...c, id });
    }

    // Schnorr with fixed aux=zeros => deterministic, byte-exact against Rust sign_raw([0;32])
    const msg1 = hexToBytes(v.event_ids[0].id);
    const aux0 = new Uint8Array(32);
    const sigA = schnorr.sign(msg1, privA, aux0);
    v.schnorr.push({
      priv: hx(privA), xonly_pub: hx(pubA), msg: hx(msg1), aux: hx(aux0), sig: hx(sigA), valid: schnorr.verify(sigA, msg1, pubA),
    });

    // NIP-04
    v.nip04.shared_secret = {
      a_priv: hx(privA), b_pub: hx(pubB), secret: NIP04.deriveSharedSecretHex(hx(privA), hx(pubB)),
    };
    v.nip04.messages = [];
    for (const m of ['hi', 'The quick brown fox jumps over the lazy dog', 'x'.repeat(2000)]) {
      const payload = await NIP04.encrypt(m, privA, pubB);
      v.nip04.messages.push({ plaintext: m, from_priv: hx(privA), from_pub: hx(pubA), to_pub: hx(pubB), payload, gz: payload.startsWith('gz:') });
    }

    // NIP-44 (TS/AEAD variant)
    v.nip44.conversation_key = {
      a_priv: hx(privA), b_pub: hx(pubB), key: NIP44.deriveConversationKeyHex(hx(privA), hx(pubB)),
    };
    v.nip44.conversation_key_reverse = NIP44.deriveConversationKeyHex(hx(privB), hx(pubA));
    v.nip44.messages = [];
    for (const m of ['hi', 'a'.repeat(50), 'unicode 😀 café', 'y'.repeat(500)]) {
      const payload = NIP44.encrypt(m, privA, pubB);
      v.nip44.messages.push({ plaintext: m, from_priv: hx(privA), from_pub: hx(pubA), to_pub: hx(pubB), payload });
    }

    v.bech32.push({ hrp: 'npub', hex: hx(pubA), encoded: Bech32.encodeNpub(pubA) });
    v.bech32.push({ hrp: 'nsec', hex: hx(privA), encoded: Bech32.encodeNsec(privA) });

    // NIP-17 gift-wrapped DMs. Gift wraps are non-deterministic (random ephemeral
    // key + timestamps + nonces), so we emit a real gift wrap from alice->bob and
    // the Rust port asserts it UNWRAPS to the expected rumor. We also self-check
    // the unwrap here in JS.
    const aliceKM = NostrKeyManager.fromPrivateKeyHex(hx(privA));
    const bobKM = NostrKeyManager.fromPrivateKeyHex(hx(privB));
    const bobPubHex = hx(pubB);
    v.nip17 = { messages: [] as any[] };
    {
      const content = 'hey bob 👋 gm from the reference sdk';
      const gw = NIP17.createGiftWrap(aliceKM, bobPubHex, content);
      const pm = NIP17.unwrap(gw, bobKM);
      v.nip17.messages.push({
        desc: 'basic',
        gift_wrap: gw.toJSON(),
        expect: {
          sender_pub: hx(pubA),
          recipient_pub: hx(pubB),
          content,
          kind: EventKinds.CHAT_MESSAGE,
          js_unwrapped_content: pm.content,
        },
      });
    }
    {
      const replyId = v.event_ids[0].id;
      const content = 'this is a reply';
      const gw = NIP17.createGiftWrap(aliceKM, bobPubHex, content, { replyToEventId: replyId });
      const pm = NIP17.unwrap(gw, bobKM);
      v.nip17.messages.push({
        desc: 'reply',
        gift_wrap: gw.toJSON(),
        expect: {
          sender_pub: hx(pubA),
          recipient_pub: hx(pubB),
          content,
          kind: EventKinds.CHAT_MESSAGE,
          reply_to: replyId,
          js_unwrapped_reply: pm.replyToEventId,
        },
      });
    }

    // UNIP-01 nametag utils (deterministic hashing/normalization/validation +
    // recoverable encrypted_nametag). Phone/E.164 nametags are out of scope.
    v.nametag = {
      sha256_hex: [{ input: 'unicity:nametag:alice', hex: Nametag.sha256Hex('unicity:nametag:alice') }],
      hash_nametag: ['Alice', 'bob_the_agent', 'Carol@unicity', '  spaced  '].map((n) => ({
        nametag: n,
        hash: Nametag.hashNametag(n),
      })),
      hash_address: ['DIRECT://0000abcdef', 'alpha1qxyz'].map((a) => ({
        address: a,
        hash: Nametag.hashAddressForTag(a),
      })),
      valid: ['@alice', 'ab', 'has space', 'bob_the_agent', 'UPPER'].map((n) => ({
        nametag: n,
        valid: Nametag.isValidNametag(n),
      })),
      encrypt: [] as any[],
    };
    for (const nm of ['my-agent', 'unicode-tag-😀']) {
      const payload = await Nametag.encryptNametag(nm, hx(privA));
      v.nametag.encrypt.push({ nametag: nm, priv: hx(privA), payload });
    }

    mkdirSync(dirname(OUT), { recursive: true });
    writeFileSync(OUT, JSON.stringify(v, null, 2));
    // eslint-disable-next-line no-console
    console.log('wrote vectors to', OUT);
  });
});
