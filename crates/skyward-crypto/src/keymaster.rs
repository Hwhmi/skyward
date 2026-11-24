//! The phone's key service as phones up to Android 12 describe it: a
//! hardware service reached over the hardware driver, whose interface is
//! numbered 4.0. Its calls take the older layout, where a run of bytes is
//! written as a frame saying where it is followed by an address, and its
//! parameters are a run of fixed-size records.
//!
//! None of this changes anything of the phone's own: a key is only ever
//! unwrapped in the secure world, and the plaintext of a decryption comes
//! back here.

// The calls and answers serve the phone's own driver; the host tests use
// the layout alone.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use anyhow::{bail, Context, Result};
use skyward_binder::hidl::{self, Answer, Message};

/// The service as the phone's hardware directory knows it.
pub const SERVICE: &str = "android.hardware.keymaster@4.0::IKeymasterDevice";
const INSTANCE: &str = "default";

/// The methods, as 4.0 numbers them: the ones this program calls.
const GET_HARDWARE_INFO: u32 = 1;
const GET_KEY_CHARACTERISTICS: u32 = 9;
const UPGRADE_KEY: u32 = 12;
const BEGIN: u32 = 16;
const UPDATE: u32 = 17;
const FINISH: u32 = 18;
const ABORT: u32 = 19;

/// How a parameter is laid out: its tag, four bytes of padding, the
/// discriminator of its value, four more, and the value.
pub const PARAMETER_BYTES: usize = 32;
const VALUE_AT: usize = 16;

/// The top of a tag says which kind of value it carries.
const TAG_KIND: i32 = -268_435_456;
const KIND_ULONG: i32 = 1_342_177_280;
const KIND_ULONG_REP: i32 = -1_610_612_736;
const KIND_DATE: i32 = 1_610_612_736;
const KIND_BYTES: i32 = -1_879_048_192;
const KIND_BIGNUM: i32 = -2_147_483_648;

const PURPOSE_DECRYPT: i32 = 1;
const BLOCK_MODE_GCM: i32 = 32;
const PADDING_NONE: i32 = 1;

const TAG_PURPOSE: i32 = 536_870_913;
const TAG_BLOCK_MODE: i32 = 536_870_916;
const TAG_PADDING: i32 = 536_870_918;
const TAG_MAC_LENGTH: i32 = 805_307_371;
const TAG_APPLICATION_ID: i32 = -1_879_047_591;
const TAG_NONCE: i32 = -1_879_047_191;

const VALUE_PADDING_MODE: i32 = 3;
const VALUE_KEY_PURPOSE: i32 = 7;
const VALUE_INTEGER: i32 = 11;
const VALUE_BLOB: i32 = 14;
const VALUE_BLOCK_MODE: i32 = 2;

/// How long the nonce of an AES-GCM key is here.
const NONCE_BYTES: usize = 12;

/// The key service's way of saying the key was made under an older build of
/// the phone's own firmware and has to be renewed before it will be used.
const KEY_REQUIRES_UPGRADE: i32 = -62;

/// What the phone says about its key hardware.
pub struct Hardware {
    pub version: i32,
    pub security_level: i32,
    pub name: String,
    pub author: String,
}

/// A parameter as the call writes it.
enum Value<'a> {
    Enum(i32, i32),
    Integer(i32),
    Blob(&'a [u8]),
}

pub struct Parameter<'a> {
    tag: i32,
    value: Value<'a>,
}

fn enum_of(tag: i32, arm: i32, value: i32) -> Parameter<'static> {
    Parameter { tag, value: Value::Enum(arm, value) }
}

/// The parameters a decryption is opened with: how the key is used, how
/// long its tag is, what it is bound to, and the nonce. A key bound to
/// nothing names nothing: the secure world folds the binding into the key
/// it unwraps, so an empty binding is not the same to it as none.
fn gcm<'a>(app_id: &'a [u8], nonce: &'a [u8]) -> Vec<Parameter<'a>> {
    let mut params = vec![
        enum_of(TAG_BLOCK_MODE, VALUE_BLOCK_MODE, BLOCK_MODE_GCM),
        enum_of(TAG_PADDING, VALUE_PADDING_MODE, PADDING_NONE),
        Parameter { tag: TAG_MAC_LENGTH, value: Value::Integer(128) },
    ];
    if !app_id.is_empty() {
        params.push(Parameter { tag: TAG_APPLICATION_ID, value: Value::Blob(app_id) });
    }
    params.push(Parameter { tag: TAG_NONCE, value: Value::Blob(nonce) });
    params.push(enum_of(TAG_PURPOSE, VALUE_KEY_PURPOSE, PURPOSE_DECRYPT));
    params
}

/// A run of parameters, each a record of its own.
fn parameters(call: &mut Message, params: &[Parameter]) {
    call.records(params.len(), PARAMETER_BYTES, |r| {
        for (i, param) in params.iter().enumerate() {
            let at = i * PARAMETER_BYTES;
            r.u32(at, param.tag as u32);
            match param.value {
                Value::Enum(arm, value) => {
                    r.u32(at + 8, arm as u32);
                    r.u32(at + VALUE_AT, value as u32);
                }
                Value::Integer(value) => {
                    r.u32(at + 8, VALUE_INTEGER as u32);
                    r.u32(at + VALUE_AT, value as u32);
                }
                Value::Blob(bytes) => {
                    r.u32(at + 8, VALUE_BLOB as u32);
                    r.bytes(at + VALUE_AT, bytes);
                }
            }
        }
    });
}

/// The phone's key service, as this program talks to it.
#[cfg(target_os = "android")]
pub struct Keymaster<'a> {
    device: skyward_binder::driver::Handle<'a>,
}

#[cfg(target_os = "android")]
impl<'a> Keymaster<'a> {
    /// Reach the running key service, or say that none is.
    pub fn open(hardware: &'a skyward_binder::driver::Binder) -> Result<Keymaster<'a>> {
        let device = hidl::find(hardware, SERVICE, INSTANCE)?
            .with_context(|| format!("{SERVICE}/{INSTANCE} is not running; the phone's key service has to be started first"))?;
        Ok(Keymaster { device })
    }

    /// What the service says about itself. This changes nothing, so it is
    /// what to call to see that the service answers at all.
    pub fn hardware(&self) -> Result<Hardware> {
        let what = "ask the key service about itself";
        let reply = self.device.transact(GET_HARDWARE_INFO, &Message::call(SERVICE)).context(what)?;
        let mut read = Answer::new(reply.bytes());
        let security_level = read.i32().context(what)?;
        let name = read.text_run().context(what)?;
        let author = read.text_run().context(what)?;
        Ok(Hardware { version: 400, security_level, name, author })
    }

    /// What the key service says a key may be used for: each entry is a tag
    /// and the number or length that came with it.
    pub fn authorizations(&self, key_blob: &[u8], app_id: &[u8]) -> Result<Vec<(i32, i64)>> {
        let what = "ask what the key may be used for";
        let mut call = Message::call(SERVICE);
        call.bytes(key_blob);
        call.bytes(app_id);
        call.bytes(&[]);
        let reply = self.device.transact(GET_KEY_CHARACTERISTICS, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        let error = read.i32().context(what)?;
        if error != 0 {
            bail!("{what}: the key service refused with its code {error}");
        }
        read.align(8);
        let (count, raw) = read.run().context(what)?;
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let at = i * PARAMETER_BYTES;
            if at + PARAMETER_BYTES > raw.len() {
                break;
            }
            let tag = i32::from_le_bytes(raw[at..at + 4].try_into().expect("four bytes"));
            let arm = i32::from_le_bytes(raw[at + 8..at + 12].try_into().expect("four bytes"));
            let value = match tag & TAG_KIND {
                KIND_ULONG | KIND_ULONG_REP | KIND_DATE => {
                    i64::from_le_bytes(raw[at + VALUE_AT..at + VALUE_AT + 8].try_into().expect("eight bytes"))
                }
                KIND_BYTES | KIND_BIGNUM => {
                    u64::from_le_bytes(raw[at + VALUE_AT + 8..at + VALUE_AT + 16].try_into().expect("eight bytes")) as i64
                }
                _ if arm == VALUE_BLOB => 0,
                _ => i32::from_le_bytes(raw[at + VALUE_AT..at + VALUE_AT + 4].try_into().expect("four bytes")) as i64,
            };
            out.push((tag, value));
        }
        Ok(out)
    }

    /// Undo an AES-GCM encryption the key service did with `key_blob`. The
    /// service only hands back the plaintext when `app_id` is the one the
    /// key was made for, so a wrong secret fails here rather than yielding
    /// something that looks like a key.
    pub fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8]) -> Result<Vec<u8>> {
        let handle = self.begin(key_blob, app_id, nonce)?;
        let mut out = self.update(handle, body)?;
        out.extend_from_slice(&self.finish(handle, &[])?);
        Ok(out)
    }

    /// Whether the secure world will unwrap the key at all: a decryption is
    /// opened under a nonce of nothing and dropped again, which reads
    /// nothing and changes nothing.
    pub fn usable(&self, key_blob: &[u8], app_id: &[u8]) -> Result<()> {
        let handle = self.begin(key_blob, app_id, &[0; NONCE_BYTES])?;
        self.abort(handle)
    }

    fn begin(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8]) -> Result<u64> {
        let what = "start a decryption";
        let mut call = Message::call(SERVICE);
        call.u32(PURPOSE_DECRYPT as u32);
        call.align(8);
        call.bytes(key_blob);
        parameters(&mut call, &gcm(app_id, nonce));
        // A key that is not guarded by the screen lock takes no note, which
        // is written as a token of nothing.
        call.vacant(AUTH_TOKEN_BYTES);
        let reply = self.device.transact(BEGIN, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        let error = read.i32().context(what)?;
        if error != 0 {
            bail!("{what}: the key service refused with its code {error}");
        }
        read.align(8);
        read.run().context("read what the decryption came back with")?;
        let handle = read.i64().context("read the decryption the key service opened")?;
        Ok(handle as u64)
    }

    fn update(&self, handle: u64, input: &[u8]) -> Result<Vec<u8>> {
        let what = "feed the decryption";
        let mut call = Message::call(SERVICE);
        call.u64(handle);
        call.records(0, PARAMETER_BYTES, |_| {});
        call.bytes(input);
        call.vacant(AUTH_TOKEN_BYTES);
        call.vacant(VERIFICATION_TOKEN_BYTES);
        let reply = self.device.transact(UPDATE, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        let error = read.i32().context(what)?;
        if error != 0 {
            bail!("{what}: the key service refused with its code {error}");
        }
        read.i32().context("read how much the decryption took")?;
        read.align(8);
        read.run().context("read what the decryption came back with")?;
        let (_, output) = read.run().context("read what the decryption gave back")?;
        Ok(output.to_vec())
    }

    fn finish(&self, handle: u64, signature: &[u8]) -> Result<Vec<u8>> {
        let what = "close the decryption, which is where a wrong key is refused";
        let mut call = Message::call(SERVICE);
        call.u64(handle);
        call.records(0, PARAMETER_BYTES, |_| {});
        call.bytes(&[]);
        call.bytes(signature);
        call.vacant(AUTH_TOKEN_BYTES);
        call.vacant(VERIFICATION_TOKEN_BYTES);
        let reply = self.device.transact(FINISH, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        let error = read.i32().context(what)?;
        if error != 0 {
            bail!("{what}: the key service refused with its code {error}");
        }
        read.align(8);
        read.run().context("read what the decryption came back with")?;
        let (_, output) = read.run().context("read what the decryption ended with")?;
        Ok(output.to_vec())
    }

    fn abort(&self, handle: u64) -> Result<()> {
        let what = "drop the decryption";
        let mut call = Message::call(SERVICE);
        call.u64(handle);
        let reply = self.device.transact(ABORT, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        let error = read.i32().context(what)?;
        if error != 0 {
            bail!("{what}: the key service refused with its code {error}");
        }
        Ok(())
    }

    /// A key for the firmware running now, from one made under an older
    /// build.
    pub fn upgrade(&self, key_blob: &[u8], params: &[Parameter]) -> Result<Vec<u8>> {
        let what = "renew the key";
        let mut call = Message::call(SERVICE);
        call.bytes(key_blob);
        parameters(&mut call, params);
        let reply = self.device.transact(UPGRADE_KEY, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        let error = read.i32().context(what)?;
        if error != 0 {
            bail!("{what}: the key service refused with its code {error}");
        }
        read.align(8);
        let (_, renewed) = read.run().context("read the renewed key")?;
        Ok(renewed.to_vec())
    }
}

/// How long the note the secure world wrote for a screen lock is: its four
/// numbers, its type, its time, and a run of bytes for the mark.
const AUTH_TOKEN_BYTES: usize = 8 + 8 + 8 + 8 + 8 + 16 + 80;

/// How long a token saying what was verified is, which is handed over empty
/// here: two times, an empty run of parameters, its level, and an empty
/// mark.
const VERIFICATION_TOKEN_BYTES: usize = 8 + 8 + 16 + 80 + 4 + 4 + 16 + 80;
