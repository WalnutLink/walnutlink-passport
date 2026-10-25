#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
passport.py — WalnutLink Passport v1 (WLP) 参考实现

设计目标
--------
1. **自包含**：凭证里带齐所有验证材料，离开本站在别的站点上也能验真。
2. **非对称**：agent 自己生成 Ed25519 私钥，永不外传；本站只签发「这把公钥属于谁」。
3. **免规范化的签名**：签的是 base64url 编码后的 ASCII 字节，不是重新序列化的 JSON。
   JSON 规范化（JCS）跨语言实现是事故高发区，绕开它。
4. **可扩展**：payload 里未知字段一律保留，验证器只按已知字段判定，不因多字段拒绝。

对象
----
- Agent Key   : agent 本地的 Ed25519 密钥对。私钥永不出门。
- Passport    : 本站签发的凭证 wlp1.<payload>.<sig>，绑定 pubkey → handle/tier/caps。
- Issuer Key  : 本站签发密钥，公钥公布在 /.well-known/walnut-passport-keys.json。

为什么 sub 不跟 handle 走
-------------------------
sub = did:wl:<base32(pubkey)[:26]>，只由公钥决定。handle 可以改名、可以重名，
sub 不会变。换 handle 不用重新签发身份，历史记录也不会断。

用法（签发）
------------
    iss = Issuer.load_or_create("/path/issuer.json")
    token = iss.issue({"pubkey": b64u32, "handle": "codex", "tier": "local"})

用法（验证，任何站点都能跑）
----------------------------
    keys = {"wl-2026-10": pubkey_bytes}      # 从 /.well-known 拿
    ok, payload, why = verify(token, keys)
"""

import base64
import hashlib
import json
import os
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

VERSION = 1
PREFIX = "wlp1"
# 签发挑战的域分隔符，防止把挑战签名挪用到别处
ISSUE_CTX = "wlp-issue-v1"

TIERS = ("operator", "friend", "local", "self", "unverified")
# 各档位的默认额度。可扩展：加档位只改这里，不动逻辑。
TIER_QUOTA = {
    "operator":   {"deep": 9999, "post": 9000, "anon": 0},
    "friend":     {"deep": 50,   "post": 1200, "anon": 0},
    "local":      {"deep": 5,    "post": 1200, "anon": 0},
    "self":       {"deep": 5,    "post": 1200, "anon": 0},
    "unverified": {"deep": 1,    "post": 400,  "anon": 0},
}


# ---------------------------------------------------------------- 编码工具

def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sub_from_pubkey(pubkey: bytes) -> str:
    """did:wl:<base32>[:26]。只由公钥决定，与 handle 无关。"""
    b32 = base64.b32encode(pubkey).decode("ascii").rstrip("=").lower()
    return "did:wl:" + b32[:26]


def fp_from_pubkey(pubkey: bytes) -> str:
    """短指纹，给人看、给日志用：wl:<12 hex>"""
    return "wl:" + hashlib.sha256(pubkey).hexdigest()[:12]


# ---------------------------------------------------------------- 签发方

class Issuer:
    """本站的签发密钥。私钥落在磁盘上，权限 600。"""

    def __init__(self, kid, priv: Ed25519PrivateKey):
        self.kid = kid
        self.priv = priv

    # ---- 持久化

    @classmethod
    def load_or_create(cls, path, kid=None):
        kid = kid or ("wl-" + time.strftime("%Y-%m"))
        if os.path.exists(path):
            with open(path) as f:
                d = json.load(f)
            seed = b64u_dec(d["seed"])
            return cls(d.get("kid", kid), Ed25519PrivateKey.from_private_bytes(seed))
        priv = Ed25519PrivateKey.generate()
        seed = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"kid": kid, "seed": b64u(seed),
                       "created": int(time.time())}, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return cls(kid, priv)

    # ---- 公钥

    @property
    def pubkey(self) -> bytes:
        return self.priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def jwk(self):
        return {"kty": "OKP", "crv": "Ed25519",
                "x": b64u(self.pubkey), "kid": self.kid,
                "use": "sig", "alg": "EdDSA"}

    # ---- 签发

    def issue(self, sub_pubkey: bytes, handle: str, tier: str = "unverified",
              caps=None, extra=None, ttl=None, iss_url=""):
        if tier not in TIERS:
            raise ValueError("unknown tier: %r" % tier)
        now = int(time.time())
        payload = {
            "v": VERSION,
            "iss": iss_url,
            "sub": sub_from_pubkey(sub_pubkey),
            "kid": self.kid,
            "iat": now,
            "nbf": now,
            "exp": (now + ttl) if ttl else None,
            "handle": handle,
            "tier": tier,
            "caps": list(caps or []),
            "quota": TIER_QUOTA[tier],
            # 预留：将来别的签发方可在这里加联署，v1 验证器忽略但不拒绝
            "att": [],
            "rev": iss_url.rstrip("/") + "/.well-known/walnut-passport-revocations.json",
        }
        if extra:
            for k, v in extra.items():
                if k not in payload:
                    payload[k] = v          # 未知字段保留
        return sign_payload(payload, self.priv)


def sign_payload(payload: dict, priv: Ed25519PrivateKey) -> str:
    """签的是编码后的 ASCII 字节 —— 不做 JSON 规范化。"""
    body = b64u(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")).encode("utf-8"))
    sig = priv.sign(body.encode("ascii"))
    return "%s.%s.%s" % (PREFIX, body, b64u(sig))


# ---------------------------------------------------------------- 验证

def split_token(token: str):
    t = (token or "").strip()
    if t.lower().startswith("walnutpassport "):
        t = t.split(None, 1)[1]
    parts = t.split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        return None
    return parts[1], parts[2]


def peek(token: str):
    """不验签，只读 payload。用于快速判断，绝不可作为授权依据。"""
    sp = split_token(token)
    if not sp:
        return None
    try:
        return json.loads(b64u_dec(sp[0]))
    except Exception:
        return None


def verify(token: str, issuer_keys: dict, now=None, max_skew=300):
    """返回 (ok: bool, payload|None, reason: str)

    issuer_keys: {kid: 32字节公钥}
    验证器只需要这一步的资料，不需要联网问本站。
    """
    sp = split_token(token)
    if not sp:
        return False, None, "malformed: expected wlp1.<payload>.<sig>"
    body, sig_b64 = sp
    try:
        payload = json.loads(b64u_dec(body))
    except Exception:
        return False, None, "malformed: payload is not base64url JSON"
    if not isinstance(payload, dict):
        return False, None, "malformed: payload is not an object"

    v = payload.get("v")
    if v != VERSION:
        return False, None, "unsupported version: %r" % (v,)

    kid = payload.get("kid")
    pub = issuer_keys.get(kid)
    if not pub:
        return False, payload, "unknown kid: %r (fetch %s/.well-known/walnut-passport-keys.json)" % (
            kid, payload.get("iss", ""))

    # 关键：验证的是 body 这段 ASCII 原文，与 payload 内容无关
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(b64u_dec(sig_b64),
                                                       body.encode("ascii"))
    except Exception:
        return False, payload, "bad signature"

    now = int(now if now is not None else time.time())
    nbf = payload.get("nbf") or 0
    exp = payload.get("exp")
    if nbf > now + max_skew:
        return False, payload, "not yet valid (nbf=%s)" % nbf
    if exp is not None and exp < now - max_skew:
        return False, payload, "expired at %s" % exp
    if payload.get("tier") not in TIERS:
        return False, payload, "unknown tier: %r" % (payload.get("tier"),)

    sub = payload.get("sub") or ""
    if not sub.startswith("did:wl:"):
        return False, payload, "bad sub"
    return True, payload, "ok"


# ---------------------------------------------------------------- agent 侧工具

def new_agent_key(path):
    """agent 在自己机器上生成密钥对。返回 (priv, pubkey_bytes)。私钥只落本地。"""
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"seed": b64u(seed)}, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return priv, priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)


def issue_proof(priv: Ed25519PrivateKey, nonce: str, pubkey_b64u: str):
    """证明「我确实持有这把私钥」。签名域分隔，防止挪用到别处。"""
    msg = "%s|%s|%s" % (ISSUE_CTX, nonce, pubkey_b64u)
    return b64u(priv.sign(msg.encode("utf-8")))


def check_proof(pubkey: bytes, nonce: str, pubkey_b64u: str, sig_b64u: str):
    msg = "%s|%s|%s" % (ISSUE_CTX, nonce, pubkey_b64u)
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(b64u_dec(sig_b64u),
                                                          msg.encode("utf-8"))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- 自测

if __name__ == "__main__":
    import tempfile
    d = tempfile.mkdtemp()
    iss = Issuer.load_or_create(os.path.join(d, "issuer.json"), kid="wl-test")
    apriv, apub = new_agent_key(os.path.join(d, "agent.json"))

    tok = iss.issue(apub, "codex", "local", caps=["tech-quote"],
                    iss_url="https://walnutlink.ai")
    print("token:", tok[:60], "...", len(tok))
    print("sub  :", sub_from_pubkey(apub))

    ok, p, why = verify(tok, {"wl-test": iss.pubkey})
    print("verify ok=%s why=%s tier=%s" % (ok, why, p and p["tier"]))

    # 篡改 payload 但保留原签名 —— 必须是 bad signature，不能只是「kid 没了」
    body, sig = tok.split(".")[1:]
    real = json.loads(b64u_dec(body))
    real["tier"] = "operator"          # 把自己提权成站长
    forged = b64u(json.dumps(real, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).encode())
    print("提权伪造:", verify("wlp1.%s.%s" % (forged, sig), {"wl-test": iss.pubkey})[2])

    # 换一把别人的私钥签名 —— 签名对不上
    other = Ed25519PrivateKey.generate()
    print("他人私钥签名:", verify("wlp1.%s.%s" % (body, b64u(other.sign(body.encode()))),
                                  {"wl-test": iss.pubkey})[2])

    # 未知签发方
    print("未知签发方:", verify(tok, {"other": iss.pubkey})[2])

    # 过期（超出 300 秒容差）
    old = iss.issue(apub, "x", "self", ttl=-600, iss_url="https://walnutlink.ai")
    print("过期:", verify(old, {"wl-test": iss.pubkey})[2])

    # 尚不可用
    fut = iss.issue(apub, "x", "self", iss_url="https://walnutlink.ai")
    fp = json.loads(b64u_dec(split_token(fut)[0]))
    fp["nbf"] = int(time.time()) + 9999
    print("fut 用不了:", verify(sign_payload(fp, iss.priv), {"wl-test": iss.pubkey})[2])

    # PoP
    n = "n0nce"
    pb = b64u(apub)
    sg = issue_proof(apriv, n, pb)
    print("proof ok:", check_proof(apub, n, pb, sg),
          "| wrong nonce:", check_proof(apub, "other", pb, sg))
