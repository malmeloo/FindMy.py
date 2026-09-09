"""Value-free, allowlisted Apple boot schema diagnostics. Never persist raw HTML/JSON."""

import json
from typing import Any

from apple_fido import LIMIT, _unique_object
from bs4 import BeautifulSoup

# Only these constant names may appear in the output. Unknown/dynamic names are not echoed.
NAMES = frozenset(
    [
        "direct",
        "twoSV",
        "authFactors",
        "fsaVerification",
        "fsaChallenge",
        "challenge",
        "rpId",
        "keyHandles",
        "requestId",
        "type",
        "authType",
        "securityKeyVerification",
        "securityKeyChallenge",
        "securityKey",
        "authentication",
        "verification",
        "data",
        "auth",
        "hsa2",
        "phoneNumberVerification",
        "trustedPhoneNumbers",
        "securityCode",
        "federatedAuthentication",
        "account",
        "securityKeyData",
        "webAuthn",
        "publicKey",
        "allowCredentials",
        "id",
        "transports",
        "extensions",
        "userVerification",
        "timeout",
        "bootData",
        "authOptions",
        "mode",
        "version",
    ]
)
FACTORS = frozenset(
    ("fsa2_hsa2", "fsa2", "fsa1", "sms", "push", "trustedDeviceSecondaryAuth", "secondaryAuth")
)


def summarize_auth_page(html: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "format": "apple-auth-schema-v1",
        "raw_values_saved": False,
        "fields": [],
    }
    if not isinstance(html, str) or len(html) > LIMIT:
        out["parse_status"] = "size_or_type_rejected"
        return out
    tags = BeautifulSoup(html, "html.parser").select("script.boot_args")
    out["boot_args_count"] = min(len(tags), 10)
    if len(tags) != 1:
        out["parse_status"] = "boot_args_not_unique"
        return out
    try:
        boot = json.loads(tags[0].get_text(), object_pairs_hook=_unique_object)
    except Exception:
        out["parse_status"] = "invalid_json"
        return out
    out["parse_status"] = "ok"
    budget = [240]

    def visit(value: object, path: str, depth: int = 0) -> None:
        if budget[0] <= 0 or depth > 10:
            out["truncated"] = True
            return
        budget[0] -= 1
        kind = (
            "object"
            if isinstance(value, dict)
            else "array"
            if isinstance(value, list)
            else "null"
            if value is None
            else "boolean"
            if isinstance(value, bool)
            else "number"
            if isinstance(value, (int, float))
            else "string"
        )
        row: dict[str, Any] = {"path": path, "type": kind}
        out["fields"].append(row)
        if isinstance(value, dict):
            row["other_fields"] = sum(k not in NAMES for k in value)
            for key in sorted(NAMES.intersection(value)):
                visit(value[key], path + "." + key, depth + 1)
        elif isinstance(value, list):
            row["items"] = min(len(value), 100)
            # No individual IDs, handles, challenges, names, strings or sizes.
            row["item_types"] = sorted({type(v).__name__ for v in value[:100]})
            if path.endswith(".authFactors"):
                row["known_factors"] = sorted(
                    {v for v in value if isinstance(v, str) and v in FACTORS}
                )
                row["other_factors"] = any(
                    not isinstance(v, str) or v not in FACTORS for v in value
                )
            if value and isinstance(value[0], dict):
                visit(value[0], path + "[]", depth + 1)

    visit(boot, "$")
    return out
