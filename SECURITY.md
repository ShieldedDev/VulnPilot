# Security Considerations

## Authorized Use Only

VulnPilot is intended for authorized security testing only. It should never be used against targets without appropriate consent.

## Safe Defaults

The project now includes more conservative defaults:

- certificate verification enabled by default
- lower concurrency by default
- retry-limited behavior
- user-agent identification for scanner traffic
- scope-managed scanning controls

## Important Limitations

The current scanner is best treated as an evidence-focused reconnaissance and candidate discovery tool. It is not a destructive exploitation framework.

## Guidance

- do not execute untrusted PoCs automatically
- avoid internal network expansion without explicit scope approval
- log only operational metadata, not sensitive credentials
- prefer evidence-based findings with low false-positive risk
