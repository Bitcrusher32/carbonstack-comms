# Local Vault Model

The local vault stores:

- message database
- identity keys
- group state
- contact trust records
- revocation state

The vault must be cryptographically locked, not merely hidden.

In CarbonStackOS lockdown or duress states, vault keys should be evicted from memory and vault access should stop.
