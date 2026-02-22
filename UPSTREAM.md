# Upstream Bug Tracking Register

This document serves as a central register for tracking bugs, architectural limitations, and missing features discovered in upstream projects (e.g., `systemd`, `iwd`, `linux kernel`) during the development of RXNM (ROCKNIX Network Manager).

By maintaining this register, we track the status of our upstream contributions (Issues/PRs) and document the rationale behind any downstream patches, forks, or workarounds currently maintained within the RXNM ecosystem.

## Active Tracking

### 1. systemd: Managed IPv4 Link-Local (RFC 3927) Restrictions

* **Project**: `systemd` (`systemd-networkd`)

* **Discovered**: During RXNM USB Gadget (NCM/RNDIS) and Point-to-Point integration testing.

* **Upstream Issue**: [systemd/systemd#40783](https://github.com/systemd/systemd/issues/40783)

* **Upstream PR**: [systemd/systemd#40785](https://github.com/systemd/systemd/pull/40785)

* **Impact on RXNM**: High. Prevented the use of `169.254.x.x` subnets for managed Point-to-Point links, forcing the use of standard RFC 1918 space (e.g., `192.168.x.x`) which introduced severe subnet collision hazards with host networks.

* **Description**: `systemd-networkd` hard-coded aggressive restrictions against the `169.254.0.0/16` subnet, conflating the physical address space with the unmanaged ZeroConf Auto-IP mechanism. It prevented `DHCPServer` from binding to IPv4LL addresses, trapped `DHCP4` client leases in a `degraded` (`RT_SCOPE_LINK`) state, and rejected IPv4LL default gateways as unreachable.

* **Current Mitigation**: We maintain a downstream patchset (documented in `ADR-001: Support for Managed IPv4 Link-Local Networks`) in our `systemd` fork to unblock the DHCP Server, promote the client scope to `RT_SCOPE_UNIVERSE`, and whitelist the gateway readiness checks. Awaiting upstream merge.

## Resolved / Merged

*(No resolved upstream issues yet)*
