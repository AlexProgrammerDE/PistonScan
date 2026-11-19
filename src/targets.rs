use std::net::Ipv4Addr;
use std::ops::RangeInclusive;

use thiserror::Error;

#[derive(Debug, Error)]
#[error("Enter an IPv4 address or an IPv4 subnet in CIDR notation.")]
pub struct InvalidTarget;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Targets(RangeInclusive<u32>);

impl Targets {
    /// Parses a single IPv4 address or a CIDR range, including both endpoints.
    ///
    /// # Errors
    ///
    /// Returns an error if the address or subnet prefix is invalid.
    pub fn parse(input: &str) -> Result<Self, InvalidTarget> {
        let (address, prefix) = match input.trim().split_once('/') {
            Some((address, prefix)) => (
                address,
                prefix.parse::<u32>().map_err(|_error| InvalidTarget)?,
            ),
            None => (input.trim(), 32),
        };
        let address = u32::from(
            address
                .parse::<Ipv4Addr>()
                .map_err(|_error| InvalidTarget)?,
        );
        let host_bits = 32u32.checked_sub(prefix).ok_or(InvalidTarget)?;
        let network_mask = u32::MAX.checked_shl(host_bits).unwrap_or(0);
        Ok(Self((address & network_mask)..=(address | !network_mask)))
    }

    #[must_use]
    pub fn count(&self) -> u64 {
        u64::from(*self.0.end()) - u64::from(*self.0.start()) + 1
    }

    pub fn addresses(self) -> impl Iterator<Item = Ipv4Addr> {
        self.0.map(Ipv4Addr::from)
    }
}

#[cfg(test)]
mod tests {
    use super::{InvalidTarget, Targets};
    use std::net::Ipv4Addr;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Test assertions report fixture mismatches"
    )]
    fn includes_network_and_broadcast() -> Result<(), InvalidTarget> {
        let targets = Targets::parse("192.168.1.3/30")?;
        let addresses = targets.addresses().collect::<Vec<_>>();
        assert_eq!(
            addresses,
            [
                Ipv4Addr::new(192, 168, 1, 0),
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 2),
                Ipv4Addr::new(192, 168, 1, 3),
            ],
            "A host address in a CIDR resolves the entire subnet"
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Test assertions report fixture mismatches"
    )]
    fn handles_address_space_boundaries() -> Result<(), InvalidTarget> {
        let all = Targets::parse("0.0.0.0/0")?;
        assert_eq!(all.count(), 1u64 << 32, "A /0 spans all IPv4 addresses");
        let last = Targets::parse("255.255.255.255")?;
        assert_eq!(
            last.addresses().collect::<Vec<_>>(),
            [Ipv4Addr::BROADCAST],
            "The last address must not wrap around"
        );
        assert!(
            Targets::parse("1.2.3.4/33").is_err(),
            "An oversized prefix must fail"
        );
        Ok(())
    }
}
