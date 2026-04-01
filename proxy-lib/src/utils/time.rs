use std::{
    ops::{Add, Sub},
    time::SystemTime,
};

use rama::utils::time::now_unix_ms;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SystemTimestampMilliseconds(i64);

impl SystemTimestampMilliseconds {
    pub const EPOCH: SystemTimestampMilliseconds = SystemTimestampMilliseconds(0);
    pub const MAX: SystemTimestampMilliseconds = SystemTimestampMilliseconds(i64::MAX);
}

impl From<SystemTime> for SystemTimestampMilliseconds {
    fn from(system_time: SystemTime) -> Self {
        Self(match system_time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => d.as_millis().try_into().unwrap_or(i64::MAX),
            Err(e) => {
                let ms: i64 = e.duration().as_millis().try_into().unwrap_or(i64::MAX);
                -ms
            }
        })
    }
}

impl Serialize for SystemTimestampMilliseconds {
    #[inline(always)]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SystemTimestampMilliseconds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let n = i64::deserialize(deserializer)?;
        Ok(Self(n))
    }
}

pub mod system_time_serde_seconds {
    use super::SystemTimestampMilliseconds;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        value: &SystemTimestampMilliseconds,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(value.0 / 1_000)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTimestampMilliseconds, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = i64::deserialize(deserializer)?;
        Ok(SystemTimestampMilliseconds(secs.saturating_mul(1_000)))
    }
}

pub mod option_system_time_serde_seconds {
    use super::SystemTimestampMilliseconds;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        value: &Option<SystemTimestampMilliseconds>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(&(value.0 / 1_000)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<SystemTimestampMilliseconds>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = Option::<i64>::deserialize(deserializer)?;
        Ok(secs.map(|secs| SystemTimestampMilliseconds(secs.saturating_mul(1_000))))
    }
}

impl SystemTimestampMilliseconds {
    pub fn now() -> Self {
        Self(now_unix_ms())
    }

    #[cfg(test)]
    pub fn is_positive_epoch_msg(self) -> bool {
        self.0 > 0
    }

    pub fn elapsed_since(other: Self) -> SystemDuration {
        SystemDuration(Self::now().0.saturating_sub(other.0))
    }
}

impl Add<SystemDuration> for SystemTimestampMilliseconds {
    type Output = Self;

    fn add(self, dur: SystemDuration) -> Self::Output {
        Self(self.0.saturating_add(dur.0))
    }
}

impl Sub<SystemDuration> for SystemTimestampMilliseconds {
    type Output = Self;

    fn sub(self, dur: SystemDuration) -> Self::Output {
        Self(self.0.saturating_sub(dur.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SystemDuration(i64);

impl SystemDuration {
    pub const fn milliseconds(n: u32) -> Self {
        Self(n as i64)
    }

    pub const fn seconds(n: u32) -> Self {
        Self((n as i64) * 1_000)
    }

    pub const fn minutes(n: u16) -> Self {
        Self::seconds((n as u32) * 60)
    }

    pub const fn hours(n: u16) -> Self {
        Self::seconds((n as u32) * 60 * 60)
    }

    pub const fn days(n: u8) -> Self {
        Self::hours((n as u16) * 24)
    }

    pub const fn weeks(n: u8) -> Self {
        Self::days(n * 7)
    }
}
