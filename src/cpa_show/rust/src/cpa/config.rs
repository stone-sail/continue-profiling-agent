// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub raw: BTreeMap<String, String>,
    pub cpu_num: Option<u32>,
    pub freq: Option<u32>,
    pub record_interval: Option<u32>,
    /// `us` when counts are microseconds (stores mixing on- and off-CPU);
    /// a perf event name when counts are estimated events of `--perf_event`;
    /// absent when counts are on-CPU samples.
    pub count_unit: Option<String>,
}

/// First frame after the metadata entry of an off-CPU stack.
pub const OFFCPU_MARKER: &str = "<# OFFCPU SAMPLE";

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut raw = BTreeMap::new();

        for line in content.lines() {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_string();
                let val = v.trim().to_string();
                if !key.is_empty() {
                    raw.insert(key, val);
                }
            }
        }

        let cpu_num = raw.get("cpu_num").and_then(|v| v.parse().ok());
        let freq = raw.get("freq").and_then(|v| v.parse().ok());
        let record_interval = raw.get("record_interval").and_then(|v| v.parse().ok());
        let count_unit = raw.get("count_unit").cloned();

        Ok(Self {
            raw,
            cpu_num,
            freq,
            record_interval,
            count_unit,
        })
    }

    /// Counts that add up to one core busy for one second; `None` when
    /// counts are events rather than time.
    /// jemalloc inuse stores keep one heap snapshot per record; a range shows
    /// its last snapshot instead of a sum.
    pub fn is_snapshot(&self) -> bool {
        self.raw.get("count_mode").map(String::as_str) == Some("snapshot")
    }

    pub fn counts_per_core_second(&self) -> Option<f64> {
        match self.count_unit.as_deref() {
            Some("us") => Some(1_000_000.0),
            Some(_) => None,
            None => self.freq.map(|f| f as f64).filter(|f| *f > 0.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_conf_basic() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("conf");
        fs::write(
            &p,
            "cpu_num: 8\nfreq: 99\nrecord_interval: 5\nfoo: bar baz\n",
        )
        .unwrap();

        let c = Config::load(&p).unwrap();
        assert_eq!(c.cpu_num, Some(8));
        assert_eq!(c.freq, Some(99));
        assert_eq!(c.record_interval, Some(5));
        assert_eq!(c.raw.get("foo").unwrap(), "bar baz");
    }

    #[test]
    fn counts_per_core_second_by_unit() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("conf");

        fs::write(&p, "freq: 49\n").unwrap();
        assert_eq!(Config::load(&p).unwrap().counts_per_core_second(), Some(49.0));

        fs::write(&p, "freq: 49\ncount_unit: us\n").unwrap();
        assert_eq!(Config::load(&p).unwrap().counts_per_core_second(), Some(1_000_000.0));

        fs::write(&p, "freq: 49\ncount_unit: branch-misses\n").unwrap();
        assert_eq!(Config::load(&p).unwrap().counts_per_core_second(), None);

        fs::write(&p, "count_unit: bytes\ncount_mode: snapshot\n").unwrap();
        let c = Config::load(&p).unwrap();
        assert_eq!(c.counts_per_core_second(), None);
        assert!(c.is_snapshot());

        fs::write(&p, "count_unit: bytes\ncount_mode: delta\n").unwrap();
        assert!(!Config::load(&p).unwrap().is_snapshot());
    }
}
