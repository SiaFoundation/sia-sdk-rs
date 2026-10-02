/// helper module for base64 serialization
pub(crate) mod base64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let base64 = STANDARD.encode(v);
        s.serialize_str(&base64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        STANDARD
            .decode(base64.as_bytes())
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// Helper module for timestamps that indexd may encode as null. indexd's CBOR
/// encoder writes the zero `time.Time` as null instead of
/// "0001-01-01T00:00:00Z", so null decodes as the zero time. Timestamps
/// serialize as `Some` so that non-self-describing formats round trip.
pub mod null_as_zero_time {
    use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_some(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        Ok(Option::deserialize(d)?.unwrap_or_else(|| {
            NaiveDate::from_ymd_opt(1, 1, 1)
                .unwrap()
                .and_time(NaiveTime::MIN)
                .and_utc()
        }))
    }
}

/// Deserializes a fixed-size byte array type that serializes as a string in
/// human-readable formats and as a byte string otherwise. `parse` decodes the
/// string form and `from_bytes` the byte form.
pub fn deserialize_str_or_bytes<'de, D, T, F, E, const N: usize>(
    deserializer: D,
    parse: F,
    from_bytes: fn([u8; N]) -> T,
) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    F: FnOnce(&str) -> Result<T, E>,
    E: core::fmt::Display,
{
    struct StrOrBytesVisitor<T, F, const N: usize>(F, fn([u8; N]) -> T);

    impl<'de, T, F, E, const N: usize> serde::de::Visitor<'de> for StrOrBytesVisitor<T, F, N>
    where
        F: FnOnce(&str) -> Result<T, E>,
        E: core::fmt::Display,
    {
        type Value = T;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            write!(formatter, "a string or {N} bytes")
        }

        fn visit_str<DE: serde::de::Error>(self, value: &str) -> Result<Self::Value, DE> {
            (self.0)(value).map_err(DE::custom)
        }

        fn visit_bytes<DE: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, DE> {
            value
                .try_into()
                .map(self.1)
                .map_err(|_| DE::invalid_length(value.len(), &self))
        }
    }

    // Flattened structs do not preserve `is_human_readable`, so the
    // human-readable path also accepts bytes.
    if deserializer.is_human_readable() {
        deserializer.deserialize_str(StrOrBytesVisitor(parse, from_bytes))
    } else {
        deserializer.deserialize_bytes(StrOrBytesVisitor(parse, from_bytes))
    }
}

pub(crate) mod timestamp_array {
    use core::fmt;

    use chrono::{DateTime, FixedOffset, Utc};
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(timestamps: &[DateTime<Utc>; 11], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(11))?;
        for timestamp in timestamps {
            let rfc3339_string = timestamp.to_rfc3339();
            seq.serialize_element(&rfc3339_string)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[DateTime<Utc>; 11], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TimestampVisitor;

        impl<'de> Visitor<'de> for TimestampVisitor {
            type Value = [DateTime<Utc>; 11];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of 11 RC3339 timestamps")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut timestamps = [DateTime::UNIX_EPOCH; 11];

                let mut idx = 0;
                while let Some(value) = seq.next_element::<String>()? {
                    if idx >= 11 {
                        return Err(serde::de::Error::custom("too many timestamps"));
                    }
                    timestamps[idx] = DateTime::<FixedOffset>::parse_from_rfc3339(&value)
                        .map(|dt| dt.to_utc())
                        .map_err(serde::de::Error::custom)?;
                    idx += 1;
                }
                Ok(timestamps)
            }
        }
        deserializer.deserialize_seq(TimestampVisitor)
    }
}

/// Helper module for base64 serialization of `Vec<Vec<u8>>`.
pub(crate) mod vec_base64 {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(v: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: Vec<String> = v.iter().map(|bytes| STANDARD.encode(bytes)).collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: Vec<String> = Vec::deserialize(deserializer)?;
        encoded
            .into_iter()
            .map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

pub(crate) mod nano_second_duration {
    use chrono::Duration;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(
            v.num_nanoseconds()
                .ok_or(serde::ser::Error::custom("invalid duration"))? as u64,
        )
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let nanos = u64::deserialize(d)?;
        Ok(Duration::nanoseconds(nanos as i64))
    }
}
