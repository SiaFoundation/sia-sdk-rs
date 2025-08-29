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

pub(crate) mod timestamp_array {
    use core::fmt;

    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S>(timestamps: &[OffsetDateTime; 11], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(11))?;
        for timestamp in timestamps {
            let rfc3339_string = timestamp
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(serde::ser::Error::custom)?;
            seq.serialize_element(&rfc3339_string)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[OffsetDateTime; 11], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TimestampVisitor;

        impl<'de> Visitor<'de> for TimestampVisitor {
            type Value = [OffsetDateTime; 11];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of 11 RC3339 timestamps")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut timestamps = [OffsetDateTime::UNIX_EPOCH; 11];

                let mut idx = 0;
                while let Some(value) = seq.next_element::<String>()? {
                    if idx >= 11 {
                        return Err(serde::de::Error::custom("too many timestamps"));
                    }
                    timestamps[idx] = OffsetDateTime::parse(
                        &value,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .map_err(serde::de::Error::custom)?;
                    idx += 1;
                }
                Ok(timestamps)
            }
        }
        deserializer.deserialize_seq(TimestampVisitor)
    }
}

/// helper module for Vec<Vec<u8>> base64 serialization
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
    use serde::{Deserialize, Deserializer, Serializer};
    use time::Duration;

    pub fn serialize<S: Serializer>(v: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(v.whole_nanoseconds() as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let nanos = u64::deserialize(d)?;
        Ok(Duration::nanoseconds(nanos as i64))
    }
}
