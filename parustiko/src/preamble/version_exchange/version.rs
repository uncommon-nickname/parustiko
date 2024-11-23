use super::errors::VersionExchangeError;
use super::SshVersion;
use std::fmt;

impl SshVersion {
    pub fn try_build(
        proto_version: &str,
        software_version: &str,
        comments: Option<&str>,
    ) -> Result<Self, VersionExchangeError> {
        // TODO? maybe forbidden list?
        if proto_version != "1.0" && proto_version != "2.0" {
            return Err(VersionExchangeError::InvalidProtoVersion(
                "correct versions: '1.0' or '2.0'",
            ));
        }

        if software_version.len() > 255 {
            return Err(VersionExchangeError::TooLongString("Software version"));
        }

        if let Some(c) = comments {
            if c.len() > 255 {
                return Err(VersionExchangeError::TooLongString("Comment"));
            }
        }

        Ok(Self {
            proto_version: proto_version.to_string(),
            software_version: software_version.to_string(),
            comments: comments.map(|c| c.to_string()),
        })
    }

    pub fn from_string(version_string: &str) -> Result<Self, VersionExchangeError> {
        if !version_string.starts_with("SSH-") {
            return Err(VersionExchangeError::InvalidSshMsgFormat(
                "Missing 'SSH-' part",
            ));
        }

        let clean_str = version_string
            .trim_end_matches("\r\n")
            .trim_start_matches("SSH-");

        let parts: Vec<&str> = clean_str.splitn(3, ' ').collect();

        if parts.len() < 2 {
            return Err(VersionExchangeError::InvalidSshMsgFormat(
                "Malformed SSH version exchange string",
            ));
        }

        let proto_version = parts[0].to_string();
        let software_version = parts[1].to_string();
        let comments = if parts.len() == 3 {
            Some(parts[2].to_string())
        } else {
            None
        };

        Ok(Self {
            proto_version,
            software_version,
            comments,
        })
    }

    pub fn to_string(&self) -> String {
        let mut result = format!("SSH-{}-{}", self.proto_version, self.software_version);
        if let Some(ref comments) = self.comments {
            result.push(' ');
            result.push_str(comments);
        }
        result.push_str("\r\n");
        result
    }
}

impl fmt::Display for SshVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};

    #[test]
    fn test_correct_create_verion_exchange_structure() {
        let msg = SshVersion::try_build("2.0", "OpenSSH-XXX", None);
        assert!(msg.is_ok());
    }

    // #[rstest]
    // #[case(
    //     "3.0",
    //     "",
    //     "Proto version incorrect - correct versions: '1.0' or '2.0'"
    // )]
    // #[case("2.0", "A".repeat(256), "padding is too short for SSH message")]
    // #[case(vec![0_u8; 5], 25, "unknown SSH message ID")]
    // fn test_create_message_errors(
    //     #[case] proto_version: &str,
    //     #[case] software_version: &str,
    //     #[case] comment: Option<&str>,
    //     #[case] err_str: &str,
    // ) {
    //     let err = SshVersion::try_build(proto_version, software_version, comment)
    //         .unwrap_err()
    //         .to_string();

    //     assert_eq!(err, err_str);
    // }
    #[test]
    fn test_incorrect_proto_version() {
        let err = SshVersion::try_build("3.0", "", None)
            .unwrap_err()
            .to_string();

        assert_eq!(
            err,
            "Proto version incorrect - correct versions: '1.0' or '2.0'"
        );
    }

    #[test]
    fn test_too_long_software_version() {
        let sw = "a".repeat(256);
        let err = SshVersion::try_build("2.0", sw.as_str(), None)
            .unwrap_err()
            .to_string();

        assert_eq!(err, "Software version too long");
    }

    #[test]
    fn test_too_long_comment() {
        let c = "a".repeat(256);
        let err = SshVersion::try_build("2.0", "abc", Some(c.as_str()))
            .unwrap_err()
            .to_string();

        assert_eq!(err, "Comment too long");
    }
}
