use super::SshVersion;
use crate::errors::VersionExchangeError;
use std::fmt;
use std::io::Read;

impl SshVersion {
    pub fn try_build(
        proto_version: &str,
        software_version: &str,
        comments: Option<&str>,
    ) -> Result<Self, VersionExchangeError> {
        if proto_version != "1.0" && proto_version != "2.0" {
            return Err(VersionExchangeError::InvalidProtoVersion(
                "correct versions: '1.0' or '2.0'",
            ));
        }

        if software_version.len() > 255 {
            return Err(VersionExchangeError::InvalidString(
                "Software version string is too long",
            ));
        }

        if let Some(c) = comments {
            if c.len() > 255 {
                return Err(VersionExchangeError::InvalidString(
                    "Comment string is too long",
                ));
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

        let parts: Vec<&str> = clean_str.split(' ').collect();

        let proto_version: String;
        let software_version: String;
        if let Some((proto, software)) = parts[0].split_once('-') {
            proto_version = proto.to_string();
            software_version = software.to_string();
        } else {
            return Err(VersionExchangeError::InvalidSshMsgFormat(
                "Malformed SSH version exchange string",
            ));
        }

        let comments = if parts.len() == 2 {
            Some(parts[1].to_string())
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

    // Read bytes from stream until CR and LF ('\r\n') occur
    pub fn read_header<R: Read>(arr: &mut R) -> Result<Vec<u8>, VersionExchangeError> {
        const MAX_SIZE: usize = 51; // max size defined by RFC4253
        let mut header = vec![0; MAX_SIZE];

        _ = arr.read_exact(&mut header[..1]);
        for i in 1..MAX_SIZE {
            _ = arr.read_exact(&mut header[i..(i + 1)]);
            if header[i - 1] == 13 && header[i] == 10 {
                return Ok(header[..(i + 1)].to_vec());
            }
        }

        Err(VersionExchangeError::EmptyStream(format!(
            "Not found '\r\n in the first {MAX_SIZE} bytes"
        )))
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
    use rstest::rstest;

    #[test]
    fn test_correct_create_verion_exchange_structure() {
        let msg = SshVersion::try_build("2.0", "parustiko-XXX", None);
        assert!(msg.is_ok());

        let version = msg.unwrap();
        assert_eq!(version.proto_version, "2.0");
        assert_eq!(version.software_version, "parustiko-XXX");
        assert_eq!(version.comments, None);
    }

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

        assert_eq!(err, "Software version string is too long");
    }

    #[test]
    fn test_too_long_comment() {
        let c = "a".repeat(256);
        let err = SshVersion::try_build("2.0", "abc", Some(c.as_str()))
            .unwrap_err()
            .to_string();

        assert_eq!(err, "Comment string is too long");
    }

    #[test]
    fn test_build_from_string_with_comments() {
        let result = SshVersion::from_string("SSH-2.0-parustiko-XXX comments\r\n");
        assert!(result.is_ok());

        let version = result.unwrap();
        assert_eq!(version.proto_version, "2.0");
        assert_eq!(version.software_version, "parustiko-XXX");
        assert_eq!(version.comments, Some("comments".to_string()));
    }

    #[test]
    fn test_build_from_string_without_comments() {
        let result = SshVersion::from_string("SSH-2.0-parustiko-XXX");
        assert!(result.is_ok());

        let version = result.unwrap();
        assert_eq!(version.proto_version, "2.0");
        assert_eq!(version.software_version, "parustiko-XXX");
        assert_eq!(version.comments, None);
    }

    #[rstest]
    #[case("SSH-2.0parustikoXXX\r\n", "Malformed SSH version exchange string")]
    #[case("2.0-parustiko-XXX\r\n", "Missing 'SSH-' part")]
    fn test_invalid_string_message(#[case] msg: &str, #[case] err_str: &str) {
        let result = SshVersion::from_string(msg);
        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert_eq!(err, err_str);
    }

    #[test]
    fn test_version_to_string() {
        let version = SshVersion {
            proto_version: "2.0".to_string(),
            software_version: "parustiko".to_string(),
            comments: None,
        };

        assert_eq!(version.to_string(), "SSH-2.0-parustiko\r\n");
    }

    #[test]
    fn test_read_header_invalid_stream_bytes() {
        let mut stream = std::io::Cursor::new(b"SSH".to_vec());

        let result = SshVersion::read_header(&mut stream);
        assert!(result.is_err());

        let msg = result.unwrap_err().to_string();
        assert_eq!(msg, "Not found '\r\n in the first 51 bytes");
    }

    #[test]
    fn test_read_header_success() {
        let server_response = b"SSH\r\n";
        let mut stream = std::io::Cursor::new(server_response.to_vec());

        let result = SshVersion::read_header(&mut stream);
        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data, [83, 83, 72, 13, 10]);
    }
}
