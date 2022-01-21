use std::borrow::Cow;
use usiem::components::parsing::LogParsingError;
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::intrusion::{IntrusionCategory, IntrusionEvent, IntrusionOutcome};
use usiem::events::protocol::NetworkProtocol;
use usiem::events::{field_dictionary, SiemEvent, SiemLog};

pub fn paloalto_threat<'a>(
    field_map: Vec<&'a str>,
    mut log: SiemLog,
) -> Result<SiemLog, LogParsingError> {

    match field_map.get(1) {
        Some(md) => {
            log.add_field("observer.id", SiemField::Text(Cow::Owned(md.to_string())));
        }
        None => return Err(LogParsingError::NoValidParser(log)),
    };
    log.set_vendor(Cow::Borrowed("PaloAlto"));
    log.set_product(Cow::Borrowed("PaloAlto"));
    log.set_category(Cow::Borrowed("Firewall"));

    let subtype = match field_map.get(3) {
        Some(category) => category,
        None => return Err(LogParsingError::ParserError(log, "Less than 3 csv columns".to_string())),
    };
    let event_outcome = match field_map.get(29) {
        Some(event_outcome) => match *event_outcome {
            "alert" => IntrusionOutcome::DETECTED,
            "allow" => IntrusionOutcome::DETECTED,
            "drop" => IntrusionOutcome::BLOCKED,
            "reset-client" => IntrusionOutcome::BLOCKED,
            "reset-server" => IntrusionOutcome::BLOCKED,
            "reset-both" => IntrusionOutcome::BLOCKED,
            "block-url" => IntrusionOutcome::BLOCKED,
            "block-ip" => IntrusionOutcome::BLOCKED,
            "random-drop" => IntrusionOutcome::DETECTED,
            "sinkhole" => IntrusionOutcome::BLOCKED,
            "syncookie-sent" => IntrusionOutcome::DETECTED,
            "block-continue" => IntrusionOutcome::BLOCKED,
            "continue" => IntrusionOutcome::MONITOR,
            "block-override" => IntrusionOutcome::BLOCKED,
            "override-lockout" => IntrusionOutcome::BLOCKED,
            "override" => IntrusionOutcome::MONITOR,
            "block" => IntrusionOutcome::BLOCKED,
            _ => return Err(LogParsingError::FormatError(log, "Invalid event.outcome".to_string())),
        },
        None => return Err(LogParsingError::ParserError(log, "Nonexistent event.outcome".to_string())),
    };

    let source_ip = match field_map.get(6) {
        Some(srcip) => match SiemIp::from_ip_str(*srcip) {
            Ok(srcip) => srcip,
            Err(_) => return Err(LogParsingError::ParserError(log, "Invalid source.ip".to_string())),
        },
        None => return Err(LogParsingError::ParserError(log, "Innexistent source.ip".to_string())),
    };
    let destination_ip = match field_map.get(7) {
        Some(destination_ip) => match SiemIp::from_ip_str(*destination_ip) {
            Ok(destination_ip) => destination_ip,
            Err(_) => return Err(LogParsingError::ParserError(log, "Invalid destination.ip".to_string())),
        },
        None => return Err(LogParsingError::ParserError(log, "Innexistent destination.ip".to_string())),
    };
    let (rule_name, rule_id) = match field_map.get(31) {
        Some(name) => match extract_rule_info(*name) {
            Ok((name, id)) => (name, id.parse::<u32>().unwrap_or(0)),
            Err(_) => return Err(LogParsingError::ParserError(log, "Invalid rule.name and rule.id".to_string())),
        },
        None => return Err(LogParsingError::ParserError(log, "Nonexistent rule.name and rule.id".to_string())),
    };

    match field_map.get(11) {
        Some(user) => match *user {
            "" => {}
            v => {
                log.add_field("source.user.name", SiemField::from_str(v.to_string()));
            }
        },
        None => return Err(LogParsingError::ParserError(log, "Nonexistent source.user.name".to_string())),
    };
    match field_map.get(12) {
        Some(user) => match *user {
            "" => {}
            v => {
                log.add_field("destination.user.name", SiemField::from_str(v.to_string()));
            }
        },
        None => return Err(LogParsingError::ParserError(log, "Nonexistent destination.user.name".to_string())),
    };
    match field_map.get(13) {
        Some(app) => match *app {
            "" => {}
            "not-applicable" => {}
            v => {
                log.add_field("service.name", SiemField::from_str(v.to_string()));
            }
        },
        None => return Err(LogParsingError::ParserError(log, "Nonexistent service.name".to_string())),
    };
    match field_map.get(34) {
        Some(val) => {
            match *val {
                "client-to-server" => log.add_field(
                    "network.direction",
                    SiemField::Text(Cow::Borrowed("client-to-server")),
                ),
                "server-to-client" => log.add_field(
                    "network.direction",
                    SiemField::Text(Cow::Borrowed("server-to-client")),
                ),
                "0" => log.add_field(
                    "network.direction",
                    SiemField::Text(Cow::Borrowed("client-to-server")),
                ),
                "1" => log.add_field(
                    "network.direction",
                    SiemField::Text(Cow::Borrowed("server-to-client")),
                ),
                _ => {}
            };
        }
        None => {}
    };

    //contenttype
    match field_map.get(39) {
        Some(val) => {
            if val != &"" {
                log.add_field(
                    field_dictionary::HTTP_RESPONSE_MIME_TYPE,
                    SiemField::Text(Cow::Owned(val.to_string())),
                );
            }
        }
        None => {}
    };
    //filedigest
    match field_map.get(41) {
        Some(val) => {
            if val != &"" {
                log.add_field("file.hash", SiemField::Text(Cow::Owned(val.to_string())));
            }
        }
        None => {}
    };
    //user_agent
    match field_map.get(44) {
        Some(val) => {
            if val != &"" {
                log.add_field(
                    "http.request.user_agent",
                    SiemField::Text(Cow::Owned(val.to_string())),
                );
            }
        }
        None => {}
    };
    //xff
    match field_map.get(46) {
        Some(val) => {
            if val != &"" {
                log.add_field(
                    "http.request.x_forwarded_for",
                    SiemField::Text(Cow::Owned(val.to_string())),
                );
            }
        }
        None => {}
    };
    //referer
    match field_map.get(47) {
        Some(val) => {
            if val != &"" {
                log.add_field(
                    "http.request.referer",
                    SiemField::Text(Cow::Owned(val.to_string())),
                );
            }
        }
        None => {}
    };
    //sender
    match field_map.get(48) {
        Some(val) => {
            if val != &"" {
                log.add_field(
                    "source.user.email",
                    SiemField::Text(Cow::Owned(val.to_string())),
                );
            }
        }
        None => {}
    };
    //subject
    match field_map.get(49) {
        Some(val) => {
            if val != &"" {
                log.add_field("mail.subject", SiemField::Text(Cow::Owned(val.to_string())));
            }
        }
        None => {}
    };
    //recipient
    match field_map.get(50) {
        Some(val) => {
            if val != &"" {
                log.add_field(
                    "destination.user.email",
                    SiemField::Text(Cow::Owned(val.to_string())),
                );
            }
        }
        None => {}
    };
    //http_method
    match field_map.get(57) {
        Some(val) => {
            if val != &"" {
                log.add_field(
                    field_dictionary::HTTP_REQUEST_METHOD,
                    SiemField::Text(Cow::Owned(val.to_string())),
                );
            }
        }
        None => {}
    };

    match field_map.get(17) {
        Some(val) => {
            log.add_field(
                field_dictionary::IN_INTERFACE,
                SiemField::Text(Cow::Owned(val.to_string())),
            );
        }
        None => {}
    };
    match field_map.get(18) {
        Some(val) => {
            log.add_field(
                field_dictionary::OUT_INTERFACE,
                SiemField::Text(Cow::Owned(val.to_string())),
            );
        }
        None => {}
    };
    //sessionid
    match field_map.get(21) {
        Some(val) => {
            log.add_field("trace.id", SiemField::Text(Cow::Owned(val.to_string())));
        }
        None => {}
    };

    let source_port = field_map
        .get(23)
        .map(|c| (*c).parse::<u16>().unwrap_or(0))
        .unwrap_or(0);
    let destination_port = field_map
        .get(24)
        .map(|c| (*c).parse::<u16>().unwrap_or(0))
        .unwrap_or(0);

    let network_transport = field_map
        .get(28)
        .map(|c| parse_network_transport(c))
        .unwrap_or(NetworkProtocol::UNKNOWN);
    // TODO:
    /*
    PaloAlto Subtype of threat log. Values include the following:
    data—Data pattern matching a Data Filtering profile.
    file—File type matching a File Blocking profile.
    flood—Flood detected via a Zone Protection profile.
    packet—Packet-based attack protection triggered by a Zone Protection profile.
    scan—Scan detected via a Zone Protection profile.
    spyware —Spyware detected via an Anti-Spyware profile.
    url—URL filtering log.
    virus—Virus detected via an Antivirus profile.
    vulnerability —Vulnerability exploit detected via a Vulnerability Protection profile.
    wildfire —A WildFire verdict generated when the firewall submits a file to WildFire per a WildFire Analysis profile and a verdict (malicious, phishing, grayware, or benign, depending on what you are logging) is logged in the WildFire Submissions log.
    wildfire-virus—Virus detected via an Antivirus profile.
    */
    let rule_category = match rule_id {
        9999 => IntrusionCategory::PHISHING,
        r_id if r_id >= 8_000 && r_id < 8_100 => IntrusionCategory::SURVEILLANCE,
        r_id if r_id >= 8_500 && r_id < 8_600 => IntrusionCategory::DOS,
        r_id if r_id >= 10_000 && r_id < 20_000 => IntrusionCategory::SPYWARE,
        r_id if r_id >= 20_000 && r_id < 30_000 => IntrusionCategory::SPYWARE,
        r_id if r_id >= 30_000 && r_id < 45_000 => IntrusionCategory::REMOTE_EXPLOIT,
        r_id if r_id >= 52_000 && r_id < 53_000 => IntrusionCategory::VIRUS,
        r_id if r_id >= 60_000 && r_id < 70_000 => IntrusionCategory::DATA_THEFT,
        _ => IntrusionCategory::UNKNOWN, //Not known
    };

    match field_map.get(30) {
        Some(file_url) => {
            let file_url = escape_string(file_url);
            if ["file", "spyware", "wildfire", "wildfire-virus", "virus"].contains(subtype) {
                log.add_field("file.name", SiemField::from_str(file_url.to_string()));
            } else if "url" == *subtype {
                log.add_field(
                    field_dictionary::URL_FULL,
                    SiemField::from_str(file_url.to_string()),
                );
            }
        }
        None => return Err(LogParsingError::ParserError(log, "Nonexistent file_url field".to_string())),
    };

    let event = IntrusionEvent {
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        network_protocol: network_transport,
        outcome: event_outcome,
        rule_id,
        rule_name: Cow::Owned(rule_name.to_string()),
        rule_category,
    };
    log.set_event(SiemEvent::Intrusion(event));

    Ok(log)
}

pub fn escape_string<'a>(val : &'a str) -> &'a str {
    if val.starts_with('"') && val.ends_with('"') {
        &val[1..val.len() - 1]
    }else{
        println!("{:?}, {}, {}", val, val.starts_with('"'),val.ends_with('"'));
        val
    }
}

pub fn parse_network_transport(protocol: &str) -> NetworkProtocol {
    match protocol {
        "tcp" => NetworkProtocol::TCP,
        "udp" => NetworkProtocol::UDP,
        _ => NetworkProtocol::OTHER(Cow::Owned(protocol.to_uppercase())),
    }
}

pub fn extract_rule_info<'a>(val: &'a str) -> Result<(&'a str, &'a str), &'static str> {
    if !val.ends_with(")") {
        return Err("Wrong format");
    }
    match val.find("(") {
        Some(pos) => Ok((&val[..pos], &val[pos + 1..val.len() - 1])),
        None => Err("Wrong format"),
    }
}
