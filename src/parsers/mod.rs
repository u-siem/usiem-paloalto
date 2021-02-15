use chrono::prelude::{TimeZone, Utc};
use std::borrow::Cow;
use usiem::components::common::LogParsingError;
use usiem::events::field::SiemField;
use usiem::events::SiemLog;
mod firewall;
mod threat;

pub fn parse_log(log: SiemLog) -> Result<SiemLog, LogParsingError> {
    let log_line = log.message();
    let start_log_pos = match log_line.find(",") {
        Some(val) => val,
        None => return Err(LogParsingError::NoValidParser(log)),
    };
    //let syslog_header = &log_line[0..start_log_pos];
    let log_content = &log_line[start_log_pos + 1..];

    let csv_content = extract_fields(log_content);
    let module = match csv_content.get(2) {
        Some(md) => md,
        None => return Err(LogParsingError::NoValidParser(log)),
    };
    let event_created = match csv_content.get(0) {
        Some(val) => {
            //FORMAT: 2021/02/05 15:05:55
            match Utc.datetime_from_str(val, "%Y/%m/%d %H:%M:%S") {
                Ok(timestamp) => timestamp.timestamp_millis(),
                Err(_err) => return Err(LogParsingError::NoValidParser(log)),
            }
        }
        None => return Err(LogParsingError::NoValidParser(log)),
    };

    let mut log = SiemLog::new(
        log_content.to_owned(),
        log.event_received(),
        log.origin().clone(),
    );
    match csv_content.get(1) {
        Some(md) => {
            log.add_field("observer.id", SiemField::Text(Cow::Owned(md.to_string())));
        }
        None => return Err(LogParsingError::NoValidParser(log)),
    };
    log.set_event_created(event_created);
    log.set_vendor(Cow::Borrowed("PaloAlto"));
    log.set_product(Cow::Borrowed("PaloAlto"));
    log.set_category(Cow::Borrowed("Firewall"));
    match &module[..] {
        "TRAFFIC" => {
            log.set_service(Cow::Borrowed("TRAFFIC"));
            return firewall::paloalto_firewall(csv_content, log);
        }
        "THREAT" => {
            log.set_service(Cow::Borrowed("THREAT"));
            return threat::paloalto_threat(csv_content, log);
        }
        _ => Ok(log),
    }
}

pub fn extract_fields<'a>(message: &'a str) -> Vec<&'a str> {
    let mut field_map = Vec::with_capacity(80);
    let mut start_field = 0;
    let mut is_string = false;
    let mut last_char = ',';
    for (i, c) in message.char_indices() {
        if is_string {
            if c == '"' && last_char != '"' {
                is_string = false;
            }
        } else {
            if c == ',' {
                field_map.push(&message[start_field..i]);
                start_field = i + 1;
            } else if c == '"' && last_char == ',' {
                is_string = true;
                start_field = i;
            }
        }
        last_char = c;
    }
    field_map
}

#[cfg(test)]
mod filterlog_tests {
    use super::{extract_fields, parse_log};
    use usiem::events::field::{SiemField, SiemIp};
    use usiem::events::SiemLog;
    use usiem::events::field_dictionary;

    #[test]
    fn test_extract_fields() {
        let log = "2021/02/05 15:05:55,0123456789,TRAFFIC,drop,2305,2021/02/05 15:05:55,192.168.2.1,192.168.3.2,0.0.0.0,0.0.0.0,intrazone-default,,,not-applicable,vsys1,untrust,untrust,ethernet1,,Log Collector,2021/02/05 15:05:55,0,1,35861,514,0,0,0x0,udp,deny,102,102,0,1,2021/02/08 16:06:59,0,any,0,3996658540,0x0,192.168.0.0-192.168.255.255,192.168.0.0-192.168.255.255,0,1,0,policy-deny,0,0,0,0,,pa-test,from-policy,,,0,,0,,N/A,0,0,0,0,aa1d1908-68cd-467a-bc90-68a57096ef3b,0,0,,,,,,,";
        let map = extract_fields(log);
        assert_eq!(map.get(0), Some(&"2021/02/05 15:05:55"));
        assert_eq!(map.get(1), Some(&"0123456789"));
        assert_eq!(map.get(2), Some(&"TRAFFIC"));
        assert_eq!(map.get(64), Some(&"aa1d1908-68cd-467a-bc90-68a57096ef3b"));
    }

    #[test]
    fn test_parse_firewall() {
        let log = "Feb  5 15:05:55 pa-test 1,2021/02/05 15:05:55,0123456789,TRAFFIC,drop,2305,2021/02/05 15:05:55,192.168.2.1,192.168.3.2,0.0.0.0,0.0.0.0,intrazone-default,,,not-applicable,vsys1,untrust,untrust,ethernet1,,Log Collector,2021/02/05 15:05:55,0,1,35861,514,0,0,0x0,udp,deny,102,102,0,1,2021/02/08 16:06:59,0,any,0,3996658540,0x0,192.168.0.0-192.168.255.255,192.168.0.0-192.168.255.255,0,1,0,policy-deny,0,0,0,0,,pa-test,from-policy,,,0,,0,,N/A,0,0,0,0,aa1d1908-68cd-467a-bc90-68a57096ef3b,0,0,,,,,,,";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let siem_log = parse_log(log);
        match siem_log {
            Ok(log) => {
                assert_eq!(log.service(), "TRAFFIC");

                assert_eq!(
                    log.field("observer.id"),
                    Some(&SiemField::from_str("0123456789"))
                );
                assert_eq!(
                    log.field("source.ip"),
                    Some(&SiemField::IP(SiemIp::from_ip_str("192.168.2.1").unwrap()))
                );
                assert_eq!(
                    log.field("destination.ip"),
                    Some(&SiemField::IP(SiemIp::from_ip_str("192.168.3.2").unwrap()))
                );
            }
            Err(_) => assert_eq!(1, 0),
        }
    }

    #[test]
    fn test_parse_threat_vuln() {
        let log = "Feb  8 09:05:49 pa-fw1 1,2021/02/08 09:05:48,0123456789,THREAT,vulnerability,1,2021/02/08 09:05:48,100.10.20.34,200.10.20.65,100.10.20.34,200.10.20.65,ssl vpn access,,,web-browsing,vsys1,untrust,untrust,ethernet1/1,ethernet1/1,InnoTec Log Collector,2021/02/08 09:05:48,104063,1,36026,443,36026,20077,0x1502000,tcp,reset-both,\"diag_Form\",GPON Home Routers Remote Code Execution Vulnerability(37264),any,critical,client-to-server,1607660,0x8000000000000000,Spain,Spain,0,,0,,,1,,,,,,,,0,0,0,0,0,,pa-fw1,,,,,0,,0,,N/A,code-execution,AppThreat-8371-6531,0x2";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let siem_log = parse_log(log);
        match siem_log {
            Ok(log) => {
                assert_eq!(log.service(), "THREAT");

                assert_eq!(
                    log.field("observer.id"),
                    Some(&SiemField::from_str("0123456789"))
                );
                assert_eq!(
                    log.field("source.ip"),
                    Some(&SiemField::IP(SiemIp::from_ip_str("100.10.20.34").unwrap()))
                );
                assert_eq!(
                    log.field("destination.ip"),
                    Some(&SiemField::IP(SiemIp::from_ip_str("200.10.20.65").unwrap()))
                );
                assert_eq!(
                    log.field("rule.id"),
                    Some(&SiemField::U32(37264))
                );
                assert_eq!(
                    log.field("source.port"),
                    Some(&SiemField::U32(36026))
                );
                assert_eq!(
                    log.field("destination.port"),
                    Some(&SiemField::U32(443))
                );
                assert_eq!(
                    log.field("rule.name"),
                    Some(&SiemField::from_str("GPON Home Routers Remote Code Execution Vulnerability"))
                );
                assert_eq!(
                    log.field("network.direction"),
                    Some(&SiemField::from_str("client-to-server"))
                );
                assert_eq!(
                    log.field("event.outcome"),
                    Some(&SiemField::from_str("BLOCKED"))
                );
                assert_eq!(
                    log.field("trace.id"),
                    Some(&SiemField::from_str("104063"))
                );
                assert_eq!(
                    log.field(field_dictionary::IN_INTERFACE),
                    Some(&SiemField::from_str("ethernet1/1"))
                );
                assert_eq!(
                    log.field(field_dictionary::OUT_INTERFACE),
                    Some(&SiemField::from_str("ethernet1/1"))
                );
            }
            Err(_) => assert_eq!(1, 0),
        }
    }
    #[test]
    fn test_parse_threat_url() {
        //TODO: This in a webproxy event
        let log = "Aug 5 14:56:46 Ilija-PA-VM-2.al.com 1,2014/08/05 14:56:46,0123456789,THREAT,url,1,2014/08/05 14:56:40,192.168.8.89,173.194.41.175,10.193.17.8,173.194.41.175,allow_all,,,ssl,vsys1,Trust-L3,Untrust-L3,ethernet1/2,ethernet1/1,forward to panorama and splunk,2014/08/05 14:56:46,196863,1,55143,443,52716,443,0x408000,tcp,alert,\"www.google.nl/\",(9999),search-engines,informational,client-to-server,67483,0x0,192.168.0.0-192.168.255.255,US,0,,0,,";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let siem_log = parse_log(log);
        match siem_log {
            Ok(log) => {
                assert_eq!(log.service(), "THREAT");

                assert_eq!(
                    log.field("observer.id"),
                    Some(&SiemField::from_str("0123456789"))
                );
                assert_eq!(
                    log.field("source.ip"),
                    Some(&SiemField::IP(SiemIp::from_ip_str("192.168.8.89").unwrap()))
                );
                assert_eq!(
                    log.field("destination.ip"),
                    Some(&SiemField::IP(SiemIp::from_ip_str("173.194.41.175").unwrap()))
                );
                assert_eq!(
                    log.field("rule.id"),
                    Some(&SiemField::U32(9999))
                );
                assert_eq!(
                    log.field("source.port"),
                    Some(&SiemField::U32(55143))
                );
                assert_eq!(
                    log.field("destination.port"),
                    Some(&SiemField::U32(443))
                );
                assert_eq!(
                    log.field("rule.name"),
                    Some(&SiemField::from_str(""))
                );
                assert_eq!(
                    log.field("network.direction"),
                    Some(&SiemField::from_str("client-to-server"))
                );
                assert_eq!(
                    log.field("event.outcome"),
                    Some(&SiemField::from_str("DETECTED"))
                );
                assert_eq!(
                    log.field("trace.id"),
                    Some(&SiemField::from_str("196863"))
                );
                assert_eq!(
                    log.field(field_dictionary::URL_FULL),
                    Some(&SiemField::from_str("www.google.nl/"))
                );
                assert_eq!(
                    log.field(field_dictionary::IN_INTERFACE),
                    Some(&SiemField::from_str("ethernet1/2"))
                );
                assert_eq!(
                    log.field(field_dictionary::OUT_INTERFACE),
                    Some(&SiemField::from_str("ethernet1/1"))
                );
            }
            Err(_) => assert_eq!(1, 0),
        }
    }
}
