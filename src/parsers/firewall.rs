use chrono::prelude::{TimeZone, Utc};
use std::borrow::Cow;
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::firewall::{FirewallEvent, FirewallOutcome};
use usiem::events::protocol::NetworkProtocol;
use usiem::events::{SiemLog,SiemEvent};

pub fn paloalto_firewall<'a>(
    field_map: Vec<&'a str>,
    mut log: SiemLog,
) -> Result<SiemLog, SiemLog> {
    let event_outcome = match field_map.get(3) {
        Some(outcome) => match *outcome {
            "deny" => FirewallOutcome::BLOCK,
            "drop" => FirewallOutcome::BLOCK,
            "start" => FirewallOutcome::OPEN,
            "end" => FirewallOutcome::END,
            _ => FirewallOutcome::UNKNOWN,
        },
        None => return Err(log),
    };
    let source_ip = match field_map.get(6) {
        Some(srcip) => match SiemIp::from_ip_str(*srcip) {
            Ok(srcip) => srcip,
            Err(_) => return Err(log),
        },
        None => return Err(log),
    };
    let destination_ip = match field_map.get(7) {
        Some(destination_ip) => match SiemIp::from_ip_str(*destination_ip) {
            Ok(destination_ip) => destination_ip,
            Err(_) => return Err(log),
        },
        None => return Err(log),
    };
    match field_map.get(11) {
        Some(user) => match *user {
            "" => {}
            v => {
                log.add_field("source.user.name", SiemField::from_str(v.to_string()));
            }
        },
        None => return Err(log),
    };
    match field_map.get(12) {
        Some(user) => match *user {
            "" => {}
            v => {
                log.add_field("destination.user.name", SiemField::from_str(v.to_string()));
            }
        },
        None => return Err(log),
    };
    match field_map.get(13) {
        Some(app) => match *app {
            "" => {}
            "not-applicable" => {}
            v => {
                log.add_field("service.name", SiemField::from_str(v.to_string()));
            }
        },
        None => return Err(log),
    };

    let in_interface = match field_map.get(17) {
        Some(source_if) => Cow::Owned((*source_if).to_string()),
        None => return Err(log),
    };
    let out_interface = match field_map.get(18) {
        Some(destination_if) => Cow::Owned((*destination_if).to_string()),
        None => return Err(log),
    };

    let source_port = field_map.get(23).map(|c| (*c).parse::<u16>().unwrap_or(0)).unwrap_or(0);
    let destination_port = field_map.get(24).map(|c| (*c).parse::<u16>().unwrap_or(0)).unwrap_or(0);

    let network_transport = field_map.get(26).map(|c| parse_network_transport(c)).unwrap_or(NetworkProtocol::UNKNOWN);

    let event_outcome = match event_outcome {
        FirewallOutcome::UNKNOWN => {
            match field_map.get(27) {
                Some(outcome) => match *outcome {
                    "allow" => FirewallOutcome::ALLOW,
                    "deny" => FirewallOutcome::BLOCK,
                    "drop" => FirewallOutcome::END,
                    "drop ICMP" => FirewallOutcome::END,
                    "reset both" => FirewallOutcome::END,
                    "reset client" => FirewallOutcome::END,
                    "reset server" => FirewallOutcome::END,
                    _ => return Err(log),
                },
                None => return Err(log),
            }
        },
        eo => eo
    };

    let out_bytes = field_map.get(29).map(|c| (*c).parse::<u32>().unwrap_or(0)).unwrap_or(0);
    let in_bytes = field_map.get(30).map(|c| (*c).parse::<u32>().unwrap_or(0)).unwrap_or(0);

    match field_map.get(32) {
        Some(val) => {
            //FORMAT: 2021/02/05 15:05:55
            match Utc.datetime_from_str(val, "%Y/%m/%d %H:%M:%S") {
                Ok(timestamp) => {
                    log.add_field("event.start", SiemField::I64(timestamp.timestamp_millis()));
                },
                Err(_err) => {},
            }
        }
        None => {},
    };
    match field_map.get(33) {
        Some(val) => {
            match val.parse::<u32>() {
                Ok(v) => {log.add_field("event.duration", SiemField::U32(v));},
                Err(_) => {}
            }
        }
        None => {},
    };

    let event = FirewallEvent{
        source_ip,
        source_port,
        in_interface,
        destination_ip,
        destination_port,
        out_interface,
        network_protocol : network_transport,
        outcome : event_outcome,
        in_bytes,
        out_bytes,
    };
    log.set_event(SiemEvent::Firewall(event));

    Ok(log)
}

pub fn parse_network_transport(protocol : &str) -> NetworkProtocol {
    match protocol {
        "tcp" => NetworkProtocol::TCP,
        "udp" => NetworkProtocol::UDP,
        _ => NetworkProtocol::OTHER(Cow::Owned(protocol.to_uppercase())),
    }
}