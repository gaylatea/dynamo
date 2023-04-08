/**
dynamo is a small program that will emit logs at a specified pace, intended
as an instructional tool for people using Vector.

It is distinct from a normal fuzzing tool in its specificity; particular
educational outcomes are desired from it so it is not worthwhile to have a
tool like Lading or similar that would produce random outputs.

Those educational goals are:
 - Demonstrate the power of Vector on the student's machine to process a
   high volume of incoming logs;
 - Demonstrate the value of Vector by generating "data leaks" or other
   anomalous conditions that the student can react to; and
 - Demonstrate Vector's flexibility by having multiple types of log formats
   that the student can react to and write parsers for.

To this end, Dynamo supports the following outputs, which are intended to
be directed at a listening Vector instance with the `datadog_agent` source
configured:

 - HTTP logs coming from a sample e-commerce store, including a data leak
   of customer credit card information; and
 - VPC flow logs, including evidence of an SSH brute-force attack.
*/
use std::time;
use std::time::Duration;

use async_stream::stream;
use chrono::prelude::*;
use clap::Parser;
use fakeit::company;
use fakeit::internet;
use fakeit::payment;
use gethostname::gethostname;
use json_patch::merge;
use leaky_bucket::RateLimiter;
use rand::Rng;
use serde_json::{self, json};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Vector `datadog_agent` source address to send to.
    #[arg(long, default_value = "http://localhost:8282")]
    datadog_agent_target: String,

    /// Total rate limit for normal HTTP logs.
    #[arg(long, default_value_t = 100)]
    http_log_rate_limit_per_s: usize,

    /// Rate limit for HTTP error logs.
    #[arg(long, default_value_t = 10)]
    http_log_error_rate_limit_per_s: usize,

    /// Rate limit for HTTP logs that will leak credit card info.
    #[arg(long, default_value_t = 1)]
    http_log_leak_rate_limit_per_s: usize,

    /// Rate limit for regular VPC flow logs. Disabled by default.
    #[arg(long, default_value_t = 0)]
    vpc_log_rate_limit_per_s: usize,

    /// Rate limit for SSH brute force attack VPC logs. Disabled by default.
    #[arg(long, default_value_t = 0)]
    vpc_log_attack_rate_limit_per_s: usize,

    /// Batch size for sending to Vector.
    #[arg(long, default_value_t = 5)]
    sender_batch_size: usize,

    /// Batch timeout in seconds for sending to Vector.
    #[arg(long, default_value_t = 5)]
    sender_batch_timeout_s: u64,
}

fn send_log(
    tx: &tokio::sync::mpsc::Sender<serde_json::Value>,
    rate_limit_per_s: usize,
    generator: fn() -> serde_json::Value,
) {
    // The rate limiters don't support 0-values, so we just don't create the
    // logger if a zero is specified.
    if rate_limit_per_s == 0 {
        return;
    }

    let rate_limiter = RateLimiter::builder()
        .max(rate_limit_per_s * 100)
        .initial(0)
        .refill(rate_limit_per_s * 1.01 as usize)
        .interval(time::Duration::from_millis(1000))
        .build();
    let tx2 = tx.clone();

    // These simple attributes are needed for the Datadog API as
    // implemented by Vector, so we add them to every message.
    let hostname = gethostname().into_string().expect("could not get hostname");
    let needed = json!({
        "ddsource": "dynamo",
        "hostname": hostname,
        "status": "INFO",
        "ddtags": "kube_namespace:test",
    });

    tokio::spawn(async move {
        loop {
            rate_limiter.acquire_one().await;

            let mut v = generator();
            if !v.is_array() {
                v = json!([v]);
            }

            let vs = v
                .as_array_mut()
                .expect("JSON returned from generator should be an array");
            for mut val in vs {
                merge(&mut val, &needed);

                val["timestamp"] = json!(Utc::now().timestamp_micros() / 1000);
                match tx2.send(val.to_owned()).await {
                    Ok(_) => {}
                    Err(_) => {
                        break;
                    }
                }
            }
        }
    });
}

fn generate_apache_log_line(method: &str, status: usize) -> String {
    let addr = internet::ipv4_address();
    let username = internet::username();

    let ts = Utc::now().format("%d/%b/%G:%H:%M:%S %z");

    // TODO: handle time generation
    return format!(
        "{} - {} [{}] \"{} /{} {}\" {} {}",
        addr,
        username,
        ts,
        method,
        company::buzzword(),
        "HTTP/1.1",
        status,
        1024
    );
}

fn generate_vpc_flow_line(action: &str, status: &str, port: usize) -> String {
    let mut rng = rand::thread_rng();

    let start = Utc::now()
        .checked_sub_signed(chrono::Duration::seconds(rng.gen_range(5..30)))
        .expect("could not create start time for log");
    let end = Utc::now();

    let client_ip = internet::ipv4_address();
    let server_ip = internet::ipv4_address();
    let client_port = rng.gen_range(30000..78000);
    let request_bytes = rng.gen_range(230..9000);
    let request_packets = rng.gen_range(5..1000);

    return format!(
        "{} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        2,
        "1234567890",
        "eni-sdvu4NphZxGvp1MDz",
        client_ip,
        server_ip,
        client_port,
        port,
        6,
        request_packets,
        request_bytes,
        start.timestamp(),
        end.timestamp(),
        action,
        status,
    );
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let logs_client_address = format!("{}/api/v2/logs", args.datadog_agent_target);
    let logs_client = reqwest::Client::builder()
        .gzip(true)
        .build()
        .expect("could not initialize client");
    let (tx, mut rx) = mpsc::channel(32);

    send_log(&tx, args.http_log_rate_limit_per_s, || {
        return json!({
            "message": generate_apache_log_line("GET", 200),
            "service": "storedog",
        });
    });

    send_log(&tx, args.http_log_error_rate_limit_per_s, || {
        return json!({
            "message": generate_apache_log_line("GET", 500),
            "service": "storedog",
        });
    });

    send_log(&tx, args.http_log_leak_rate_limit_per_s, || {
        return json!([
            {
                "message": generate_apache_log_line("POST", 504),
                "service": "storedog",
            },
            {
                "message": format!("ERROR could not charge card {}!", payment::credit_card_number()),
                "service": "storedog",
            },
        ]);
    });

    send_log(&tx, args.vpc_log_rate_limit_per_s, || {
        return json!([{
            "message": generate_vpc_flow_line("ACCEPT", "OK", 443),
            "service": "aws.vpc_flow_logs",
        }]);
    });

    send_log(&tx, args.vpc_log_attack_rate_limit_per_s, || {
        return json!({
            "message": generate_vpc_flow_line("REJECT", "OK", 22),
            "service": "aws.vpc_flow_logs",
        });
    });

    let stream = stream! {
        while let Some(message) = rx.recv().await {
            yield message;
        }
    };

    let mut pinned = Box::pin(stream.chunks_timeout(
        args.sender_batch_size,
        Duration::from_secs(args.sender_batch_timeout_s),
    ));
    while let Some(message) = pinned.next().await {
        let m = json!(message);
        match logs_client
            .post(&logs_client_address)
            .body(m.to_string())
            .send()
            .await
        {
            Ok(_) => {}
            Err(e) => {
                println!("Could not connect to Vector: {}", e);
            }
        };
    }
}
