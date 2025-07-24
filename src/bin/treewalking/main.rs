#![allow(unused)]
use std::thread;
use std::time::Duration;
use std::{collections::HashSet, thread::JoinHandle};

use inmor::*;
use redis::{Client, Connection};

pub fn thread_code(redis: redis::Client) {
    let mut conn = redis.get_connection().unwrap();
    loop {
        println!("Waiting on thread!");
        let entity_id = queue_wait(&mut conn);
        if entity_id.len() > 0 {
            // We have one
            tree_walking(&entity_id, &mut conn);
        }
    }
}
pub fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let redis = redis::Client::open("redis://redis:6379").unwrap();

    let r = redis.clone();
    let h1 = thread::spawn(|| {
        // New thread
        thread_code(r);
    });

    let r = redis.clone();
    let h3 = thread::spawn(|| {
        // New thread
        thread_code(r);
    });

    let r = redis.clone();
    let h2 = thread::spawn(|| {
        // New thread
        thread_code(r);
    });
    let r = redis.clone();
    let h4 = thread::spawn(|| {
        // New thread
        thread_code(r);
    });
    let r = redis.clone();
    let h5 = thread::spawn(|| {
        // New thread
        thread_code(r);
    });
    let r = redis.clone();
    let h6 = thread::spawn(|| {
        // New thread
        thread_code(r);
    });
    let r = redis.clone();
    let h7 = thread::spawn(|| {
        // New thread
        thread_code(r);
    });

    h1.join().unwrap();
    h2.join().unwrap();
    h3.join().unwrap();
    h4.join().unwrap();
    h5.join().unwrap();
    h6.join().unwrap();
    h7.join().unwrap();

    //let result = tree_walking("https://edugain.oidf.lab.surf.nl", &mut conn, &visited_in);
    //println!("In total: {:?}", result.len());
}
