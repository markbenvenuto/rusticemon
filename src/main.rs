// Copyright 2021 Mark Benvenuto
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{Context, Result};
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use num_derive::FromPrimitive;
use num_derive::ToPrimitive;
use std::cmp::min;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use strum_macros::AsRefStr;
use strum_macros::EnumString;

extern crate num;
//#[macro_use]
extern crate num_derive;
extern crate num_traits;

extern crate byteorder;
use byteorder::ReadBytesExt;
use byteorder::{BigEndian, ByteOrder, NetworkEndian};
use pretty_hex::*;

const PROTOCOL_VERSION: u32 = 43;

fn main() -> Result<()> {
    println!("Connecting ...");

    let mut stream = TcpStream::connect("localhost:8765")?;

    println!("Sending protocol...");

    // Send the protocol version
    write_protocol(&mut stream, PROTOCOL_VERSION)?;

    // Read the protocol version from the scheduler
    let protocol_remote = read_protocol(&mut stream)?;

    println!("Got protocol: {:?}", protocol_remote);

    let protocol = min(protocol_remote, PROTOCOL_VERSION);

    write_protocol(&mut stream, protocol)?;

    println!("Negotiated protocol: {:?}", protocol);

    // Read the negotiated protocol version from the scheduler
    let protocol_remote2 = read_protocol(&mut stream)?;

    println!("Got protocol2: {:?}", protocol_remote2);

    let login_msg = MonLoginMsg {};

    write_msg(&login_msg, &mut stream)?;

    loop {
        let msg_vec = read_msg(&mut stream)?;

        let msg = parse_msg(&msg_vec, protocol)?;

        match msg {
            CommMsg::MonGetCS(m) => {
                println!("{:?}", m);
            }
            CommMsg::MonJobBegin(m) => {
                println!("{:?}", m);
            }
            CommMsg::MonJobDone(m) => {
                println!("{:?}", m);
            }
            CommMsg::End(m) => {
                println!("{:?}", m);
            }
            CommMsg::MonStats(m) => {
                println!("{:?}", m);
            }
            CommMsg::MonJobLocalBegin(m) => {
                println!("{:?}", m);
            }
            CommMsg::JobLocalDone(m) => {
                println!("{:?}", m);
            }
            CommMsg::MonLoginMsg(m) => {
                println!("{:?}", m);
            }
        }
    }

    Ok(())
}

fn is_protocol_39(p: u32) -> bool {
    p >= 39
}

//
// Protocol is little endian
// Other numbers are bit endian/network order
fn read_protocol(reader: &mut dyn Read) -> Result<u32> {
    let mut msg: Vec<u8> = Vec::new();
    msg.resize(4, 0);

    reader.read_exact(msg.as_mut())?;

    // Check length
    let mut cur = Cursor::new(msg);

    let r = cur.read_u32::<LittleEndian>()?;
    Ok(r)
}

fn write_protocol(writer: &mut dyn Write, value: u32) -> Result<()> {
    writer.write_u32::<LittleEndian>(value)?;
    Ok(())
}

pub fn write_u32(writer: &mut dyn Write, value: u32) -> Result<()> {
    writer.write_u32::<NetworkEndian>(value)?;
    Ok(())
}

fn read_u32(reader: &mut dyn Read) -> Result<u32> {
    let v = reader.read_u32::<NetworkEndian>()?;
    Ok(v)
}

pub fn write_string(writer: &mut dyn Write, value: &str) -> Result<()> {
    write_u32(writer, (value.len() as u32) + 1)?;

    // println!("write_string");

    writer.write(value.as_bytes())?;

    writer.write_u8(0)?;

    Ok(())
}

fn read_string(reader: &mut dyn Read) -> Result<String> {
    let len = read_u32(reader)?;

    // ignore trailling null
    let mut v: Vec<u8> = Vec::new();
    v.resize((len as usize) - 1, 0);

    reader.read(v.as_mut_slice())?;

    let s = String::from_utf8(v)?;

    //println!("Read string: {:?}", s);

    Ok(s)
}

// pub fn write_string_vec(writer: &mut dyn Write, value: Vec<&str>) -> Result<()> {
//     write_u32(writer, (value.len() as u32) )?;

//     // println!("write_string_vec");

//     // for each write string
//     //TODO
//     Ok(())
// }

// fn read_string_vec(reader: &mut dyn Read) -> Result<Vec<String>> {
//     // println!("read_string_vec");
//     let len = read_u32(reader)?;

//     let strings = Vec::new();

//     // TODO
//     // for( let i : )
//     // {

//     // }

//     Ok(strings)
// }

//
// Messages as follow
// -------------------
// Numbers are network byte order
// -------------------
// length - 4 bytes
// message type - 4 bytes
// message payload - varies
pub fn read_msg_and_ret_length(reader: &mut dyn Read) -> Result<Vec<u8>> {
    let mut msg: Vec<u8> = Vec::new();
    msg.resize(4, 0);

    reader.read_exact(msg.as_mut())?;

    // Check length
    let len: usize;
    {
        let mut cur = Cursor::new(msg);

        len = read_u32(&mut cur)? as usize;

        msg = cur.into_inner();
    }

    msg.resize(msg.len() + len, 0);

    let slice: &mut [u8] = msg.as_mut();
    reader.read_exact(&mut slice[4..])?;

    Ok(msg)
}

// Return a message buffer without the length prefix
pub fn read_msg(reader: &mut dyn Read) -> Result<Vec<u8>> {
    let mut msg: Vec<u8> = Vec::new();
    msg.resize(4, 0);

    reader.read_exact(msg.as_mut())?;

    // Check length
    let len: usize;
    {
        let mut cur = Cursor::new(msg);

        len = read_u32(&mut cur)? as usize;

        msg = cur.into_inner();
    }

    eprintln!("Reading message of len: {:?}", len);

    msg.resize(len, 0);

    reader.read_exact(msg.as_mut())?;

    Ok(msg)
}

#[derive(FromPrimitive, ToPrimitive, EnumString, AsRefStr, Debug, Copy, Clone, PartialEq)]
enum MsgType {
    MonGetCS = 0x53,
    MonJobBegin = 0x54,
    MonJobDone = 0x55,
    End = 0x43,
    MonStats = 0x57,
    MonJobLocalBegin = 0x56,
    JobLocalDone = 0x4F,

    MonLogin = 0x52,
}

#[derive(Debug)]

struct MonStatsMsg {
    host_id: u32,
    statmsg: String,
}

impl MonStatsMsg {
    fn parse(reader: &mut dyn Read) -> Result<MonStatsMsg> {
        let host_id = read_u32(reader)?;
        let msg = read_string(reader)?;

        Ok(MonStatsMsg {
            host_id: host_id,
            statmsg: msg,
        })
    }
}

#[derive(Debug)]

struct MonGetCSMsg {
    filename: String,
    lang: u32,
}

impl MonGetCSMsg {
    fn parse(reader: &mut dyn Read) -> Result<MonGetCSMsg> {
        let filename = read_string(reader)?;
        let lang = read_u32(reader)?;

        Ok(MonGetCSMsg { filename, lang })
    }
}

#[derive(Debug)]
struct MonJobBeginMsg {
    job_id: u32,
    start_time: u32,
    host_id: u32,
}

impl MonJobBeginMsg {
    fn parse(reader: &mut dyn Read) -> Result<MonJobBeginMsg> {
        let job_id = read_u32(reader)?;
        let start_time = read_u32(reader)?;
        let host_id = read_u32(reader)?;

        Ok(MonJobBeginMsg {
            job_id,
            start_time,
            host_id,
        })
    }
}

#[derive(Debug)]

struct MonJobDoneMsg {
    jobid: u32,
    exit_code: u32,
    real_msec: u32,
    user_msec: u32,
    sys_msec: u32,
    page_faults: u32,
    in_compressed: u32,
    in_uncompressed: u32,
    out_compressed: u32,
    out_uncompressed: u32,
    flags: u32,
    client_count: u32,
}

impl MonJobDoneMsg {
    fn parse(reader: &mut dyn Read, protocol: u32) -> Result<MonJobDoneMsg> {
        let jobid = read_u32(reader)?;
        let exit_code = read_u32(reader)?;
        let real_msec = read_u32(reader)?;
        let user_msec = read_u32(reader)?;
        let sys_msec = read_u32(reader)?;
        let page_faults = read_u32(reader)?;
        let in_compressed = read_u32(reader)?;
        let in_uncompressed = read_u32(reader)?;
        let out_compressed = read_u32(reader)?;
        let out_uncompressed = read_u32(reader)?;
        let flags = read_u32(reader)?;

        let mut client_count: u32 = 0;
        if is_protocol_39(protocol) {
            client_count = read_u32(reader)?;
        }

        Ok(MonJobDoneMsg {
            jobid,
            exit_code,
            real_msec,
            user_msec,
            sys_msec,
            page_faults,
            in_compressed,
            in_uncompressed,
            out_compressed,
            out_uncompressed,
            flags,
            client_count,
        })
    }
}

// Empty Message
#[derive(Debug)]

struct EndMsg {}

#[derive(Debug)]

struct MonJobLocalBeginMsg {
    job_id: u32,
    start_time: u32,
    host_id: u32,
    file_name: String,
}

impl MonJobLocalBeginMsg {
    fn parse(reader: &mut dyn Read) -> Result<MonJobLocalBeginMsg> {
        let job_id = read_u32(reader)?;
        let start_time = read_u32(reader)?;
        let host_id = read_u32(reader)?;
        let file_name = read_string(reader)?;

        Ok(MonJobLocalBeginMsg {
            job_id,
            start_time,
            host_id,
            file_name,
        })
    }
}

#[derive(Debug)]

struct JobLocalDoneMsg {
    job_id: u32,
}

impl JobLocalDoneMsg {
    fn parse(reader: &mut dyn Read) -> Result<JobLocalDoneMsg> {
        let job_id = read_u32(reader)?;

        Ok(JobLocalDoneMsg { job_id })
    }
}

trait MessageWriter {
    fn get_type(&self) -> MsgType;

    fn write(&self, write: &mut dyn Write);
}

// Empty Message
#[derive(Debug)]
struct MonLoginMsg {}

impl MessageWriter for MonLoginMsg {
    fn get_type(&self) -> MsgType {
        MsgType::MonLogin
    }

    fn write(&self, write: &mut dyn Write) {
        // nothing to write
    }
}

#[derive(Debug)]
enum CommMsg {
    MonGetCS(MonGetCSMsg),
    MonJobBegin(MonJobBeginMsg),
    MonJobDone(MonJobDoneMsg),
    End(EndMsg),
    MonStats(MonStatsMsg),
    MonJobLocalBegin(MonJobLocalBeginMsg),
    JobLocalDone(JobLocalDoneMsg),

    MonLoginMsg(MonLoginMsg),
}

fn write_msg(msg: &dyn MessageWriter, writer: &mut dyn Write) -> Result<()> {
    let mut vec: Vec<u8> = Vec::new();

    let start_pos = 0;
    write_u32(&mut vec, 0)?;

    let mt = msg.get_type();
    let mt_u32 = num::ToPrimitive::to_u32(&mt).unwrap();

    write_u32(&mut vec, mt_u32)?;

    msg.write(&mut vec);

    let current_pos = vec.len();
    let len = current_pos - start_pos - 4;

    let mut v1: Vec<u8> = Vec::new();
    write_u32(&mut v1, len as u32)?;

    vec[start_pos..(4 + start_pos)].clone_from_slice(&v1[..4]);

    writer.write_all(&vec)?;

    Ok(())
}

fn parse_msg(msg: &[u8], protocol: u32) -> Result<CommMsg> {
    let mut cur = Cursor::new(msg);

    let msg_type = read_u32(&mut cur)?;

    let msg_type_enum: Option<MsgType> = num::FromPrimitive::from_u32(msg_type);

    match msg_type_enum {
        None => {
            eprintln!("Unknown message type: {:?}", msg_type);
            panic!();
        }
        Some(mt) => match mt {
            MsgType::MonStats => Ok(CommMsg::MonStats(MonStatsMsg::parse(&mut cur)?)),
            MsgType::MonGetCS => Ok(CommMsg::MonGetCS(MonGetCSMsg::parse(&mut cur)?)),
            MsgType::MonJobBegin => Ok(CommMsg::MonJobBegin(MonJobBeginMsg::parse(&mut cur)?)),
            MsgType::MonJobDone => Ok(CommMsg::MonJobDone(MonJobDoneMsg::parse(
                &mut cur, protocol,
            )?)),
            MsgType::End => Ok(CommMsg::End(EndMsg {})),
            MsgType::JobLocalDone => Ok(CommMsg::JobLocalDone(JobLocalDoneMsg::parse(&mut cur)?)),
            MsgType::MonJobLocalBegin => Ok(CommMsg::MonJobLocalBegin(MonJobLocalBeginMsg::parse(
                &mut cur,
            )?)),
            _ => {
                panic!();
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use pretty_hex::PrettyHex;

    use crate::{write_msg, write_protocol, write_u32, MonLoginMsg};

    #[test]
    fn test_protocol() {
        let mut vec: Vec<u8> = Vec::new();

        write_protocol(&mut vec, 43).unwrap();

        print!("Dump of bytes {:?}", vec.hex_dump());

        let good = vec![0x2b, 0x00, 0x00, 0x00];

        assert_eq!(vec.len(), 4);

        assert_eq!(vec, good);
    }

    #[test]
    fn test_login() {
        let mut vec: Vec<u8> = Vec::new();

        let login_msg = MonLoginMsg {};

        write_msg(&login_msg, &mut vec).unwrap();

        print!("Dump of bytes {:?}", vec.hex_dump());

        let good = vec![0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x52];

        assert_eq!(vec.len(), 8);

        assert_eq!(vec, good);
    }
}
