// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::fs;
use std::io::Write;

pub fn leaf(manifest: &[u8], ed: &[u8], pq: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"NONOSREL:leaf");
    h.update(manifest);
    h.update(ed);
    h.update(pq);
    *h.finalize().as_bytes()
}

pub fn append_entry(path: &str, manifest: &[u8], ed: &[u8], pq: &[u8]) -> std::io::Result<()> {
    let line = format!("{} {} {}\n", hex::encode(manifest), hex::encode(ed), hex::encode(pq));
    let mut f = fs::OpenOptions::new().append(true).create(true).open(path)?;
    f.write_all(line.as_bytes())
}

pub fn find_entry(path: &str, manifest_hex: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    for line in fs::read_to_string(path).ok()?.lines() {
        let mut p = line.split_whitespace();
        if let (Some(m), Some(e), Some(q)) = (p.next(), p.next(), p.next()) {
            if m == manifest_hex {
                return Some((hex::decode(e).ok()?, hex::decode(q).ok()?));
            }
        }
    }
    None
}

pub fn merkle_root(path: &str) -> [u8; 32] {
    let content = fs::read_to_string(path).unwrap_or_default();
    let mut level: Vec<[u8; 32]> = content
        .lines()
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            match (p.next(), p.next(), p.next()) {
                (Some(m), Some(e), Some(q)) => {
                    Some(leaf(&hex::decode(m).ok()?, &hex::decode(e).ok()?, &hex::decode(q).ok()?))
                }
                _ => None,
            }
        })
        .collect();
    if level.is_empty() {
        return [0u8; 32];
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
                let mut h = blake3::Hasher::new();
                h.update(b"NONOSREL:node");
                h.update(&pair[0]);
                h.update(right);
                *h.finalize().as_bytes()
            })
            .collect();
    }
    level[0]
}
