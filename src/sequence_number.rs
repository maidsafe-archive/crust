// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

// TODO Get rid of this file ??

use std::cmp::Ordering;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct SequenceNumber {
    num: u32,
}

impl SequenceNumber {
    #[allow(dead_code)]
    pub fn new(start: u32) -> SequenceNumber {
        SequenceNumber { num: start }
    }

    pub fn next(&mut self) -> u32 {
        let ret = self.number();
        self.increment();
        ret
    }

    #[allow(dead_code)]
    pub fn increment(&mut self) {
        if self.num != ::std::u32::MAX {
            self.num += 1
        } else {
            self.num = 0;
        }
    }

    #[allow(dead_code)]
    pub fn number(&self) -> u32 {
        self.num
    }
}

// This special ordering makes sure that the next sequence number is always seen as greater than
// the previous one
impl Ord for SequenceNumber {
    fn cmp(&self, other: &SequenceNumber) -> Ordering {
        const MIDDLE: u32 = ::std::u32::MAX / 2;

        if self.num == other.num {
            return Ordering::Equal;
        }

        if other.num > self.num {
            if (other.num - self.num) <= MIDDLE {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        } else {
            if (self.num - other.num) > MIDDLE {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
    }
}

impl PartialOrd for SequenceNumber {
    fn partial_cmp(&self, other: &SequenceNumber) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

#[cfg(test)]
mod test {
    use sequence_number::SequenceNumber;

    const MAX: u32 = ::std::u32::MAX;
    const MIDDLE: u32 = ::std::u32::MAX / 2;

    #[test]
    fn sequence_number() {
        let a = SequenceNumber::new(0);
        let b = SequenceNumber::new(0);

        assert!(a == b);

        let a = SequenceNumber::new(0);
        let b = SequenceNumber::new(1);

        assert!(a < b);
        assert!(b > a);

        let a = SequenceNumber::new(0);
        let b = SequenceNumber::new(MIDDLE);

        assert!(a < b);
        assert!(b > a);

        let a = SequenceNumber::new(0);
        let b = SequenceNumber::new(MIDDLE + 1);

        assert!(b < a);
        assert!(a > b);

        let a = SequenceNumber::new(MIDDLE + 1);
        let b = SequenceNumber::new(MAX);

        assert!(a < b);
        assert!(b > a);

        let a = SequenceNumber::new(MAX);
        let b = SequenceNumber::new(0);

        assert!(a < b);
        assert!(b > a);
    }
}
