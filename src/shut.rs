use std::{ops, fmt};
#[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct Shutflag(usize);

const READ: usize = 0b00001;
const WRITE: usize = 0b00010;
const BOTH: usize = 0b00011;

impl Shutflag {
    pub fn empty() -> Shutflag {
        Shutflag(0)
    }

    pub fn read() -> Shutflag {
        Shutflag(READ)
    }

    pub fn write() -> Shutflag {
        Shutflag(WRITE)
    }

    pub fn both() -> Shutflag {
        Shutflag(BOTH)
    }

    pub fn bits(&self) -> usize {
        self.0
    }

    pub fn contains<T: Into<Self>>(&self, other: T) -> bool {
        let other = other.into();
        (*self & other) == other
    }
}

impl<T: Into<Shutflag>> ops::BitOr<T> for Shutflag {
    type Output = Shutflag;

    #[inline]
    fn bitor(self, other: T) -> Shutflag {
        Shutflag(self.0 | other.into().0)
    }
}

impl<T: Into<Shutflag>> ops::BitOrAssign<T> for Shutflag {
    #[inline]
    fn bitor_assign(&mut self, other: T) {
        self.0 |= other.into().0;
    }
}

impl<T: Into<Shutflag>> ops::BitXor<T> for Shutflag {
    type Output = Shutflag;

    #[inline]
    fn bitxor(self, other: T) -> Shutflag {
        Shutflag(self.0 ^ other.into().0)
    }
}

impl<T: Into<Shutflag>> ops::BitXorAssign<T> for Shutflag {
    #[inline]
    fn bitxor_assign(&mut self, other: T) {
        self.0 ^= other.into().0;
    }
}

impl<T: Into<Shutflag>> ops::BitAnd<T> for Shutflag {
    type Output = Shutflag;

    #[inline]
    fn bitand(self, other: T) -> Shutflag {
        Shutflag(self.0 & other.into().0)
    }
}

impl<T: Into<Shutflag>> ops::BitAndAssign<T> for Shutflag {
    #[inline]
    fn bitand_assign(&mut self, other: T) {
        self.0 &= other.into().0
    }
}

impl<T: Into<Shutflag>> ops::Sub<T> for Shutflag {
    type Output = Shutflag;

    #[inline]
    fn sub(self, other: T) -> Shutflag {
        Shutflag(self.0 & !other.into().0)
    }
}

impl<T: Into<Shutflag>> ops::SubAssign<T> for Shutflag {
    #[inline]
    fn sub_assign(&mut self, other: T) {
        self.0 &= !other.into().0;
    }
}

impl fmt::Debug for Shutflag {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut one = false;
        let flags = [
            (Shutflag::empty(), "Live"),
            (Shutflag::read(), "Read"),
            (Shutflag::write(), "Write"),
            (Shutflag::both(), "Both")];

        for &(flag, msg) in &flags {
            if self.contains(flag) {
                if one { write!(fmt, " | ")? }
                write!(fmt, "{}", msg)?;

                one = true
            }
        }

        if !one {
            fmt.write_str("(empty)")?;
        }

        Ok(())
    }
}
