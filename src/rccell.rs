use std::cell::RefCell;
use std::rc::Rc;

pub type RcCell<T> = Rc<RefCell<T>>;

pub fn new_rc_cell<T>(val: T) -> Rc<RefCell<T>> {
    Rc::new(RefCell::new(val))
}
