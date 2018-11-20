use ::Result;

use std::sync::Arc;
use api::Callback;
use std::sync::{Mutex, Condvar};

pub fn wait_until_done<F, T: Clone + Send + 'static>(operation: F) -> Result<T> where F: for<'a> Fn(Callback<T>) {
    let pair = Arc::new((Mutex::new(None), Condvar::new()));
    let pair2 = pair.clone();
    let on_finish = Box::new(move|result: Result<T>| {
        let &(ref lock, ref cvar) = &*pair2;
        let mut done = lock.lock().unwrap();
        *done = Some(result.clone());
        cvar.notify_one();
    });

    operation(on_finish);

    // wait until we're done
    let &(ref lock, ref cvar) = &*pair;

    let mut done = lock.lock().unwrap();
    while (*done).is_none() {
        done = cvar.wait(done).unwrap();
    }

    // TODO: this copy is avoidable
    (*done).clone().unwrap()
}
