use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
};

#[derive(Clone)]
pub struct SynchronizedQueue<T>
where
    T: Clone,
{
    queue: Arc<Mutex<VecDeque<T>>>,
    queue_cv: Arc<Condvar>,
    stopped: Arc<AtomicBool>,
}

impl<T> SynchronizedQueue<T>
where
    T: Clone,
{
    /**
     * Creates an empty SynchronizedQueue.
     */
    pub fn new() -> SynchronizedQueue<T> {
        SynchronizedQueue {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            queue_cv: Arc::new(Condvar::new()),
            stopped: Arc::new(AtomicBool::new(false)),
        }
    }

    /**
     * Pushes an element onto the queue. If previously empty, notifies cv.
     */
    pub fn push(&mut self, elt: T) {
        let mut queue = self.queue.lock().unwrap();
        queue.push_back(elt);
        if queue.len() == 1 {
            self.queue_cv.notify_one();
        }
    }

    /**
     * Pops an element from the queue. If empty, waits on CV until filled. If stopped, returns
     * error.
     */
    pub fn pop(&mut self) -> Option<T> {
        let mut queue = self.queue.lock().unwrap();
        while queue.is_empty() && !self.stopped.load(Ordering::Relaxed) {
            queue = self.queue_cv.wait(queue).unwrap();
        }
        if self.stopped.load(Ordering::Relaxed) {
            None
        } else {
            queue.pop_front()
        }
    }

    /**
     * Checks if queue is empty.
     */
    pub fn is_empty(&mut self) -> bool {
        self.queue.lock().unwrap().is_empty()
    }

    /**
     * Stops queue, and wakes all waiting threads.
     */
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        self.queue_cv.notify_all();
    }
}
