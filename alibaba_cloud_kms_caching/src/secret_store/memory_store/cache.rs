use linked_hash_map::LinkedHashMap;
use std::{borrow::Borrow, hash::Hash, num::NonZeroUsize};

#[derive(Debug, Clone)]
/// Keeps track of the most recently used items and evicts old entries when max_size is reached
pub struct Cache<K: Hash + Eq, V> {
    entries: LinkedHashMap<K, V>,
    max_size: NonZeroUsize,
}

/// Create a cache with a default size of 1000
impl<K: Hash + Eq, V> Default for Cache<K, V> {
    fn default() -> Self {
        Self::new(NonZeroUsize::new(1000).unwrap())
    }
}

impl<K: Hash + Eq, V> Cache<K, V> {
    /// Returns a new least recently updated cache with default configuration.
    pub fn new(max_size: NonZeroUsize) -> Self {
        Cache {
            entries: LinkedHashMap::new(),
            max_size,
        }
    }

    /// Returns the number of items currently in the cache.
    pub fn len(&mut self) -> usize {
        self.entries.len()
    }

    /// Inserts a key into the cache.
    ///  If the key already exists, it overwrites it
    ///  If the insert results in too many keys in the cache, the oldest updated entry is removed.
    pub fn insert(&mut self, key: K, val: V) {
        self.entries.insert(key, val);
        if self.len() > self.max_size.get() {
            self.entries.pop_front();
        }
    }

    /// Retrieves the key from the cache.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        // This Q is used to allow for syntactic sugar with types like String, allowing &str as a key for example
        Q: ?Sized + Hash + Eq,
        K: Borrow<Q>,
    {
        self.entries.get(key)
    }
}
