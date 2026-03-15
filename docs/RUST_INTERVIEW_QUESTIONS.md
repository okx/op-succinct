# Rust 面试题目集

## 题目难度说明

本题目集包含三个难度级别：

1. **中等难度（12题）**：适合考察 Rust 基础知识和常见编程模式
   - **业务逻辑类（5题）**：
     - 线程安全计数器
     - LRU Cache
     - Result 错误处理
     - 自定义迭代器
     - 生命周期函数
   - **核心知识点类（7题，聚焦 Rust 核心特性）**：
     - Box + Deref + Drop（5.1）
     - Cell + 内部可变性（5.2）
     - RefCell + 运行时借用检查（5.3）
     - Arc + Mutex + 并发编程（5.4）
     - Drop trait + 资源清理（5.5）
     - PhantomData + 类型状态模式（5.6）
     - 宏定义（macro_rules!）+ 模式匹配（5.7）

2. **中等偏难（6题）**：适合考察对 Rust 核心特性的深入理解和实际应用能力
   - 线程池（Arc + Mutex + 并发）
   - tokio + async/await + Future（6.1）
   - Send + Sync trait + 线程安全（6.2）
   - 类型安全的 Builder 模式
   - 简单的引用计数智能指针
   - 简单的宏
   - 线程安全的栈

3. **高难度（2题，可选）**：适合考察高级 Rust 特性和系统编程能力
   - 无锁并发数据结构
   - 简单的异步 Future

**使用建议：**
- **初级候选人**：主要使用中等难度题目（3-4题）
- **中级候选人**：中等难度（2-3题）+ 中等偏难（2-3题）
- **高级候选人**：中等偏难（3-4题）+ 高难度（1-2题，可选）

---

## 编程题目（中等难度）

> 适合考察 Rust 基础知识和常见编程模式

### 题目 1: 实现一个线程安全的计数器

**要求：**
实现一个 `Counter` 结构体，支持多线程环境下的安全计数操作。

```rust
// 需要实现以下功能：
// 1. 创建计数器
// 2. 增加计数
// 3. 减少计数
// 4. 获取当前值
// 5. 重置计数器

pub struct Counter {
    // TODO: 实现字段
}

impl Counter {
    pub fn new() -> Self {
        // TODO
    }
    
    pub fn increment(&self) {
        // TODO
    }
    
    pub fn decrement(&self) {
        // TODO
    }
    
    pub fn get(&self) -> i32 {
        // TODO
    }
    
    pub fn reset(&self) {
        // TODO
    }
}

// 测试用例
#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
    #[test]
    fn test_concurrent_increment() {
        let counter = Counter::new();
        let mut handles = vec![];
        
        for _ in 0..10 {
            let counter = counter.clone(); // 假设实现了 Clone
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    counter.increment();
                }
            }));
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        assert_eq!(counter.get(), 1000);
    }
}
```

**考察点：**
- `Arc` 和 `Mutex` 的使用
- 线程安全编程
- 所有权和借用规则

**参考答案要点：**
```rust
use std::sync::{Arc, Mutex};

pub struct Counter {
    value: Arc<Mutex<i32>>,
}

impl Counter {
    pub fn new() -> Self {
        Self {
            value: Arc::new(Mutex::new(0)),
        }
    }
    
    pub fn increment(&self) {
        let mut value = self.value.lock().unwrap();
        *value += 1;
    }
    
    pub fn decrement(&self) {
        let mut value = self.value.lock().unwrap();
        *value -= 1;
    }
    
    pub fn get(&self) -> i32 {
        *self.value.lock().unwrap()
    }
    
    pub fn reset(&self) {
        let mut value = self.value.lock().unwrap();
        *value = 0;
    }
}

impl Clone for Counter {
    fn clone(&self) -> Self {
        Self {
            value: Arc::clone(&self.value),
        }
    }
}
```

---

### 题目 2: 实现一个简单的 LRU Cache

**要求：**
实现一个 LRU (Least Recently Used) 缓存，支持 `get` 和 `put` 操作，时间复杂度为 O(1)。

```rust
// 需要实现：
// 1. 创建指定容量的缓存
// 2. get(key) -> Option<&V>
// 3. put(key, value) -> Option<V> (返回被淘汰的值)

pub struct LRUCache<K, V> {
    // TODO: 实现字段
    capacity: usize,
}

impl<K, V> LRUCache<K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    pub fn new(capacity: usize) -> Self {
        // TODO
    }
    
    pub fn get(&mut self, key: &K) -> Option<&V> {
        // TODO
    }
    
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        // TODO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_lru_cache() {
        let mut cache = LRUCache::new(2);
        
        cache.put(1, "one");
        cache.put(2, "two");
        assert_eq!(cache.get(&1), Some(&"one"));
        
        cache.put(3, "three"); // 这会淘汰 key=2
        assert_eq!(cache.get(&2), None);
        assert_eq!(cache.get(&3), Some(&"three"));
    }
}
```

**考察点：**
- `HashMap` 和 `VecDeque` 的使用
- 所有权和借用
- 泛型编程

**参考答案要点：**
```rust
use std::collections::{HashMap, VecDeque};

pub struct LRUCache<K, V> {
    map: HashMap<K, V>,
    order: VecDeque<K>,
    capacity: usize,
}

impl<K, V> LRUCache<K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    pub fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }
    
    pub fn get(&mut self, key: &K) -> Option<&V> {
        if self.map.contains_key(key) {
            // 移动到末尾（最近使用）
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                self.order.remove(pos);
            }
            self.order.push_back(key.clone());
            self.map.get(key)
        } else {
            None
        }
    }
    
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        let evicted = if self.map.contains_key(&key) {
            // 更新现有值
            self.map.insert(key.clone(), value)
        } else {
            // 新插入
            if self.map.len() >= self.capacity {
                // 淘汰最旧的
                if let Some(oldest) = self.order.pop_front() {
                    self.map.remove(&oldest)
                } else {
                    None
                }
            } else {
                None
            }
            self.map.insert(key.clone(), value);
            None
        };
        
        // 更新顺序
        if let Some(pos) = self.order.iter().position(|k| k == &key) {
            self.order.remove(pos);
        }
        self.order.push_back(key);
        
        evicted
    }
}
```

---

### 题目 3: 实现一个 Result 类型的错误处理工具函数

**要求：**
实现一个函数，将多个 `Result<T, E>` 合并为一个 `Result<Vec<T>, E>`。如果所有结果都是 `Ok`，返回 `Ok(Vec<T>)`；如果任何一个结果是 `Err`，返回第一个 `Err`。

```rust
// 函数签名
fn collect_results<T, E>(results: Vec<Result<T, E>>) -> Result<Vec<T>, E> {
    // TODO
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_all_ok() {
        let results = vec![Ok(1), Ok(2), Ok(3)];
        assert_eq!(collect_results(results), Ok(vec![1, 2, 3]));
    }
    
    #[test]
    fn test_has_error() {
        let results = vec![Ok(1), Err("error"), Ok(3)];
        assert_eq!(collect_results(results), Err("error"));
    }
}
```

**考察点：**
- `Result` 类型的使用
- 迭代器和函数式编程
- 错误处理模式

**参考答案要点：**
```rust
fn collect_results<T, E>(results: Vec<Result<T, E>>) -> Result<Vec<T>, E> {
    let mut vec = Vec::new();
    for result in results {
        vec.push(result?);
    }
    Ok(vec)
}

// 或者使用迭代器
fn collect_results<T, E>(results: Vec<Result<T, E>>) -> Result<Vec<T>, E> {
    results.into_iter().collect()
}
```

---

### 题目 4: 实现一个自定义迭代器

**要求：**
实现一个 `Fibonacci` 迭代器，生成斐波那契数列。

```rust
pub struct Fibonacci {
    // TODO: 实现字段
}

impl Fibonacci {
    pub fn new() -> Self {
        // TODO
    }
}

impl Iterator for Fibonacci {
    type Item = u64;
    
    fn next(&mut self) -> Option<Self::Item> {
        // TODO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fibonacci() {
        let fib: Vec<u64> = Fibonacci::new().take(10).collect();
        assert_eq!(fib, vec![0, 1, 1, 2, 3, 5, 8, 13, 21, 34]);
    }
}
```

**考察点：**
- `Iterator` trait 的实现
- 状态管理
- 泛型编程

**参考答案要点：**
```rust
pub struct Fibonacci {
    current: u64,
    next: u64,
}

impl Fibonacci {
    pub fn new() -> Self {
        Self {
            current: 0,
            next: 1,
        }
    }
}

impl Iterator for Fibonacci {
    type Item = u64;
    
    fn next(&mut self) -> Option<Self::Item> {
        let value = self.current;
        self.current = self.next;
        self.next = value + self.current;
        Some(value)
    }
}
```

---

### 题目 5: 实现一个生命周期相关的函数

**要求：**
实现一个函数，找出两个字符串切片中较长的那个，并返回它的引用。

```rust
fn longer_string<'a>(s1: &'a str, s2: &'a str) -> &'a str {
    // TODO
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_longer_string() {
        let s1 = "short";
        let s2 = "much longer string";
        assert_eq!(longer_string(s1, s2), s2);
    }
}
```

**考察点：**
- 生命周期注解
- 引用和借用
- 字符串切片

**参考答案要点：**
```rust
fn longer_string<'a>(s1: &'a str, s2: &'a str) -> &'a str {
    if s1.len() > s2.len() {
        s1
    } else {
        s2
    }
}
```

---

### 题目 5.1: 实现 Box + Deref + Drop

**要求：**
实现一个简化版的 `Box<T>`，使用堆分配，并实现 `Deref` 和 `Drop` trait。

```rust
use std::ops::Deref;
use std::ptr;

// TODO: 实现一个简单的 Box，在堆上分配内存
pub struct MyBox<T> {
    // TODO: 使用原始指针存储堆上的数据
    ptr: *mut T,
}

impl<T> MyBox<T> {
    pub fn new(value: T) -> Self {
        // TODO: 在堆上分配内存并存储值
        // 提示：使用 Box::into_raw 或手动分配
    }
    
    pub fn into_inner(self) -> T {
        // TODO: 消耗 self，返回内部值
        // 注意：需要防止 double free
    }
}

// TODO: 实现 Deref trait，支持自动解引用
impl<T> Deref for MyBox<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        // TODO: 返回堆上数据的引用
        // 注意：unsafe 代码
    }
}

// TODO: 实现 Drop trait，自动释放内存
impl<T> Drop for MyBox<T> {
    fn drop(&mut self) {
        // TODO: 释放堆上分配的内存
        // 注意：防止内存泄漏
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mybox_basic() {
        let boxed = MyBox::new(42);
        assert_eq!(*boxed, 42);
    }
    
    #[test]
    fn test_deref() {
        let boxed = MyBox::new(String::from("hello"));
        // 由于实现了 Deref，可以直接调用 String 的方法
        assert_eq!(boxed.len(), 5);
        assert_eq!(boxed.to_uppercase(), "HELLO");
    }
    
    #[test]
    fn test_into_inner() {
        let boxed = MyBox::new(100);
        let value = boxed.into_inner();
        assert_eq!(value, 100);
        // boxed 已经被消耗，drop 不会再次释放
    }
}
```

**考察点：**
- `Box` 和堆分配
- `Deref` trait 和自动解引用
- `Drop` trait 和资源清理
- `unsafe` Rust 和内存安全
- 原始指针的使用

**参考答案要点：**
```rust
use std::ops::Deref;
use std::ptr;

pub struct MyBox<T> {
    ptr: *mut T,
}

impl<T> MyBox<T> {
    pub fn new(value: T) -> Self {
        let boxed = Box::new(value);
        Self {
            ptr: Box::into_raw(boxed),
        }
    }
    
    pub fn into_inner(mut self) -> T {
        let ptr = self.ptr;
        self.ptr = ptr::null_mut(); // 防止 drop 释放
        unsafe { *Box::from_raw(ptr) }
    }
}

impl<T> Deref for MyBox<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

impl<T> Drop for MyBox<T> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                drop(Box::from_raw(self.ptr));
            }
        }
    }
}
```

---

### 题目 5.2: Cell + 内部可变性 + 不可变引用下的修改

**要求：**
使用 `Cell` 实现内部可变性，允许在不可变引用下修改值。实现一个计数器，支持多线程场景下的计数操作。

```rust
use std::cell::Cell;

// TODO: 实现一个计数器，使用 Cell 实现内部可变性
pub struct Counter {
    // TODO: 使用 Cell 包装计数值
}

impl Counter {
    pub fn new(initial: i32) -> Self {
        // TODO
    }
    
    // TODO: 在不可变引用下增加计数
    pub fn increment(&self) {
        // TODO: 使用 Cell::get 和 Cell::set
    }
    
    // TODO: 在不可变引用下减少计数
    pub fn decrement(&self) {
        // TODO
    }
    
    // TODO: 获取当前值
    pub fn get(&self) -> i32 {
        // TODO
    }
    
    // TODO: 设置值
    pub fn set(&self, value: i32) {
        // TODO
    }
    
    // TODO: 使用闭包更新值
    pub fn update<F>(&self, f: F)
    where
        F: FnOnce(i32) -> i32,
    {
        // TODO: 使用 Cell::get 和 Cell::set
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_counter_basic() {
        let counter = Counter::new(10);
        assert_eq!(counter.get(), 10);
        
        counter.increment();
        assert_eq!(counter.get(), 11);
        
        counter.decrement();
        assert_eq!(counter.get(), 10);
    }
    
    #[test]
    fn test_multiple_borrows() {
        let counter = Counter::new(5);
        let c1 = &counter;
        let c2 = &counter;
        
        // Cell 允许多个不可变引用同时修改
        c1.increment();
        c2.increment();
        assert_eq!(counter.get(), 7);
    }
    
    #[test]
    fn test_update() {
        let counter = Counter::new(10);
        counter.update(|x| x * 2);
        assert_eq!(counter.get(), 20);
    }
    
    #[test]
    fn test_set() {
        let counter = Counter::new(0);
        counter.set(100);
        assert_eq!(counter.get(), 100);
    }
}
```

**考察点：**
- `Cell` 和内部可变性
- 不可变引用下的修改
- `Cell::get()` 和 `Cell::set()` 的使用
- 与 `RefCell` 的区别（`Cell` 不需要运行时借用检查）
- `Copy` trait 的要求（`Cell` 只能存储 `Copy` 类型）

**参考答案要点：**
```rust
use std::cell::Cell;

pub struct Counter {
    value: Cell<i32>,
}

impl Counter {
    pub fn new(initial: i32) -> Self {
        Self {
            value: Cell::new(initial),
        }
    }
    
    pub fn increment(&self) {
        self.value.set(self.value.get() + 1);
    }
    
    pub fn decrement(&self) {
        self.value.set(self.value.get() - 1);
    }
    
    pub fn get(&self) -> i32 {
        self.value.get()
    }
    
    pub fn set(&self, value: i32) {
        self.value.set(value);
    }
    
    pub fn update<F>(&self, f: F)
    where
        F: FnOnce(i32) -> i32,
    {
        let old = self.value.get();
        self.value.set(f(old));
    }
}
```

---

### 题目 5.3: RefCell + 内部可变性 + 运行时借用检查

**要求：**
使用 `RefCell` 实现内部可变性，支持运行时借用检查。实现一个缓存结构，支持在不可变引用下修改内部数据。

```rust
use std::cell::RefCell;
use std::collections::HashMap;

// TODO: 实现一个缓存结构，使用 RefCell 实现内部可变性
pub struct Cache<K, V> {
    // TODO: 使用 RefCell 包装 HashMap
}

impl<K, V> Cache<K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    pub fn new() -> Self {
        // TODO
    }
    
    // TODO: 实现 get 方法，返回 Ref<V>
    // 注意：使用 borrow() 获取 Ref
    pub fn get(&self, key: &K) -> Option<std::cell::Ref<'_, V>> {
        // TODO: 使用 Ref::map 返回内部值的引用
    }
    
    // TODO: 实现 set 方法
    pub fn set(&self, key: K, value: V) {
        // TODO: 使用 borrow_mut() 获取 RefMut
    }
    
    // TODO: 实现 get_or_insert，使用闭包计算默认值
    pub fn get_or_insert<F>(&self, key: K, f: F) -> std::cell::Ref<'_, V>
    where
        F: FnOnce() -> V,
    {
        // TODO: 先检查是否存在，不存在则插入
    }
    
    // TODO: 实现一个方法，同时获取两个值
    // 注意：RefCell 不允许同时有多个 RefMut，但可以有多个 Ref
    pub fn get_two(&self, key1: &K, key2: &K) -> Option<(std::cell::Ref<'_, V>, std::cell::Ref<'_, V>)> {
        // TODO: 需要小心处理，可能需要先获取两个 Ref
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cache_set_get() {
        let cache = Cache::new();
        cache.set("key1".to_string(), 100);
        
        let value = cache.get(&"key1".to_string());
        assert_eq!(value.map(|v| *v), Some(100));
    }
    
    #[test]
    fn test_get_or_insert() {
        let cache = Cache::new();
        
        let value1 = cache.get_or_insert("key1".to_string(), || 42);
        assert_eq!(*value1, 42);
        
        let value2 = cache.get_or_insert("key1".to_string(), || 100);
        assert_eq!(*value2, 42); // 应该返回已存在的值
    }
    
    #[test]
    fn test_multiple_refs() {
        let cache = Cache::new();
        cache.set("a".to_string(), 1);
        cache.set("b".to_string(), 2);
        
        // RefCell 允许多个不可变借用（Ref）同时存在
        let ref1 = cache.get(&"a".to_string());
        let ref2 = cache.get(&"b".to_string());
        assert_eq!(ref1.map(|v| *v), Some(1));
        assert_eq!(ref2.map(|v| *v), Some(2));
    }
    
    #[test]
    #[should_panic(expected = "already borrowed")]
    fn test_refcell_panic() {
        let cache = Cache::new();
        cache.set("key".to_string(), 1);
        
        // 这会 panic，因为不能同时有 RefMut 和 Ref
        let _ref1 = cache.get(&"key".to_string());
        cache.set("key".to_string(), 2); // panic!
    }
}
```

**考察点：**
- `RefCell` 和内部可变性
- `Ref` 和 `RefMut` 的区别
- 运行时借用检查
- `borrow()` 和 `borrow_mut()` 的使用
- `Ref::map` 的使用
- 与 `Cell` 的区别（`RefCell` 可以存储非 `Copy` 类型，但需要运行时检查）

**参考答案要点：**
```rust
use std::cell::RefCell;
use std::collections::HashMap;

pub struct Cache<K, V> {
    data: RefCell<HashMap<K, V>>,
}

impl<K, V> Cache<K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    pub fn new() -> Self {
        Self {
            data: RefCell::new(HashMap::new()),
        }
    }
    
    pub fn get(&self, key: &K) -> Option<std::cell::Ref<'_, V>> {
        let map = self.data.borrow();
        if map.contains_key(key) {
            Some(std::cell::Ref::map(map, |m| m.get(key).unwrap()))
        } else {
            None
        }
    }
    
    pub fn set(&self, key: K, value: V) {
        self.data.borrow_mut().insert(key, value);
    }
    
    pub fn get_or_insert<F>(&self, key: K, f: F) -> std::cell::Ref<'_, V>
    where
        F: FnOnce() -> V,
    {
        if !self.data.borrow().contains_key(&key) {
            let value = f();
            self.data.borrow_mut().insert(key.clone(), value);
        }
        std::cell::Ref::map(self.data.borrow(), |m| m.get(&key).unwrap())
    }
    
    pub fn get_two(&self, key1: &K, key2: &K) -> Option<(std::cell::Ref<'_, V>, std::cell::Ref<'_, V>)> {
        let map = self.data.borrow();
        if map.contains_key(key1) && map.contains_key(key2) {
            // 需要分别获取两个 Ref
            let map1 = self.data.borrow();
            let map2 = self.data.borrow();
            Some((
                std::cell::Ref::map(map1, |m| m.get(key1).unwrap()),
                std::cell::Ref::map(map2, |m| m.get(key2).unwrap()),
            ))
        } else {
            None
        }
    }
}
```

---

### 题目 5.4: Arc + Mutex + 并发编程

**要求：**
使用 `Arc` 和 `Mutex` 实现一个线程安全的共享计数器，支持多线程并发访问。

```rust
use std::sync::{Arc, Mutex};
use std::thread;

// TODO: 实现一个线程安全的计数器
pub struct SharedCounter {
    // TODO: 使用 Arc<Mutex<i32>> 实现线程安全的共享状态
}

impl SharedCounter {
    pub fn new(initial: i32) -> Self {
        // TODO
    }
    
    // TODO: 增加计数（线程安全）
    pub fn increment(&self) {
        // TODO: 使用 lock() 获取 MutexGuard
    }
    
    // TODO: 减少计数（线程安全）
    pub fn decrement(&self) {
        // TODO
    }
    
    // TODO: 获取当前值（线程安全）
    pub fn get(&self) -> i32 {
        // TODO
    }
    
    // TODO: 设置值（线程安全）
    pub fn set(&self, value: i32) {
        // TODO
    }
}

// TODO: 实现 Clone，支持创建多个引用
impl Clone for SharedCounter {
    // TODO: 克隆 Arc
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_single_thread() {
        let counter = SharedCounter::new(10);
        counter.increment();
        assert_eq!(counter.get(), 11);
    }
    
    #[test]
    fn test_multi_thread() {
        let counter = Arc::new(SharedCounter::new(0));
        let mut handles = vec![];
        
        // 创建 10 个线程，每个线程增加 100 次
        for _ in 0..10 {
            let counter = Arc::clone(&counter);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    counter.increment();
                }
            }));
        }
        
        // 等待所有线程完成
        for handle in handles {
            handle.join().unwrap();
        }
        
        assert_eq!(counter.get(), 1000);
    }
    
    #[test]
    fn test_clone() {
        let counter1 = SharedCounter::new(42);
        let counter2 = counter1.clone();
        
        // 两个引用指向同一个数据
        counter1.increment();
        assert_eq!(counter2.get(), 43);
    }
}
```

**考察点：**
- `Arc` 和原子引用计数
- `Mutex` 和互斥锁
- 线程安全和并发编程
- `MutexGuard` 和 RAII
- `Arc::clone()` 的使用
- `Send` 和 `Sync` trait

**参考答案要点：**
```rust
use std::sync::{Arc, Mutex};

pub struct SharedCounter {
    value: Arc<Mutex<i32>>,
}

impl SharedCounter {
    pub fn new(initial: i32) -> Self {
        Self {
            value: Arc::new(Mutex::new(initial)),
        }
    }
    
    pub fn increment(&self) {
        let mut guard = self.value.lock().unwrap();
        *guard += 1;
    }
    
    pub fn decrement(&self) {
        let mut guard = self.value.lock().unwrap();
        *guard -= 1;
    }
    
    pub fn get(&self) -> i32 {
        *self.value.lock().unwrap()
    }
    
    pub fn set(&self, value: i32) {
        let mut guard = self.value.lock().unwrap();
        *guard = value;
    }
}

impl Clone for SharedCounter {
    fn clone(&self) -> Self {
        Self {
            value: Arc::clone(&self.value),
        }
    }
}
```

---

### 题目 5.5: Drop trait + 资源清理 + RAII

**要求：**
实现一个资源管理器，使用 `Drop` trait 确保资源在离开作用域时自动清理。

```rust
use std::fmt;

// TODO: 实现一个文件句柄，模拟文件资源
pub struct File {
    name: String,
    is_open: bool,
}

impl File {
    pub fn open(name: &str) -> Self {
        println!("Opening file: {}", name);
        Self {
            name: name.to_string(),
            is_open: true,
        }
    }
    
    pub fn close(&mut self) {
        if self.is_open {
            println!("Closing file: {}", self.name);
            self.is_open = false;
        }
    }
    
    pub fn read(&self) -> String {
        if self.is_open {
            format!("Reading from {}", self.name)
        } else {
            panic!("File is closed");
        }
    }
}

// TODO: 实现 Drop trait，确保文件自动关闭
impl Drop for File {
    fn drop(&mut self) {
        // TODO: 在 drop 时关闭文件
    }
}

// TODO: 实现一个资源池，管理多个资源
pub struct ResourcePool<T> {
    resources: Vec<T>,
}

impl<T> ResourcePool<T> {
    pub fn new() -> Self {
        Self {
            resources: Vec::new(),
        }
    }
    
    pub fn add(&mut self, resource: T) {
        self.resources.push(resource);
    }
}

// TODO: 实现 Drop trait for ResourcePool
// 要求：按相反顺序清理资源（后进先出）
impl<T> Drop for ResourcePool<T>
where
    T: fmt::Debug,
{
    fn drop(&mut self) {
        // TODO: 清理所有资源
        // 提示：可以使用 while let 或 reverse
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_file_drop() {
        {
            let file = File::open("test.txt");
            // 文件在使用中
            assert_eq!(file.read(), "Reading from test.txt");
        } // 文件在这里自动关闭（drop 被调用）
    }
    
    #[test]
    fn test_resource_pool() {
        let mut pool = ResourcePool::new();
        pool.add(File::open("file1.txt"));
        pool.add(File::open("file2.txt"));
        pool.add(File::open("file3.txt"));
        // pool 在这里被 drop，所有文件按相反顺序关闭
    }
    
    #[test]
    fn test_manual_close() {
        let mut file = File::open("test.txt");
        file.close();
        // drop 时不应该再次关闭
    }
}
```

**考察点：**
- `Drop` trait 的实现
- RAII（Resource Acquisition Is Initialization）模式
- 资源自动清理
- `drop` 函数的调用时机
- 手动清理 vs 自动清理

**参考答案要点：**
```rust
impl Drop for File {
    fn drop(&mut self) {
        self.close();
    }
}

impl<T> Drop for ResourcePool<T>
where
    T: fmt::Debug,
{
    fn drop(&mut self) {
        // 按相反顺序清理（后进先出）
        while let Some(resource) = self.resources.pop() {
            // 资源在这里被 drop
            drop(resource);
        }
    }
}
```

---

### 题目 5.6: PhantomData + 类型状态模式 + 所有权转移 + 泛型

**要求：**
使用 `PhantomData` 实现类型级别的状态机，结合泛型、所有权转移和类型状态模式，在编译时保证状态转换的正确性。

```rust
use std::marker::PhantomData;

// 类型标记（零大小的类型）
pub struct Uninitialized;
pub struct Initialized;
pub struct Closed;

// TODO: 实现一个泛型状态机
// 要求：
// 1. 使用 PhantomData 标记状态
// 2. 不同状态有不同的可用方法
// 3. 状态转换需要消耗所有权
pub struct Database<T> {
    connection_string: String,
    _marker: PhantomData<T>,
}

impl Database<Uninitialized> {
    pub fn new(connection_string: String) -> Self {
        // TODO: 创建未初始化的数据库
    }
    
    // TODO: 连接数据库，消耗 self，返回已初始化的状态
    pub fn connect(self) -> Database<Initialized> {
        // TODO: 注意所有权转移
    }
}

impl Database<Initialized> {
    // TODO: 执行查询，返回 Result
    pub fn query(&self, sql: &str) -> Result<String, String> {
        // TODO
    }
    
    // TODO: 关闭数据库，消耗 self，返回 Closed 状态
    pub fn close(self) -> Database<Closed> {
        // TODO
    }
}

impl Database<Closed> {
    // TODO: 重新连接，消耗 self，返回 Initialized 状态
    pub fn reconnect(self) -> Database<Initialized> {
        // TODO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_database_lifecycle() {
        let db = Database::new("postgresql://localhost".to_string());
        let db = db.connect(); // 必须连接后才能查询
        let result = db.query("SELECT * FROM users");
        assert!(result.is_ok());
        
        let db = db.close(); // 关闭数据库
        let db = db.reconnect(); // 重新连接
        let result = db.query("SELECT * FROM users");
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_cannot_query_uninitialized() {
        // 这个测试应该无法编译
        // let db = Database::new("postgresql://localhost".to_string());
        // db.query("SELECT * FROM users"); // 应该编译错误
    }
}
```

**考察点：**
- `PhantomData` 和零大小类型
- 类型状态模式（Typestate Pattern）
- 所有权转移和消耗语义
- 泛型编程和类型参数
- 编译时状态保证

**参考答案要点：**
```rust
use std::marker::PhantomData;

pub struct Database<T> {
    connection_string: String,
    _marker: PhantomData<T>,
}

impl Database<Uninitialized> {
    pub fn new(connection_string: String) -> Self {
        Self {
            connection_string,
            _marker: PhantomData,
        }
    }
    
    pub fn connect(self) -> Database<Initialized> {
        // 模拟连接过程
        println!("Connecting to: {}", self.connection_string);
        Database {
            connection_string: self.connection_string,
            _marker: PhantomData,
        }
    }
}

impl Database<Initialized> {
    pub fn query(&self, sql: &str) -> Result<String, String> {
        Ok(format!("Query result for: {}", sql))
    }
}
```

---

### 题目 5.7: 宏定义（macro_rules!）+ 模式匹配 + 重复

**要求：**
使用 `macro_rules!` 实现几个常用的宏，包括创建向量、打印调试信息和计算最大值。

```rust
// TODO: 实现一个 my_vec! 宏，类似标准库的 vec!
// 支持两种用法：
// 1. my_vec![1, 2, 3] - 创建包含指定元素的向量
// 2. my_vec![0; 5] - 创建包含 5 个 0 的向量

#[macro_export]
macro_rules! my_vec {
    // TODO: 实现第一种模式（元素列表）
    // 提示：使用 $( $x:expr ),* 匹配多个表达式
}

// TODO: 实现一个 debug_print! 宏
// 用法：debug_print!(x, y, z) 会打印 "x = {x的值}, y = {y的值}, z = {z的值}"
#[macro_export]
macro_rules! debug_print {
    // TODO: 使用 stringify! 获取变量名
}

// TODO: 实现一个 max! 宏，计算多个值的最大值
// 用法：max!(1, 2, 3, 4) 返回 4
#[macro_export]
macro_rules! max {
    // TODO: 使用递归展开
    // 提示：max!(a, b, c) 可以展开为 max!(max!(a, b), c)
}

// TODO: 实现一个 count! 宏，计算参数数量
// 用法：count!(a, b, c) 返回 3
#[macro_export]
macro_rules! count {
    // TODO: 使用重复和替换
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_my_vec() {
        let v1 = my_vec![1, 2, 3];
        assert_eq!(v1, vec![1, 2, 3]);
        
        let v2 = my_vec![0; 5];
        assert_eq!(v2, vec![0, 0, 0, 0, 0]);
    }
    
    #[test]
    fn test_debug_print() {
        let x = 42;
        let y = "hello";
        // debug_print!(x, y); // 应该打印: x = 42, y = hello
    }
    
    #[test]
    fn test_max() {
        assert_eq!(max!(1, 2, 3), 3);
        assert_eq!(max!(10, 5, 8, 3), 10);
        assert_eq!(max!(1), 1);
    }
    
    #[test]
    fn test_count() {
        assert_eq!(count!(), 0);
        assert_eq!(count!(a), 1);
        assert_eq!(count!(a, b, c), 3);
        assert_eq!(count!(a, b, c, d, e), 5);
    }
}
```

**考察点：**
- `macro_rules!` 声明宏
- 模式匹配和重复（`$(...)*`, `$(...),*`, `$(...);*`）
- `stringify!` 和 `concat!` 内置宏
- 递归宏展开
- 宏的卫生性（hygiene）
- 元变量（metavariable）和片段分类符（fragment specifier）

**参考答案要点：**
```rust
#[macro_export]
macro_rules! my_vec {
    // 模式1: 元素列表
    ( $( $x:expr ),* ) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push($x);
            )*
            temp_vec
        }
    };
    // 模式2: 重复元素
    ( $x:expr ; $n:expr ) => {
        {
            let mut temp_vec = Vec::new();
            for _ in 0..$n {
                temp_vec.push($x);
            }
            temp_vec
        }
    };
}

#[macro_export]
macro_rules! debug_print {
    ( $( $x:ident ),* ) => {
        {
            $(
                println!("{} = {:?}", stringify!($x), $x);
            )*
        }
    };
}

#[macro_export]
macro_rules! max {
    ($x:expr) => { $x };
    ($x:expr, $($rest:expr),+) => {
        {
            let max_rest = max!($($rest),+);
            if $x > max_rest { $x } else { max_rest }
        }
    };
}

#[macro_export]
macro_rules! count {
    () => { 0 };
    ($first:expr $(, $rest:expr)*) => {
        1 + count!($($rest),*)
    };
}
```

---

## 编程题目（中等偏难）

> 适合考察对 Rust 核心特性的深入理解和实际应用能力

### 题目 6: 实现一个线程池

**要求：**
实现一个简单的线程池，支持提交任务并异步执行。需要考虑任务队列和线程管理。

```rust
use std::sync::{Arc, Mutex};
use std::thread;
use std::sync::mpsc;

type Job = Box<dyn FnOnce() + Send + 'static>;

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Option<mpsc::Sender<Job>>,
}

struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl ThreadPool {
    /// 创建一个新的线程池
    /// 
    /// size 是线程池中线程的数量
    pub fn new(size: usize) -> Self {
        assert!(size > 0);
        
        // TODO: 实现线程池创建逻辑
        // 1. 创建任务通道（sender/receiver）
        // 2. 创建指定数量的 worker 线程
        // 3. 每个 worker 从通道接收任务并执行
    }
    
    /// 执行一个任务
    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        // TODO: 将任务发送到任务队列
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        // TODO: 优雅关闭线程池
        // 1. 关闭发送端
        // 2. 等待所有 worker 线程完成
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    
    #[test]
    fn test_thread_pool() {
        let pool = ThreadPool::new(4);
        let counter = Arc::new(AtomicUsize::new(0));
        
        for _ in 0..10 {
            let counter = Arc::clone(&counter);
            pool.execute(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            });
        }
        
        // 等待任务完成
        thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(counter.load(Ordering::SeqCst), 10);
    }
}
```

**考察点：**
- 多线程编程和线程管理
- 通道（channel）的使用
- `Send` trait 和线程安全
- 优雅关闭和资源清理

**参考答案要点：**
```rust
use std::sync::mpsc;
use std::thread;

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Option<mpsc::Sender<Job>>,
}

struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl ThreadPool {
    pub fn new(size: usize) -> Self {
        assert!(size > 0);
        
        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        
        let mut workers = Vec::with_capacity(size);
        
        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }
        
        ThreadPool {
            workers,
            sender: Some(sender),
        }
    }
    
    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);
        self.sender.as_ref().unwrap().send(job).unwrap();
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        drop(self.sender.take());
        
        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

impl Worker {
    fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Job>>>) -> Self {
        let thread = thread::spawn(move || loop {
            let message = receiver.lock().unwrap().recv();
            
            match message {
                Ok(job) => {
                    job();
                }
                Err(_) => {
                    break;
                }
            }
        });
        
        Worker {
            id,
            thread: Some(thread),
        }
    }
}
```

---

### 题目 6.1: tokio + async/await + Future + 异步编程

**要求：**
使用 `tokio` 实现一个简单的异步任务执行器，支持异步任务的提交和执行。

```rust
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

// TODO: 实现一个异步任务执行器
pub struct AsyncExecutor {
    // TODO: 使用 tokio::sync::mpsc 创建任务通道
}

impl AsyncExecutor {
    pub fn new() -> Self {
        // TODO: 创建异步运行时和任务通道
    }
    
    // TODO: 提交一个异步任务
    // 返回 JoinHandle，可以等待任务完成
    pub fn spawn<F, T>(&self, future: F) -> JoinHandle<T>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // TODO: 使用 tokio::spawn 执行异步任务
    }
    
    // TODO: 实现一个方法，等待多个任务完成
    pub async fn join_all<F, T>(&self, futures: Vec<F>) -> Vec<T>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // TODO: 使用 futures::future::join_all 或 tokio::try_join!
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};
    
    #[tokio::test]
    async fn test_async_executor() {
        let executor = AsyncExecutor::new();
        
        let handle = executor.spawn(async {
            sleep(Duration::from_millis(100)).await;
            42
        });
        
        let result = handle.await.unwrap();
        assert_eq!(result, 42);
    }
    
    #[tokio::test]
    async fn test_join_all() {
        let executor = AsyncExecutor::new();
        
        let futures = vec![
            async { 1 },
            async { 2 },
            async { 3 },
        ];
        
        let results = executor.join_all(futures).await;
        assert_eq!(results, vec![1, 2, 3]);
    }
    
    #[tokio::test]
    async fn test_concurrent_tasks() {
        let executor = AsyncExecutor::new();
        let start = std::time::Instant::now();
        
        let handles: Vec<_> = (0..5)
            .map(|i| {
                executor.spawn(async move {
                    sleep(Duration::from_millis(100)).await;
                    i
                })
            })
            .collect();
        
        for handle in handles {
            handle.await.unwrap();
        }
        
        // 所有任务应该并发执行，总时间应该接近 100ms 而不是 500ms
        assert!(start.elapsed() < Duration::from_millis(200));
    }
}
```

**考察点：**
- `tokio` 异步运行时
- `async/await` 语法
- `Future` trait 和异步任务
- `tokio::spawn` 和 `JoinHandle`
- 异步并发执行
- `Send` 和 `'static` 约束

**参考答案要点：**
```rust
use tokio::task::JoinHandle;

pub struct AsyncExecutor;

impl AsyncExecutor {
    pub fn new() -> Self {
        Self
    }
    
    pub fn spawn<F, T>(&self, future: F) -> JoinHandle<T>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        tokio::spawn(future)
    }
    
    pub async fn join_all<F, T>(&self, futures: Vec<F>) -> Vec<T>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let handles: Vec<_> = futures.into_iter()
            .map(|f| self.spawn(f))
            .collect();
        
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }
        results
    }
}
```

---

### 题目 6.2: Send + Sync trait + 线程安全 + 并发编程

**要求：**
理解并实现 `Send` 和 `Sync` trait，创建一个线程安全的数据结构，并正确处理这些约束。

```rust
use std::sync::{Arc, Mutex};
use std::thread;
use std::marker::PhantomData;

// TODO: 实现一个线程安全的容器
// 要求：
// 1. 实现 Send 和 Sync trait（如果可能）
// 2. 支持多线程访问
// 3. 正确处理 Send/Sync 约束
pub struct ThreadSafeContainer<T> {
    data: Arc<Mutex<Vec<T>>>,
}

impl<T> ThreadSafeContainer<T> {
    pub fn new() -> Self {
        // TODO
    }
    
    // TODO: 添加元素（线程安全）
    pub fn push(&self, item: T) {
        // TODO
    }
    
    // TODO: 获取所有元素（线程安全）
    pub fn get_all(&self) -> Vec<T>
    where
        T: Clone,
    {
        // TODO
    }
}

// TODO: 实现 Send 和 Sync trait
// 提示：考虑 T 需要满足什么条件
impl<T> Send for ThreadSafeContainer<T> where T: Send {}
impl<T> Sync for ThreadSafeContainer<T> where T: Send + Sync {}

// TODO: 实现一个函数，检查类型是否满足 Send/Sync
pub fn check_send_sync<T: Send + Sync>() {
    // 这个函数只有在 T 实现 Send + Sync 时才能编译
}

// TODO: 创建一个不满足 Send 的类型示例
pub struct NotSend {
    // TODO: 使用 Rc 或其他非 Send 类型
}

// TODO: 创建一个不满足 Sync 的类型示例
pub struct NotSync {
    // TODO: 使用 RefCell 或其他非 Sync 类型
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;
    use std::cell::RefCell;
    
    #[test]
    fn test_thread_safe_container() {
        let container = Arc::new(ThreadSafeContainer::new());
        let mut handles = vec![];
        
        // 多个线程同时添加元素
        for i in 0..10 {
            let container = Arc::clone(&container);
            handles.push(thread::spawn(move || {
                container.push(i);
            }));
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        let items = container.get_all();
        assert_eq!(items.len(), 10);
    }
    
    #[test]
    fn test_send_sync_constraints() {
        // 这些应该能编译通过
        check_send_sync::<i32>();
        check_send_sync::<String>();
        check_send_sync::<Arc<i32>>();
        check_send_sync::<Mutex<i32>>();
        
        // 这些应该无法编译（取消注释测试）
        // check_send_sync::<Rc<i32>>(); // Rc 不是 Send
        // check_send_sync::<RefCell<i32>>(); // RefCell 不是 Sync
    }
    
    #[test]
    fn test_not_send() {
        // NotSend 不应该实现 Send
        // 这个测试应该无法编译（取消注释测试）
        // let not_send = NotSend::new();
        // thread::spawn(move || {
        //     let _ = not_send; // 应该编译错误
        // });
    }
    
    #[test]
    fn test_not_sync() {
        // NotSync 不应该实现 Sync
        // 这个测试应该无法编译（取消注释测试）
        // let not_sync = Arc::new(NotSync::new());
        // let not_sync2 = Arc::clone(&not_sync);
        // thread::spawn(move || {
        //     let _ = not_sync2; // 应该编译错误
        // });
    }
}
```

**考察点：**
- `Send` trait 的含义和使用
- `Sync` trait 的含义和使用
- `Send` 和 `Sync` 的区别
- 哪些类型自动实现 `Send`/`Sync`
- 哪些类型不实现 `Send`/`Sync`（如 `Rc`、`RefCell`）
- 如何为自定义类型实现 `Send`/`Sync`
- 线程安全约束和编译时检查

**参考答案要点：**
```rust
use std::sync::{Arc, Mutex};
use std::rc::Rc;
use std::cell::RefCell;

pub struct ThreadSafeContainer<T> {
    data: Arc<Mutex<Vec<T>>>,
}

impl<T> ThreadSafeContainer<T> {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    pub fn push(&self, item: T) {
        self.data.lock().unwrap().push(item);
    }
    
    pub fn get_all(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.data.lock().unwrap().clone()
    }
}

// Arc<Mutex<T>> 是 Send + Sync 的，如果 T: Send + Sync
impl<T> Send for ThreadSafeContainer<T> where T: Send {}
impl<T> Sync for ThreadSafeContainer<T> where T: Send + Sync {}

pub fn check_send_sync<T: Send + Sync>() {
    // 这个函数只有在 T 实现 Send + Sync 时才能编译
}

// Rc 不是 Send，因为它使用非原子引用计数
pub struct NotSend {
    _data: Rc<i32>,
}

impl NotSend {
    pub fn new() -> Self {
        Self {
            _data: Rc::new(0),
        }
    }
}

// RefCell 不是 Sync，因为它使用运行时借用检查
pub struct NotSync {
    _data: RefCell<i32>,
}

impl NotSync {
    pub fn new() -> Self {
        Self {
            _data: RefCell::new(0),
        }
    }
}
```

**补充说明：**
- `Send`: 类型可以安全地在线程间传递所有权
- `Sync`: 类型可以安全地在线程间共享引用（`&T`）
- 大多数类型自动实现 `Send` 和 `Sync`
- `Rc<T>` 不是 `Send` 也不是 `Sync`（使用 `Arc<T>` 代替）
- `RefCell<T>` 不是 `Sync`（使用 `Mutex<T>` 代替）
- `Cell<T>` 是 `Send` 但不是 `Sync`（如果 `T: Send`）
- `Mutex<T>` 是 `Send` 和 `Sync`（如果 `T: Send`）
- `Arc<T>` 是 `Send` 和 `Sync`（如果 `T: Send + Sync`）

---

### 题目 7: 实现一个类型安全的 Builder 模式

**要求：**
使用类型状态模式实现一个类型安全的 Builder，在编译时确保必填字段都已设置。

```rust
// 目标：实现一个类型安全的 UserBuilder
// 要求：name 和 email 是必填的，age 是可选的
// 只有在设置了 name 和 email 后，才能调用 build()

pub struct User {
    name: String,
    email: String,
    age: Option<u32>,
}

// TODO: 定义类型状态标记
pub struct NoName;
pub struct HasName;
pub struct NoEmail;
pub struct HasEmail;

pub struct UserBuilder<NameState, EmailState> {
    name: Option<String>,
    email: Option<String>,
    age: Option<u32>,
    _phantom: std::marker::PhantomData<(NameState, EmailState)>,
}

impl UserBuilder<NoName, NoEmail> {
    pub fn new() -> Self {
        // TODO
    }
    
    pub fn name(self, name: String) -> UserBuilder<HasName, NoEmail> {
        // TODO
    }
}

impl UserBuilder<HasName, NoEmail> {
    pub fn email(self, email: String) -> UserBuilder<HasName, HasEmail> {
        // TODO
    }
}

impl UserBuilder<HasName, HasEmail> {
    pub fn age(mut self, age: u32) -> Self {
        // TODO
    }
    
    pub fn build(self) -> User {
        // TODO: 只有在有 name 和 email 时才能调用
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_user_builder() {
        let user = UserBuilder::new()
            .name("Alice".to_string())
            .email("alice@example.com".to_string())
            .age(30)
            .build();
        
        assert_eq!(user.name, "Alice");
        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.age, Some(30));
    }
}
```

**考察点：**
- 类型状态模式（Typestate Pattern）
- 泛型和类型参数
- `PhantomData` 的使用
- 编译时保证

**参考答案要点：**
```rust
pub struct UserBuilder<NameState, EmailState> {
    name: Option<String>,
    email: Option<String>,
    age: Option<u32>,
    _phantom: std::marker::PhantomData<(NameState, EmailState)>,
}

impl UserBuilder<NoName, NoEmail> {
    pub fn new() -> Self {
        UserBuilder {
            name: None,
            email: None,
            age: None,
            _phantom: std::marker::PhantomData,
        }
    }
    
    pub fn name(self, name: String) -> UserBuilder<HasName, NoEmail> {
        UserBuilder {
            name: Some(name),
            email: self.email,
            age: self.age,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl UserBuilder<HasName, NoEmail> {
    pub fn email(self, email: String) -> UserBuilder<HasName, HasEmail> {
        UserBuilder {
            name: self.name,
            email: Some(email),
            age: self.age,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl UserBuilder<HasName, HasEmail> {
    pub fn age(mut self, age: u32) -> Self {
        self.age = Some(age);
        self
    }
    
    pub fn build(self) -> User {
        User {
            name: self.name.unwrap(),
            email: self.email.unwrap(),
            age: self.age,
        }
    }
}
```

---

### 题目 8: 实现一个简单的引用计数智能指针

**要求：**
实现一个简化版的 `Rc<T>`，支持引用计数和克隆。可以使用 `Box` 和 `Cell` 来简化实现。

```rust
use std::cell::Cell;

pub struct Rc<T> {
    inner: Box<RcInner<T>>,
}

struct RcInner<T> {
    value: T,
    count: Cell<usize>,
}

impl<T> Rc<T> {
    pub fn new(value: T) -> Self {
        // TODO: 创建引用计数指针
    }
    
    pub fn strong_count(&self) -> usize {
        // TODO: 返回当前引用计数
    }
}

impl<T> Clone for Rc<T> {
    fn clone(&self) -> Self {
        // TODO: 增加引用计数
    }
}

impl<T> std::ops::Deref for Rc<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        // TODO: 返回内部值的引用
    }
}

impl<T> Drop for Rc<T> {
    fn drop(&mut self) {
        // TODO: 减少引用计数，如果为 0 则释放内存
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rc_basic() {
        let rc1 = Rc::new(42);
        assert_eq!(rc1.strong_count(), 1);
        assert_eq!(*rc1, 42);
        
        let rc2 = rc1.clone();
        assert_eq!(rc1.strong_count(), 2);
        assert_eq!(rc2.strong_count(), 2);
        assert_eq!(*rc2, 42);
    }
}
```

**考察点：**
- 智能指针的实现
- `Cell` 和内部可变性
- 引用计数算法
- 所有权和生命周期

**参考答案要点：**
```rust
use std::cell::Cell;

pub struct Rc<T> {
    inner: Box<RcInner<T>>,
}

struct RcInner<T> {
    value: T,
    count: Cell<usize>,
}

impl<T> Rc<T> {
    pub fn new(value: T) -> Self {
        Rc {
            inner: Box::new(RcInner {
                value,
                count: Cell::new(1),
            }),
        }
    }
    
    pub fn strong_count(&self) -> usize {
        self.inner.count.get()
    }
}

impl<T> Clone for Rc<T> {
    fn clone(&self) -> Self {
        self.inner.count.set(self.inner.count.get() + 1);
        Rc {
            inner: unsafe { &*Box::into_raw(Box::new(self.inner.as_ref())) as *const _ as *mut _ }
                .as_ref()
                .unwrap()
                .clone(),
        }
    }
}

// 更简单的实现方式：使用 Arc 的简化版本
// 实际上，这个实现需要共享 Box，所以更好的方式是使用 Arc<Mutex<T>> 或者真正的引用计数
```

**注意：** 这个题目实际上展示了 `Rc` 的核心概念，但完整实现需要 `unsafe`。简化版本可以使用 `Arc` 作为参考。

---

### 题目 9: 实现一个简单的宏

**要求：**
实现一个 `vec!` 宏的简化版本，支持创建向量。

```rust
// 需要实现一个宏，支持以下用法：
// vec![1, 2, 3]
// vec![1; 5]  // 创建 5 个 1

#[macro_export]
macro_rules! my_vec {
    // TODO: 实现宏
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vec_macro() {
        let v1 = my_vec![1, 2, 3];
        assert_eq!(v1, vec![1, 2, 3]);
        
        let v2 = my_vec![0; 5];
        assert_eq!(v2, vec![0, 0, 0, 0, 0]);
    }
}
```

**考察点：**
- 声明宏（`macro_rules!`）的使用
- 模式匹配和重复
- 宏展开规则

**参考答案要点：**
```rust
#[macro_export]
macro_rules! my_vec {
    ( $( $x:expr ),* ) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push($x);
            )*
            temp_vec
        }
    };
    ( $x:expr ; $n:expr ) => {
        {
            let mut temp_vec = Vec::new();
            for _ in 0..$n {
                temp_vec.push($x);
            }
            temp_vec
        }
    };
}
```

---

### 题目 10: 实现一个线程安全的栈

**要求：**
实现一个使用 `Mutex` 的线程安全栈。

```rust
use std::sync::{Arc, Mutex};

pub struct ThreadSafeStack<T> {
    head: Arc<Mutex<Option<Box<Node<T>>>>>,
}

struct Node<T> {
    data: T,
    next: Option<Box<Node<T>>>,
}

impl<T> ThreadSafeStack<T> {
    pub fn new() -> Self {
        // TODO
    }
    
    pub fn push(&self, value: T) {
        // TODO: 使用 Mutex 保护 push 操作
    }
    
    pub fn pop(&self) -> Option<T> {
        // TODO: 使用 Mutex 保护 pop 操作
    }
    
    pub fn is_empty(&self) -> bool {
        // TODO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
    #[test]
    fn test_concurrent_push_pop() {
        let stack = Arc::new(ThreadSafeStack::new());
        let mut handles = vec![];
        
        // 10 个线程，每个 push 100 个元素
        for i in 0..10 {
            let stack = Arc::clone(&stack);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    stack.push(i * 100 + j);
                }
            }));
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        // 验证所有元素都能被 pop 出来
        let mut popped = Vec::new();
        while let Some(val) = stack.pop() {
            popped.push(val);
        }
        
        assert_eq!(popped.len(), 1000);
    }
}
```

**考察点：**
- `Arc` 和 `Mutex` 的使用
- 线程安全数据结构设计
- 内存安全和所有权

**参考答案要点：**
```rust
use std::sync::{Arc, Mutex};

pub struct ThreadSafeStack<T> {
    head: Arc<Mutex<Option<Box<Node<T>>>>>,
}

struct Node<T> {
    data: T,
    next: Option<Box<Node<T>>>,
}

impl<T> ThreadSafeStack<T> {
    pub fn new() -> Self {
        Self {
            head: Arc::new(Mutex::new(None)),
        }
    }
    
    pub fn push(&self, value: T) {
        let mut head = self.head.lock().unwrap();
        let new_node = Box::new(Node {
            data: value,
            next: head.take(),
        });
        *head = Some(new_node);
    }
    
    pub fn pop(&self) -> Option<T> {
        let mut head = self.head.lock().unwrap();
        head.take().map(|node| {
            *head = node.next;
            node.data
        })
    }
    
    pub fn is_empty(&self) -> bool {
        self.head.lock().unwrap().is_none()
    }
}
```

---

## 编程题目（高难度）

> 适合考察高级 Rust 特性、系统编程和复杂场景处理

### 题目 11: 实现一个无锁的并发数据结构（可选，高难度）

**要求：**
实现一个无锁（lock-free）的并发栈，使用原子操作而不是互斥锁。要求支持多线程的 `push` 和 `pop` 操作。

**提示：**
- 可以使用 `AtomicPtr` 来存储栈顶节点
- 使用 `compare_exchange_weak` 实现 CAS 操作
- 注意内存排序（`Ordering`）的选择
- 需要考虑 ABA 问题（本题可以忽略，但可以讨论）

```rust
use std::sync::atomic::{AtomicPtr, Ordering};
use std::ptr;

pub struct LockFreeStack<T> {
    head: AtomicPtr<Node<T>>,
}

struct Node<T> {
    data: T,
    next: *mut Node<T>,
}

impl<T> LockFreeStack<T> {
    pub fn new() -> Self {
        // TODO
    }
    
    pub fn push(&self, value: T) {
        // TODO: 使用 compare-and-swap (CAS) 实现无锁 push
    }
    
    pub fn pop(&self) -> Option<T> {
        // TODO: 使用 compare-and-swap (CAS) 实现无锁 pop
    }
}

impl<T> Drop for LockFreeStack<T> {
    fn drop(&mut self) {
        // TODO: 清理所有节点，避免内存泄漏
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::sync::Arc;
    
    #[test]
    fn test_concurrent_push_pop() {
        let stack = Arc::new(LockFreeStack::new());
        let mut handles = vec![];
        
        // 10 个线程，每个 push 100 个元素
        for i in 0..10 {
            let stack = Arc::clone(&stack);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    stack.push(i * 100 + j);
                }
            }));
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        // 验证所有元素都能被 pop 出来
        let mut popped = Vec::new();
        while let Some(val) = stack.pop() {
            popped.push(val);
        }
        
        assert_eq!(popped.len(), 1000);
    }
}
```

**考察点：**
- 原子操作和内存排序（`Ordering`）
- 无锁编程和 CAS 操作
- 内存安全和 unsafe Rust
- 并发数据结构设计

**参考答案要点：**
```rust
use std::sync::atomic::{AtomicPtr, Ordering};
use std::ptr;

pub struct LockFreeStack<T> {
    head: AtomicPtr<Node<T>>,
}

struct Node<T> {
    data: T,
    next: *mut Node<T>,
}

impl<T> LockFreeStack<T> {
    pub fn new() -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
        }
    }
    
    pub fn push(&self, value: T) {
        let new_node = Box::into_raw(Box::new(Node {
            data: value,
            next: ptr::null_mut(),
        }));
        
        loop {
            let head = self.head.load(Ordering::Acquire);
            unsafe {
                (*new_node).next = head;
            }
            
            if self.head.compare_exchange_weak(
                head,
                new_node,
                Ordering::Release,
                Ordering::Relaxed,
            ).is_ok() {
                return;
            }
        }
    }
    
    pub fn pop(&self) -> Option<T> {
        loop {
            let head = self.head.load(Ordering::Acquire);
            if head.is_null() {
                return None;
            }
            
            let next = unsafe { (*head).next };
            
            if self.head.compare_exchange_weak(
                head,
                next,
                Ordering::Release,
                Ordering::Relaxed,
            ).is_ok() {
                let node = unsafe { Box::from_raw(head) };
                return Some(node.data);
            }
        }
    }
}

impl<T> Drop for LockFreeStack<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}
```

---

### 题目 12: 实现一个简单的异步 Future（可选，高难度）

**要求：**
实现一个简单的 `Future` trait，支持异步执行。可以使用 `tokio` 或 `async-std` 作为运行时。

**提示：**
- 理解 `Future` trait 的基本结构
- 使用 `Pin` 处理自引用结构
- 理解 `Poll` 和 `Waker` 的作用
- 可以参考 `std::future::Future` 的定义

```rust
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::sync::{Arc, Mutex};
use std::collections::BinaryHeap;
use std::cmp::Ordering;

pub struct Task {
    // TODO: 实现任务结构
}

impl Task {
    pub fn new(priority: u32, future: Pin<Box<dyn Future<Output = ()> + Send>>) -> Self {
        // TODO
    }
}

impl Ord for Task {
    // TODO: 按优先级排序
}

impl PartialOrd for Task {
    // TODO
}

impl Eq for Task {}

impl PartialEq for Task {
    // TODO
}

pub struct TaskScheduler {
    // TODO: 实现调度器结构
}

impl TaskScheduler {
    pub fn new() -> Self {
        // TODO
    }
    
    pub fn submit(&self, task: Task) {
        // TODO: 提交任务到调度器
    }
    
    pub async fn run(&self) {
        // TODO: 执行任务，按优先级顺序
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_task_scheduler() {
        let scheduler = TaskScheduler::new();
        
        scheduler.submit(Task::new(1, Box::pin(async {
            println!("Low priority task");
        })));
        
        scheduler.submit(Task::new(10, Box::pin(async {
            println!("High priority task");
        })));
        
        scheduler.run().await;
    }
}
```

**考察点：**
- 异步编程（`Future`、`async/await`）
- `Pin` 和自引用结构
- 任务调度和优先级队列
- `Waker` 和任务唤醒机制

---

**注意：** 以下高难度题目为可选题目，适合对 Rust 有深入理解的候选人。如果候选人能够完成中等偏难的题目，可以尝试这些挑战。

---

## 知识点问答题

### 1. 所有权（Ownership）相关

**Q: 解释 Rust 中的所有权系统，并说明为什么需要它？**

**参考答案要点：**
- 所有权是 Rust 的核心特性，确保内存安全
- 每个值都有一个所有者，当所有者离开作用域时，值会被自动释放
- 所有权规则：
  1. 每个值都有一个所有者
  2. 同一时间只能有一个所有者
  3. 当所有者离开作用域时，值会被丢弃
- 避免了内存泄漏和悬垂指针问题
- 不需要垃圾回收器，编译时保证内存安全

---

### 2. 借用（Borrowing）相关

**Q: 解释 Rust 中的借用规则，并说明可变借用和不可变借用的区别？**

**参考答案要点：**
- 借用允许你使用值而不获取所有权
- 借用规则：
  1. 可以有多个不可变引用（`&T`）
  2. 只能有一个可变引用（`&mut T`）
  3. 可变引用和不可变引用不能同时存在
- 不可变借用：`&T`，允许多个同时存在，但不能修改
- 可变借用：`&mut T`，只能有一个，可以修改
- 这些规则在编译时检查，避免数据竞争

---

### 3. 生命周期（Lifetime）相关

**Q: 什么是生命周期？什么时候需要显式标注生命周期？**

**参考答案要点：**
- 生命周期是引用有效的作用域
- 大多数情况下，Rust 可以自动推断生命周期（生命周期省略）
- 需要显式标注的情况：
  1. 函数返回引用时
  2. 结构体包含引用时
  3. 生命周期省略规则无法推断时
- 生命周期注解语法：`'a`, `'static` 等
- `'static` 表示整个程序运行期间都有效

---

### 4. 错误处理相关

**Q: 比较 `Result<T, E>` 和 `Option<T>` 的使用场景，并说明如何优雅地处理错误？**

**参考答案要点：**
- `Option<T>`：表示值可能存在或不存在（`Some(T)` 或 `None`）
- `Result<T, E>`：表示操作可能成功（`Ok(T)`）或失败（`Err(E)`）
- 使用场景：
  - `Option`：查找操作、可能为空的值
  - `Result`：可能失败的操作、I/O 操作、解析操作
- 错误处理方式：
  - `?` 操作符：传播错误
  - `unwrap()` / `expect()`：panic（不推荐在生产代码中使用）
  - `match` / `if let`：显式处理
  - `map` / `and_then`：函数式处理

---

### 5. 并发编程相关

**Q: 解释 Rust 中的并发模型，包括 `Send` 和 `Sync` trait？**

**参考答案要点：**
- Rust 通过类型系统保证线程安全
- `Send` trait：类型可以安全地在线程间传递所有权
- `Sync` trait：类型可以安全地在线程间共享引用（`&T`）
- 大多数类型自动实现 `Send` 和 `Sync`
- 例外：`Rc<T>` 不是 `Send` 也不是 `Sync`（使用 `Arc<T>` 代替）
- `RefCell<T>` 不是 `Sync`（使用 `Mutex<T>` 代替）
- `Mutex<T>` 和 `Arc<T>` 是常用的线程安全工具

---

### 6. 智能指针相关

**Q: 比较 `Box<T>`, `Rc<T>`, `Arc<T>`, `RefCell<T>` 的使用场景？**

**参考答案要点：**
- `Box<T>`：
  - 堆分配
  - 单一所有者
  - 用于递归类型、大类型
- `Rc<T>`：
  - 引用计数，多所有者
  - 单线程使用
  - 不可变借用
- `Arc<T>`：
  - 原子引用计数，多所有者
  - 多线程安全
  - 不可变借用
- `RefCell<T>`：
  - 运行时借用检查
  - 单线程使用
  - 允许可变借用
- 组合使用：`Rc<RefCell<T>>` 或 `Arc<Mutex<T>>`

---

### 7. Trait 相关

**Q: 解释 Rust 中的 trait，包括 trait bound、trait object 和关联类型？**

**参考答案要点：**
- Trait 定义了一组方法，类似于接口
- Trait bound：泛型参数必须实现某个 trait
  ```rust
  fn foo<T: Display>(x: T) { ... }
  ```
- Trait object：动态分发，使用 `dyn Trait`
  ```rust
  fn bar(x: &dyn Display) { ... }
  ```
- 关联类型：trait 中定义的类型别名
  ```rust
  trait Iterator {
      type Item;
      fn next(&mut self) -> Option<Self::Item>;
  }
  ```
- 默认实现：trait 方法可以有默认实现
- 孤儿规则：不能为外部类型实现外部 trait

---

### 8. 模式匹配相关

**Q: 解释 Rust 中的模式匹配，包括 `match`、`if let`、`while let` 的使用场景？**

**参考答案要点：**
- `match`：全面的模式匹配，必须覆盖所有情况
- `if let`：匹配单个模式，用于简化 `match` 的简单情况
- `while let`：循环中的模式匹配
- 模式类型：
  - 字面量：`1`, `"hello"`
  - 变量绑定：`x`, `mut y`
  - 通配符：`_`
  - 范围：`1..=5`
  - 结构体解构：`Point { x, y }`
  - 元组解构：`(a, b)`
  - 引用：`&x`
  - 守卫：`x if x > 5`

---

### 9. 宏（Macro）相关

**Q: 解释声明宏（declarative macro）和过程宏（procedural macro）的区别？**

**参考答案要点：**
- 声明宏（`macro_rules!`）：
  - 使用模式匹配
  - 编译时展开
  - 例子：`vec![]`, `println!()`
- 过程宏：
  - 作为函数实现
  - 三种类型：
    1. 派生宏（`#[derive(...)]`）
    2. 属性宏（`#[attribute]`）
    3. 函数式宏（`macro_name!()`）
  - 例子：`serde` 的 `Serialize`、`Deserialize`
- 宏在编译时展开，可以生成代码

---

### 10. 内存安全相关

**Q: Rust 如何保证内存安全？与 C++ 相比有什么优势？**

**参考答案要点：**
- 编译时检查：
  - 所有权系统防止使用后释放
  - 借用检查器防止数据竞争
  - 生命周期检查防止悬垂引用
- 运行时检查：
  - 数组边界检查
  - `panic!` 处理不可恢复错误
- 与 C++ 相比：
  - 不需要手动管理内存
  - 编译时保证内存安全，不需要运行时开销
  - 没有垃圾回收器
  - 零成本抽象
  - 更严格的类型系统

---

## 深层次问答题（高级）

### 11. 生命周期高级特性

**Q: 解释高阶生命周期（Higher-Ranked Trait Bounds, HRTB）的概念和使用场景？**

**参考答案要点：**
- HRTB 使用 `for<'a>` 语法，表示"对于所有生命周期 `'a`"
- 用于处理闭包和函数指针的生命周期
- 常见场景：
  ```rust
  fn call_twice<F>(f: F) 
  where 
      F: for<'a> Fn(&'a str) -> &'a str 
  {
      f("hello")
  }
  ```
- 与普通生命周期绑定的区别：HRTB 表示函数可以接受任意生命周期的引用
- 实际应用：`Fn` trait 的定义中就使用了 HRTB
- 与 `'static` 的区别：`'static` 要求整个程序生命周期，HRTB 更灵活

---

### 12. 泛型高级特性

**Q: 解释 Rust 中的关联类型（Associated Types）、泛型关联类型（GAT）和常量泛型（Const Generics）的区别和使用场景？**

**参考答案要点：**
- **关联类型**：
  - 在 trait 中定义，每个实现者指定具体类型
  - 例子：`Iterator::Item`
  - 优势：简化 trait 签名，避免重复类型参数
- **泛型关联类型（GAT）**：
  - 关联类型本身可以是泛型的
  - Rust 1.65+ 支持
  - 例子：
    ```rust
    trait Iterator {
        type Item<'a> where Self: 'a;
    }
    ```
  - 用于更复杂的类型关系
- **常量泛型**：
  - 使用常量值作为泛型参数
  - 例子：`[T; N]`，`Array<T, const N: usize>`
  - 优势：编译时确定大小，零成本抽象
  - 与类型参数的区别：类型参数是类型，常量参数是值

---

### 13. Unsafe Rust 深入

**Q: 解释 `unsafe` Rust 的作用和使用场景，以及如何安全地使用 `unsafe` 代码？**

**参考答案要点：**
- `unsafe` 关键字的作用：
  - 允许执行编译器无法验证安全的操作
  - 不关闭借用检查器或所有权系统
  - 只是允许特定的不安全操作
- 不安全操作：
  1. 解引用裸指针（`*const T`, `*mut T`）
  2. 调用 unsafe 函数
  3. 访问或修改可变静态变量
  4. 实现 unsafe trait
  5. 访问 union 的字段
- 安全使用 `unsafe` 的原则：
  - 最小化 unsafe 代码范围
  - 提供安全的抽象接口
  - 仔细验证不变量（invariants）
  - 文档化安全保证
- 常见场景：
  - FFI（Foreign Function Interface）
  - 性能关键代码
  - 底层系统编程
  - 实现标准库类型（如 `Vec`、`Rc`）

---

### 14. 零成本抽象和性能优化

**Q: 解释 Rust 的"零成本抽象"（Zero-Cost Abstractions）概念，并举例说明？**

**参考答案要点：**
- 定义：抽象不会带来运行时开销，如果手写底层代码，性能应该相同
- 例子：
  - `Iterator` trait：编译后与手写循环性能相同
  - `Option<T>`：`None` 和 `Some(T)` 的内存布局优化
  - 闭包：可以内联，与函数调用性能相同
  - 泛型：单态化（monomorphization），编译时生成具体类型代码
- 与 C++ 的对比：
  - C++ 的虚函数有运行时开销
  - Rust 的 trait object 有动态分发开销，但静态分发是零成本的
- 性能优化技巧：
  - 使用 `#[inline]` 提示编译器
  - 避免不必要的堆分配
  - 使用 `Copy` 类型避免移动开销
  - 利用编译器的优化

---

### 15. 内存布局和优化

**Q: 解释 Rust 中结构体的内存布局，包括对齐（alignment）、填充（padding）和 `#[repr]` 属性的作用？**

**参考答案要点：**
- 默认内存布局：
  - Rust 不保证字段顺序（可能重排以优化）
  - 字段对齐到其大小的倍数
  - 结构体大小对齐到最大字段的对齐要求
- `#[repr]` 属性：
  - `#[repr(C)]`：C 兼容布局，保证字段顺序
  - `#[repr(packed)]`：紧密打包，无填充（可能影响性能）
  - `#[repr(align(n))]`：指定对齐方式
  - `#[repr(transparent)]`：单字段结构体与字段布局相同
- 优化技巧：
  - 字段重排可以减少填充
  - 大字段放在前面可能更好
  - `Option<T>` 的布局优化（`None` 可能用特殊位模式表示）
- 实际影响：
  - 影响内存使用
  - 影响缓存性能
  - FFI 互操作需要 `#[repr(C)]`

---

### 16. 编译器和类型系统深入

**Q: 解释 Rust 编译器的借用检查器（Borrow Checker）的工作原理，包括非词法生命周期（NLL）的改进？**

**参考答案要点：**
- 借用检查器的核心：
  - 跟踪每个引用的生命周期
  - 确保引用不会超过其引用的数据的生命周期
  - 检查借用规则（不可变/可变借用冲突）
- 非词法生命周期（NLL）：
  - 旧版本：生命周期基于词法作用域
  - NLL：生命周期基于实际使用范围
  - 例子：
    ```rust
    let mut v = vec![1, 2, 3];
    let first = &v[0];  // 借用开始
    v.push(4);          // 旧版本：错误（v 被借用）
                        // NLL：OK（first 不再使用）
    ```
- 借用检查器的限制：
  - 无法理解某些复杂的数据流
  - 可能需要重构代码来满足检查器
- 与运行时检查的区别：
  - 编译时检查，零运行时开销
  - 可能拒绝一些实际上安全的代码

---

### 17. 异步编程深入

**Q: 解释 Rust 异步编程的底层机制，包括 `Future` trait、`Pin`、`Waker` 和异步运行时（如 tokio）的作用？**

**参考答案要点：**
- `Future` trait：
  - 表示一个异步计算
  - `poll` 方法检查是否完成
  - 返回 `Poll::Ready(T)` 或 `Poll::Pending`
- `Pin`：
  - 固定（pin）值在内存中的位置
  - 防止自引用结构体被移动
  - `Pin<&mut T>` 确保 `T` 不会被移动
- `Waker`：
  - 通知运行时 Future 可以继续执行
  - 当异步操作完成时调用
  - 允许运行时调度 Future
- 异步运行时（tokio）：
  - 提供事件循环和任务调度
  - 管理 I/O 事件和定时器
  - 执行器（executor）负责运行 Future
- 与线程的区别：
  - 异步是协作式多任务
  - 更轻量级，可以处理大量并发
  - 需要运行时支持

---

### 18. 宏系统深入

**Q: 解释 Rust 宏系统的卫生性（Hygiene）、作用域和调试技巧？**

**参考答案要点：**
- 宏卫生性：
  - 宏中的变量不会意外捕获外部变量
  - 宏生成的标识符不会与外部冲突
  - 例子：`macro_rules!` 中的变量是"卫生的"
- 作用域规则：
  - 宏定义的作用域
  - `#[macro_export]` 导出宏
  - `#[macro_use]` 导入宏
- 调试技巧：
  - `cargo expand` 查看宏展开后的代码
  - `--pretty expanded` 编译选项
  - `dbg!()` 宏用于调试
- 过程宏 vs 声明宏：
  - 过程宏更强大，可以访问 AST
  - 声明宏更简单，但功能有限
  - 过程宏需要单独的 crate

---

### 19. 错误处理和 Panic 机制

**Q: 解释 Rust 中的 panic 机制、`catch_unwind`、`abort` vs `unwind` 的区别，以及错误处理的最佳实践？**

**参考答案要点：**
- Panic 机制：
  - 不可恢复的错误
  - 默认会展开（unwind）调用栈
  - 可以设置 `panic = 'abort'` 直接终止
- `catch_unwind`：
  - 捕获 panic，防止程序崩溃
  - 主要用于 FFI 边界
  - 不应用于常规错误处理
- `abort` vs `unwind`：
  - `unwind`：清理资源，但二进制文件更大
  - `abort`：直接终止，二进制文件更小
  - 嵌入式系统通常使用 `abort`
- 错误处理最佳实践：
  - 可恢复错误使用 `Result<T, E>`
  - 不可恢复错误使用 `panic!`
  - 使用 `?` 操作符传播错误
  - 定义自定义错误类型
  - 使用 `thiserror` 或 `anyhow` 库

---

### 20. 并发模式深入

**Q: 解释 Rust 中的各种并发原语（`Mutex`、`RwLock`、`Condvar`、`Barrier`、`Once`）的使用场景和性能特点？**

**参考答案要点：**
- `Mutex<T>`：
  - 互斥锁，同时只允许一个线程访问
  - 适合读写都少的场景
  - 可能死锁
- `RwLock<T>`：
  - 读写锁，允许多个读或一个写
  - 适合读多写少的场景
  - 可能写者饥饿
- `Condvar`：
  - 条件变量，用于线程间通信
  - 必须与 `Mutex` 配合使用
  - 用于等待特定条件
- `Barrier`：
  - 屏障，等待多个线程到达同一位置
  - 用于同步多个线程
- `Once`：
  - 确保代码只执行一次
  - 用于初始化
- 性能考虑：
  - 锁的粒度要小
  - 避免在锁内执行耗时操作
  - 考虑无锁数据结构

---

### 21. 类型系统和 Trait 深入

**Q: 解释 Rust 中的孤儿规则（Orphan Rule）、一致性（Coherence）和特化（Specialization）的概念？**

**参考答案要点：**
- 孤儿规则：
  - 不能为外部类型实现外部 trait
  - 必须至少有一个是本地的（类型或 trait）
  - 防止 trait 实现的冲突
  - 例子：不能为 `Vec<T>` 实现 `Display`（两者都是外部的）
- 一致性（Coherence）：
  - 确保每个类型对每个 trait 只有一个实现
  - 编译器检查实现的一致性
  - 防止冲突的实现
- 特化（Specialization）：
  - 允许为特定类型提供更具体的实现
  - 目前是实验性特性
  - 用于性能优化
- 实际影响：
  - 可能需要使用 newtype 模式绕过孤儿规则
  - 影响库的设计和扩展性

---

### 22. 内存管理和优化

**Q: 解释 Rust 中的栈分配、堆分配、内存对齐，以及如何优化内存使用？**

**参考答案要点：**
- 栈分配：
  - 自动管理，速度快
  - 大小固定，生命周期明确
  - 用于局部变量、函数参数
- 堆分配：
  - 使用 `Box`、`Vec`、`String` 等
  - 动态大小，生命周期灵活
  - 需要分配器（allocator）
- 内存对齐：
  - 数据必须对齐到其大小的倍数
  - 影响内存使用和性能
  - 可以使用 `#[repr]` 控制
- 优化技巧：
  - 使用 `Copy` 类型避免堆分配
  - 使用 `Cow`（Clone on Write）延迟克隆
  - 使用 `SmallVec` 优化小向量
  - 使用对象池减少分配
  - 注意 `Box` 的间接访问开销

---

### 23. 生命周期和引用深入

**Q: 解释生命周期省略规则（Lifetime Elision Rules）、`'static` 生命周期，以及何时需要显式标注生命周期？**

**参考答案要点：**
- 生命周期省略规则：
  1. 每个引用参数都有自己的生命周期
  2. 如果只有一个输入生命周期，它被赋予所有输出生命周期
  3. 如果有 `&self` 或 `&mut self`，输出生命周期与 `self` 相同
- `'static` 生命周期：
  - 整个程序运行期间有效
  - 字符串字面量是 `'static`
  - 全局变量是 `'static`
  - 与 `'static` bound 的区别
- 需要显式标注的情况：
  - 函数返回引用
  - 结构体包含引用
  - 生命周期省略规则无法推断
  - 多个生命周期需要区分
- 常见陷阱：
  - 返回局部变量的引用
  - 生命周期不匹配
  - 过度使用 `'static`

---

### 24. 编译时计算和常量

**Q: 解释 Rust 中的 `const` 函数、`const` 泛型、编译时计算（CTFE）和 `const` trait 的概念？**

**参考答案要点：**
- `const` 函数：
  - 可以在编译时执行的函数
  - 限制：只能调用其他 `const` 函数
  - 不能使用堆分配、I/O 等
  - 例子：`const fn add(a: i32, b: i32) -> i32 { a + b }`
- `const` 泛型：
  - 使用常量值作为泛型参数
  - Rust 1.51+ 支持
  - 例子：`fn foo<const N: usize>()`
- 编译时计算（CTFE）：
  - Compile-Time Function Execution
  - 在编译时执行代码
  - 零运行时开销
- `const` trait：
  - 实验性特性
  - 允许在 `const` 上下文中使用 trait
- 优势：
  - 性能优化
  - 类型安全
  - 减少运行时开销

---

### 25. 高级并发模式

**Q: 解释无锁编程（Lock-Free Programming）、原子操作（Atomic Operations）、内存排序（Memory Ordering）的概念和使用场景？**

**参考答案要点：**
- 无锁编程：
  - 不使用互斥锁的并发编程
  - 使用原子操作和 CAS（Compare-And-Swap）
  - 可能更高效，但更复杂
- 原子操作：
  - `AtomicBool`、`AtomicUsize`、`AtomicPtr` 等
  - 保证操作的原子性
  - 不需要锁
- 内存排序（`Ordering`）：
  - `Relaxed`：只保证原子性
  - `Acquire`：获取语义，防止后续操作重排到前面
  - `Release`：释放语义，防止前面操作重排到后面
  - `AcqRel`：获取+释放
  - `SeqCst`：顺序一致性，最强保证
- 使用场景：
  - 性能关键的并发代码
  - 实现无锁数据结构
  - 计数器、标志位等简单场景
- 注意事项：
  - 容易出错，需要仔细设计
  - 可能需要 `unsafe` 代码
  - 测试困难

---

### 26. 类型转换和 Trait 对象

**Q: 解释 Rust 中的类型转换机制，包括 `From`/`Into`、`AsRef`/`AsMut`、`Deref`/`DerefMut`，以及 trait 对象的动态分发？**

**参考答案要点：**
- `From`/`Into`：
  - `From` 是主 trait，`Into` 自动实现
  - 用于类型转换
  - 所有权转移
- `AsRef`/`AsMut`：
  - 引用转换，不转移所有权
  - 用于提供不同视角的引用
  - 例子：`String::as_str()`
- `Deref`/`DerefMut`：
  - 解引用操作符
  - 自动解引用（deref coercion）
  - 用于智能指针
- Trait 对象：
  - `dyn Trait` 表示动态分发
  - 使用虚函数表（vtable）
  - 有运行时开销
  - 与泛型的区别：泛型是静态分发
- 性能考虑：
  - 静态分发（泛型）通常更快
  - Trait 对象更灵活，但需要间接调用

---

### 27. 编译器和工具链

**Q: 解释 Rust 编译器的优化、LLVM 的作用、增量编译，以及如何优化编译时间？**

**参考答案要点：**
- 编译器优化：
  - 内联函数
  - 死代码消除
  - 常量传播
  - 循环优化
  - 使用 LLVM 进行后端优化
- LLVM：
  - 底层虚拟机
  - 提供代码生成和优化
  - Rust 编译为 LLVM IR，然后编译为机器码
- 增量编译：
  - 只重新编译改变的部分
  - 使用依赖图跟踪
  - 可以显著加快开发速度
- 优化编译时间：
  - 使用 `cargo build --release` 的优化设置
  - 减少依赖数量
  - 使用 `[profile.dev]` 调整开发模式优化
  - 使用 `sccache` 缓存编译结果
  - 并行编译（`-j` 参数）

---

### 28. 错误处理和类型系统

**Q: 解释 Rust 中 `Result` 的错误传播机制、错误链（Error Chaining）、`Error` trait 的设计，以及如何处理多种错误类型？**

**参考答案要点：**
- 错误传播：
  - `?` 操作符自动传播错误
  - 等价于 `match` + `return`
  - 可以链式调用
- 错误链：
  - `source()` 方法获取底层错误
  - 使用 `anyhow::Error` 或 `eyre::Report`
  - 可以追踪错误来源
- `Error` trait：
  - `Display`：用户友好的错误信息
  - `Debug`：调试信息
  - `source()`：错误链
- 处理多种错误类型：
  - 使用 `From` trait 转换
  - 使用 `Box<dyn Error>`
  - 使用 `anyhow::Result`
  - 定义统一的错误类型

---

### 29. 高级类型系统特性

**Q: 解释 Rust 中的类型状态模式（Typestate Pattern）、新类型模式（Newtype Pattern）、标记类型（Marker Types）的使用场景？**

**参考答案要点：**
- 类型状态模式：
  - 使用类型参数表示状态
  - 编译时保证状态转换的正确性
  - 例子：`Database<Uninitialized>` → `Database<Initialized>`
  - 使用 `PhantomData` 标记状态
- 新类型模式：
  - 包装现有类型创建新类型
  - 绕过孤儿规则
  - 提供类型安全
  - 例子：`struct UserId(u64)`
- 标记类型：
  - 零大小的类型
  - 用于类型级别的标记
  - 不占用内存
  - 例子：`Send`、`Sync` marker traits
- 优势：
  - 编译时保证
  - 零运行时开销
  - 类型安全

---

### 30. 性能和基准测试

**Q: 解释如何分析和优化 Rust 程序的性能，包括性能分析工具、基准测试、以及常见的性能陷阱？**

**参考答案要点：**
- 性能分析工具：
  - `perf`（Linux）
  - `cargo flamegraph`
  - `cargo bench`
  - `criterion` 库用于基准测试
- 基准测试：
  - 使用 `#[bench]` 或 `criterion`
  - 多次运行取平均值
  - 注意编译器优化
- 常见性能陷阱：
  - 不必要的堆分配
  - 过度使用 `clone()`
  - 锁竞争
  - 缓存未命中
  - 虚函数调用（trait object）
- 优化技巧：
  - 使用 `#[inline]`
  - 避免不必要的边界检查
  - 使用 `unsafe` 优化热点代码
  - 使用 `Vec::with_capacity` 预分配
  - 使用 `SmallVec` 优化小集合

---

## 评分标准

### 中等难度编程题目评分（每题 20 分）
- **功能正确性**（10 分）：代码能正确运行，通过所有测试用例
- **代码质量**（5 分）：代码清晰、可读、符合 Rust 惯用法
- **错误处理**（3 分）：正确处理边界情况和错误
- **性能考虑**（2 分）：时间复杂度、空间复杂度合理

### 高难度编程题目评分（每题 30 分）
- **功能正确性**（12 分）：代码能正确运行，通过所有测试用例
- **算法/设计正确性**（8 分）：算法或设计思路正确，考虑周全
- **代码质量**（5 分）：代码清晰、可读、符合 Rust 惯用法
- **安全性**（3 分）：正确处理 `unsafe` 代码（如适用）、内存安全、并发安全
- **性能优化**（2 分）：时间复杂度、空间复杂度合理，考虑零成本抽象

**高难度题目额外考察点：**
- 对底层机制的理解（内存布局、原子操作、异步运行时等）
- 复杂场景的处理能力（并发、内存管理、类型系统等）
- 能否在正确性和性能之间做出权衡
- 对 Rust 高级特性的掌握程度

### 问答题评分（每题 10 分）
- **准确性**（5 分）：答案正确，概念理解准确
- **完整性**（3 分）：覆盖主要要点
- **深度**（2 分）：能够结合实际场景举例说明

---

## 面试建议

### 对于中等难度题目：
1. **编程题目**：
   - 先理解题目要求，确认边界情况
   - 可以先写伪代码，再实现
   - 注意错误处理和边界情况
   - 完成后可以讨论优化方案

### 对于高难度题目：
1. **编程题目**：
   - **理解题目**：充分理解题目要求和约束条件
   - **设计阶段**：先讨论设计思路和算法选择，再开始编码
   - **分步实现**：可以分步骤实现，先实现核心功能，再完善细节
   - **测试驱动**：可以边写边测试，确保每一步都正确
   - **讨论权衡**：完成基础实现后，讨论性能优化、安全性考虑等
   - **诚实沟通**：如果遇到困难，可以说明思路和遇到的问题，展示问题解决过程

2. **问答题**：
   - 先回答核心概念
   - 结合实际代码示例
   - 可以讨论优缺点和适用场景
   - 如果不知道，诚实说明，但可以尝试推理

3. **综合评估**：
   - **代码能力**：能否写出正确、清晰的代码
   - **理解深度**：对 Rust 核心概念和高级特性的理解程度
   - **问题解决**：遇到问题时的调试思路和解决能力
   - **学习能力**：能否快速理解新概念和复杂系统
   - **系统思维**：能否从整体角度思考问题，考虑性能、安全、可维护性等
   - **实践经验**：是否有实际项目经验，能否处理复杂场景

### 题目选择建议：
- **初级候选人**：主要使用中等难度题目，可以选 1-2 道高难度题目作为加分项
- **中级候选人**：中等难度题目 + 2-3 道高难度题目
- **高级候选人**：主要使用高难度题目，可以考察系统设计和架构能力

