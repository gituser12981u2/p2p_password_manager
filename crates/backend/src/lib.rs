pub mod node;
pub mod pinset;




#[cfg(any(feature = "mimalloc", feature = "mimalloc-secure"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature="jemallocator")]
#[global_allocator]
static GLOBAL:jemallocator::Jemalloc=jemallocator::Jemalloc;

#[cfg(feature="scudo")]
#[global_allocator]
static GLOBAL:scudo::GlobalScudoAllocator=scudo::GlobalScudoAllocator;

#[cfg(feature="snmalloc")]
#[global_allocator]
static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;