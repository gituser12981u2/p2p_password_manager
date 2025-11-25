pub mod node;
pub mod pinset;
pub mod file;

#[cfg(any(
    feature = "mimalloc",
    feature = "mimalloc-secure",
    feature = "mimalloc-v3",
    feature = "mimalloc-v3-secure"
))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(feature = "scudo")]
#[global_allocator]
static GLOBAL: scudo::GlobalScudoAllocator = scudo::GlobalScudoAllocator;

#[cfg(any(feature = "snmalloc", feature = "snmalloc-secure"))]
#[global_allocator]
static GLOBAL: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

#[cfg(feature = "tcmalloc")]
#[global_allocator]
static GLOBAL: tcmalloc::TCMalloc = tcmalloc::TCMalloc;

#[cfg(feature = "rpmalloc")]
#[global_allocator]
static GLOBAL: rpmalloc::RpMalloc = rpmalloc::RpMalloc;
