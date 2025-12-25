use rust_utee::trace_print;

// #[unsafe(no_mangle)]
fn main() {
    let s = String::from("Hello, world!");
    trace_print!("{}", s);
}
