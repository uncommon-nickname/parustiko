fn main() {
    match parustiko::runner() {
        Err(e) => {
            println!("{:?}", e);
        }
        _ => {}
    }
}
