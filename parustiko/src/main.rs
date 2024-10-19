// Only for testling develop
use parustiko;

fn main() {
    match parustiko::runner() {
        Err(e) => {
            println!("{:?}", e);
        }
        _ => {}
    }
}
