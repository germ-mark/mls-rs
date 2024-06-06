
uniffi::setup_scaffolding!();

use mls_rs_crypto_cryptokit::CryptoKitProvider;

 pub struct Client {

 }

 impl Client {
     pub fn new () -> Self {
         let crypto_provider = CryptoKitProvider::default();

         Client {}
     }
 }

//boilerplate
pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
