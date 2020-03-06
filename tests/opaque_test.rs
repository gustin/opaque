extern crate opaque;

#[test]
fn test_protocol() {
    let username = "jerrg";
    let password = "onelonelyhead";

    let (alpha, pub_u, priv_u) = opaque::client::registration_start(&password);
    let (beta, v, pub_s) = opaque::registration_start(&username, &alpha);
}
