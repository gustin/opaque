extern crate opaque;

#[test]
fn test_protocol() {
    let username = "jerrg";
    let password = "onelonelyhead";

    let (alpha, keypair, pub_u, priv_u, r) =
        opaque::client::registration_start(&password);
    let (beta, v, pub_s) = opaque::registration_start(&username, &alpha);

    let envelope = opaque::client::registration_finalize(
        &password, &beta, &v, &pub_u, &pub_s, &priv_u, &r
    );
    opaque::registration_finalize(&username, &pub_u, &envelope);

    let (alpha, ke_1, x, r) =
        opaque::client::authenticate_start(&username, &password);
    let (beta, v, envelope, ke_2, y) =
        opaque::authenticate_start(&username, &alpha, &ke_1);

    let ke_3 = opaque::client::authenticate_finalize(
        &password, &keypair, &envelope, &beta, &v, &ke_2, &x, &y, &r,
    );
    opaque::authenticate_finalize(&username, &ke_3, &x);
}
