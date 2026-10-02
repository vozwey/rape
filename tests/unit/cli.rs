#[test]
fn positional_port_defaults_when_missing() {
    assert_eq!(super::port_from_args(std::iter::empty()).unwrap(), 7187);
}

#[test]
fn positional_port_is_used_when_present() {
    assert_eq!(
        super::port_from_args(["8080".to_owned()].into_iter()).unwrap(),
        8080
    );
}
