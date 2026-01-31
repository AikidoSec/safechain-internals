mod pragmatic_semver {
    use crate::firewall::version::{PragmaticSemver, PragmaticSemverParseError};

    #[track_caller]
    fn version(text: &str, v: PragmaticSemver) {
        assert_eq!(v, PragmaticSemver::parse(text).unwrap())
    }

    #[track_caller]
    fn version_err_empty_string(text: &str) {
        assert_eq!(
            PragmaticSemverParseError::EmptyString,
            PragmaticSemver::parse(text).unwrap_err(),
        )
    }

    #[track_caller]
    fn version_err_overflow_number(text: &str) {
        assert_eq!(
            PragmaticSemverParseError::OverflowNumber,
            PragmaticSemver::parse(text).unwrap_err()
        )
    }

    #[track_caller]
    fn version_err_unexpected_number_end(text: &str) {
        assert_eq!(
            PragmaticSemverParseError::UnexpectedNumberEnd,
            PragmaticSemver::parse(text).unwrap_err()
        )
    }

    #[test]
    fn test_parse() {
        version_err_empty_string("");
        version_err_empty_string("  ");

        version("1", PragmaticSemver::new_single(1));
        version("v1", PragmaticSemver::new_single(1).with_prefix("v"));
        version("v 1", PragmaticSemver::new_single(1).with_prefix("v"));
        version("r1", PragmaticSemver::new_single(1).with_prefix("r"));
        version("r 1", PragmaticSemver::new_single(1).with_prefix("r"));
        version("01", PragmaticSemver::new_single(1));
        version("1.", PragmaticSemver::new_single(1));
        version("1.2", PragmaticSemver::new_two_components(1, 2));
        version("01.002", PragmaticSemver::new_two_components(1, 2));
        version("1.2.", PragmaticSemver::new_two_components(1, 2));
        version("1.2.3", PragmaticSemver::new_semver(1, 2, 3));
        version("1.2.3.", PragmaticSemver::new_semver(1, 2, 3));
        version("0001.002.03.", PragmaticSemver::new_semver(1, 2, 3));
        version("1.2.3.4", PragmaticSemver::new_four_components(1, 2, 3, 4));
        version("1.2.3.4.", PragmaticSemver::new_four_components(1, 2, 3, 4));
        version(
            "1.2.3.4.5",
            PragmaticSemver::new_five_components(1, 2, 3, 4, 5),
        );
        version(
            "1.2.3.4.5.",
            PragmaticSemver::new_five_components(1, 2, 3, 4, 5),
        );

        version("1.2.3.", PragmaticSemver::new_semver(1, 2, 3));

        version("1.2.3.", PragmaticSemver::new_semver(1, 2, 3));
        version("1.2.3-", PragmaticSemver::new_semver(1, 2, 3));

        version_err_unexpected_number_end("a.b.c");
        version("0.b.c", PragmaticSemver::new_zeroed().with_pre("b.c"));
        version(
            "0.1.c",
            PragmaticSemver::new_two_components(0, 1).with_pre("c"),
        );

        version(
            "1.2.3 abc",
            PragmaticSemver::new_semver(1, 2, 3).with_pre("abc"),
        );
        version(
            "v1.0.0-alpha.1",
            PragmaticSemver::new_semver(1, 0, 0)
                .with_pre("alpha.1")
                .with_prefix("v"),
        );
        version(
            "1.2.3-01",
            PragmaticSemver::new_semver(1, 2, 3).with_pre("01"),
        );
        version("1.2.3-----", PragmaticSemver::new_semver(1, 2, 3));
        version("1.2.3+++", PragmaticSemver::new_semver(1, 2, 3));

        version_err_overflow_number("111111111111111111111.0.0");

        version("8\0", PragmaticSemver::new_single(8).with_pre("\0"));

        version(
            "1.2.3-alpha1",
            PragmaticSemver::new_semver(1, 2, 3).with_pre("alpha1"),
        );
        version(
            "1.2.3-alpha-1",
            PragmaticSemver::new_semver(1, 2, 3).with_pre("alpha-1"),
        );

        version(
            "1.2.3+build5",
            PragmaticSemver::new_semver(1, 2, 3).with_build("build5"),
        );
        version(
            "1.2.3+build+5",
            PragmaticSemver::new_semver(1, 2, 3).with_build("build+5"),
        );
        version(
            "1.2.3+5build",
            PragmaticSemver::new_semver(1, 2, 3).with_build("5build"),
        );

        version(
            "1.2.3-alpha1+build5",
            PragmaticSemver::new_semver(1, 2, 3)
                .with_pre("alpha1")
                .with_build("build5"),
        );

        version(
            "1.2.3-1.alpha1.9+build5.7.3aedf",
            PragmaticSemver::new_semver(1, 2, 3)
                .with_pre("1.alpha1.9")
                .with_build("build5.7.3aedf"),
        );
        version(
            "1.2.3-1.0a.alpha1.9+05build5.7.3aedf",
            PragmaticSemver::new_semver(1, 2, 3)
                .with_pre("1.0a.alpha1.9")
                .with_build("05build5.7.3aedf"),
        );
        version(
            "0.4.0-beta.1+0851523",
            PragmaticSemver::new_semver(0, 4, 0)
                .with_pre("beta.1")
                .with_build("0851523"),
        );
        version(
            "0.4.0-beta.1+0851523",
            PragmaticSemver::new_semver(0, 4, 0).with_pre("beta.1"),
        );

        // for https://nodejs.org/dist/index.json, where some older npm versions are "1.1.0-beta-10"
        version(
            "1.1.0-beta-10",
            PragmaticSemver::new_semver(1, 1, 0).with_pre("beta-10"),
        );
    }

    #[test]
    fn test_eq() {
        for (a, b) in [
            ("1.2.3", "1.2.3"),
            ("1.2.3-alpha1", "1.2.3-alpha1"),
            ("1.2.3-ALPHA1", "1.2.3-alpha1"),
            ("1.2.3-alpha1", "1.2.3-ALPHA1"),
            ("1.2.3+build.42", "1.2.3+build.42"),
            ("1.2.3+build.42", "1.2.3+"),
            ("1.2.3+build.42", "1.2.3"),
            ("1.2.3+23", "1.2.3+42"),
            ("1.2.3+build", "1.2.3+build.42"),
            ("1.2.3", "1.2.3+build.42"),
            ("1.2.3-alpha1+42", "1.2.3-alpha1+42"),
            ("1.2.3-alpha1+42", "1.2.3-alpha1"),
            ("1.2.3-alpha1", "1.2.3-alpha1"),
        ] {
            let parsed_a = PragmaticSemver::parse(a).expect(a);
            let parsed_b = PragmaticSemver::parse(b).expect(b);
            assert_eq!(parsed_a, parsed_b, "{a} == {b}");
        }
    }

    #[test]
    fn test_ne() {
        for (a, b) in [
            ("0.0.0", "0.0.1"),
            ("0.0.0", "0.1.0"),
            ("0.0.0", "1.0.0"),
            ("0.0.1", "0.0.0"),
            ("0.1.0", "0.0.0"),
            ("1.0.0", "0.0.0"),
            ("1.2.3-alpha", "1.2.3-beta"),
        ] {
            let parsed_a = PragmaticSemver::parse(a).expect(a);
            let parsed_b = PragmaticSemver::parse(b).expect(b);
            assert_ne!(parsed_a, parsed_b, "{a} != {b}");
        }
    }

    #[test]
    fn test_lt_and_gt() {
        for (a, b) in [
            ("0", "1.2.3-alpha2"),
            ("0.0", "1.2.3-alpha2"),
            ("0.0.0", "1.2.3-alpha2"),
            ("1", "1.2.3-alpha2"),
            ("1.0", "1.2.3-alpha2"),
            ("1.0.0", "1.2.3-alpha2"),
            ("1.2.0", "1.2.3-alpha2"),
            ("1.2.3-alpha1", "1.2.3"),
            ("1.2.3-alpha1", "1.2.3-alpha2"),
        ] {
            let parsed_a = PragmaticSemver::parse(a).expect(a);
            let parsed_b = PragmaticSemver::parse(b).expect(b);

            assert!(parsed_a < parsed_b, "{a} < {b}");
            assert!(parsed_b > parsed_a, "{b} > {a}");
        }
    }

    #[test]
    fn test_le_and_ge() {
        for (a, b) in [
            ("1.2", "1.2.0"),
            ("0.0.0", "1.2.3-alpha2"),
            ("1.0.0", "1.2.3-alpha2"),
            ("1.2.0", "1.2.3-alpha2"),
            ("1.2.3-alpha1", "1.2.3"),
            ("1.2.3-alpha1", "1.2.3-alpha2"),
            ("1.2.3-alpha2", "1.2.3-alpha2"),
            ("1.2.3-alpha2", "1.2.3-alpha2+build"),
            ("1.2.3-alpha2+build", "1.2.3-alpha2"),
        ] {
            let parsed_a = PragmaticSemver::parse(a).expect(a);
            let parsed_b = PragmaticSemver::parse(b).expect(b);

            assert!(parsed_a <= parsed_b, "{a} <= {b}");
            assert!(parsed_b >= parsed_a, "{b} >= {a}");
        }
    }
}

mod package_version {
    use rama::utils::str::arcstr::arcstr;

    use crate::firewall::version::{PackageVersion, PragmaticSemver};

    #[test]
    fn test_eq() {
        for (version_a, version_b, is_eq) in [
            (PackageVersion::Any, PackageVersion::Any, true),
            (
                PackageVersion::Unknown(arcstr!("foo")),
                PackageVersion::Any,
                true,
            ),
            (
                PackageVersion::Any,
                PackageVersion::Unknown(arcstr!("foo")),
                true,
            ),
            (PackageVersion::Any, PackageVersion::None, true),
            (
                PackageVersion::Unknown(arcstr!("foo")),
                PackageVersion::Unknown(arcstr!("foo")),
                true,
            ),
            (
                PackageVersion::Unknown(arcstr!("foo")),
                PackageVersion::Unknown(arcstr!(" foo")),
                true,
            ),
            (
                PackageVersion::Unknown(arcstr!("foo")),
                PackageVersion::Unknown(arcstr!("foo ")),
                true,
            ),
            (
                PackageVersion::Unknown(arcstr!("Foo")),
                PackageVersion::Unknown(arcstr!("foo")),
                true,
            ),
            (
                PackageVersion::Unknown(arcstr!("foo")),
                PackageVersion::Unknown(arcstr!("Foo")),
                true,
            ),
            (
                PackageVersion::Unknown(arcstr!("foo ")),
                PackageVersion::Unknown(arcstr!(" Foo")),
                true,
            ),
            (
                PackageVersion::Unknown(arcstr!("foo")),
                PackageVersion::Unknown(arcstr!("hello")),
                false,
            ),
            (
                PackageVersion::Semver(PragmaticSemver::new_semver(1, 2, 3)),
                PackageVersion::Unknown(arcstr!("hello")),
                false,
            ),
            (
                PackageVersion::Unknown(arcstr!("hello")),
                PackageVersion::Semver(PragmaticSemver::new_semver(1, 2, 3)),
                false,
            ),
            (
                PackageVersion::Semver(PragmaticSemver::new_semver(4, 2, 3)),
                PackageVersion::Semver(PragmaticSemver::new_semver(4, 2, 3)),
                true,
            ),
            (
                PackageVersion::Semver(PragmaticSemver::new_semver(1, 2, 3)),
                PackageVersion::Semver(PragmaticSemver::new_semver(2, 2, 3)),
                false,
            ),
            (
                PackageVersion::Semver(PragmaticSemver::new_semver(1, 2, 3)),
                PackageVersion::Semver(PragmaticSemver::new_semver(1, 2, 4)),
                false,
            ),
        ] {
            if is_eq {
                assert_eq!(version_a, version_b);
            } else {
                assert_ne!(version_a, version_b);
            }
        }
    }

    #[test]
    fn test_display() {
        let v1_0_0 = PackageVersion::Semver(PragmaticSemver::new_semver(1, 0, 0));
        assert_eq!(format!("{}", v1_0_0), "1.0.0");

        let v2_3_4 = PackageVersion::Semver(PragmaticSemver::new_semver(2, 3, 4));
        assert_eq!(format!("{}", v2_3_4), "2.3.4");

        let v10_5_1 = PackageVersion::Semver(PragmaticSemver::new_semver(10, 5, 1));
        assert_eq!(format!("{}", v10_5_1), "10.5.1");

        let v0_1_0 = PackageVersion::Semver(PragmaticSemver::new_semver(0, 1, 0));
        assert_eq!(format!("{}", v0_1_0), "0.1.0");

        let alpha_version =
            PackageVersion::Semver(PragmaticSemver::new_semver(1, 2, 3).with_pre("alpha.1"));
        assert_eq!(format!("{}", alpha_version), "1.2.3-alpha.1");

        let beta_version =
            PackageVersion::Semver(PragmaticSemver::new_semver(2, 0, 0).with_pre("beta.2"));
        assert_eq!(format!("{}", beta_version), "2.0.0-beta.2");

        let prefixed_semver = PackageVersion::Semver(
            PragmaticSemver::new_semver(1, 0, 0)
                .with_pre("snapshot-20240130")
                .with_prefix("v"),
        );
        assert_eq!(format!("{}", prefixed_semver), "v1.0.0-snapshot-20240130");

        let none_version = PackageVersion::None;
        assert_eq!(format!("{}", none_version), "");

        let any_version = PackageVersion::Any;
        assert_eq!(format!("{}", any_version), "*");

        let custom_version = PackageVersion::Unknown(arcstr!("ver 3A"));
        assert_eq!(format!("{}", custom_version), "ver 3A");
    }
}
