use super::SystemDuration;

#[test]
fn constructors_produce_expected_user_facing_durations() {
    assert_eq!(SystemDuration::milliseconds(250), SystemDuration(250));
    assert_eq!(SystemDuration::seconds(1), SystemDuration(1_000));
    assert_eq!(SystemDuration::minutes(1), SystemDuration::seconds(60));
    assert_eq!(SystemDuration::hours(1), SystemDuration::minutes(60));
    assert_eq!(SystemDuration::days(1), SystemDuration::hours(24));
    assert_eq!(SystemDuration::weeks(1), SystemDuration::days(7));
}

#[test]
fn larger_units_match_equivalent_smaller_units() {
    assert_eq!(SystemDuration::minutes(5), SystemDuration::seconds(5 * 60));
    assert_eq!(SystemDuration::hours(3), SystemDuration::minutes(3 * 60));
    assert_eq!(SystemDuration::days(2), SystemDuration::hours(2 * 24));
    assert_eq!(SystemDuration::weeks(4), SystemDuration::days(4 * 7));
}

#[test]
fn zero_is_supported_for_all_units() {
    let zero = SystemDuration(0);

    assert_eq!(SystemDuration::milliseconds(0), zero);
    assert_eq!(SystemDuration::seconds(0), zero);
    assert_eq!(SystemDuration::minutes(0), zero);
    assert_eq!(SystemDuration::hours(0), zero);
    assert_eq!(SystemDuration::days(0), zero);
    assert_eq!(SystemDuration::weeks(0), zero);
}

#[test]
fn common_real_world_durations_are_easy_to_verify() {
    assert_eq!(SystemDuration::seconds(30), SystemDuration(30_000));
    assert_eq!(
        SystemDuration::minutes(15),
        SystemDuration::seconds(15 * 60)
    );
    assert_eq!(SystemDuration::hours(24), SystemDuration::days(1));
    assert_eq!(SystemDuration::days(14), SystemDuration::weeks(2));
}
