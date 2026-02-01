use rama::{
    http::headers::specifier::{Quality, QualityValue},
    utils::collections::{NonEmptyVec, non_empty_vec},
};

rama::utils::macros::enums::enum_builder! {
    /// Some of the products we support and which to support
    /// explicitly in the benchmarks
    @String
    pub enum Product {
        /// No product
        None => "none" | "-",
        /// Visual Studio Code
        VSCode => "vscode",
        /// Python Package Index
        PyPI => "pypi",
    }
}

pub fn parse_product_values(input: &str) -> Result<ProductValues, String> {
    let result: Result<Vec<QualityValue<Product>>, _> = input
        .split(",")
        .filter(|&s| !s.is_empty())
        .map(|s| s.parse())
        .collect();
    match result {
        Ok(values) => NonEmptyVec::try_from(values).map_err(|err| err.to_string()),
        Err(err) => Err(err.to_string()),
    }
}

/// Ratio of product values to be used for generating tests
pub type ProductValues = NonEmptyVec<QualityValue<Product>>;

/// Default [`ProductValues`] used in case none are defined in cli args.
pub fn default_product_values() -> ProductValues {
    non_empty_vec![
        QualityValue::new(Product::None, Quality::one()),
        QualityValue::new(Product::VSCode, Quality::new_clamped(100)),
        QualityValue::new(Product::PyPI, Quality::new_clamped(100)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_product_values() {
        for (input, expected) in [
            (
                "-",
                Some(non_empty_vec![QualityValue::new_value(Product::None)]),
            ),
            (
                "-; q=0.1",
                Some(non_empty_vec![QualityValue::new(
                    Product::None,
                    Quality::new_clamped(100)
                )]),
            ),
            (
                "none; q=0.8, vscode; q=0.2",
                Some(non_empty_vec![
                    QualityValue::new(Product::None, Quality::new_clamped(800)),
                    QualityValue::new(Product::VSCode, Quality::new_clamped(200))
                ]),
            ),
        ] {
            let result = parse_product_values(input);
            match (result, expected) {
                (Ok(result), Some(expected)) => assert_eq!(result, expected, "input: '{input}'"),
                (Err(_), None) => (),
                (result, expected) => panic!(
                    "input = '{input}', unexpected result '{result:?}', expected: '{expected:?}'"
                ),
            }
        }
    }
}
