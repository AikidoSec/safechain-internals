use rama::error::BoxError;

use crate::Args;

pub async fn init_platform(_args: Args) -> Result<(), BoxError> {
    Err(BoxError::from(
        "MacOS is not yet supported! Please try another platform.",
    ))
}
