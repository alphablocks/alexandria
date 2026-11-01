use crate::{check, Result};
use windows::{
    core::{factory, HSTRING},
    Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    },
    Win32::{
        Foundation::HWND,
        System::WinRT::{
            IUserConsentVerifierInterop, RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED,
        },
    },
};
/// Desktop HWND interop is required; the UWP-only prompt is not a fallback.
pub fn verify_owner(hwnd: isize) -> Result<()> {
    check(hwnd != 0, "OWNER_VERIFICATION_UNAVAILABLE")?;
    std::thread::spawn(move || -> Result<()> {
        unsafe {
            RoInitialize(RO_INIT_MULTITHREADED)?;
        }
        let result = (|| {
            check(
                UserConsentVerifier::CheckAvailabilityAsync()?.get()?
                    == UserConsentVerifierAvailability::Available,
                "OWNER_VERIFICATION_UNAVAILABLE",
            )?;
            let interop: IUserConsentVerifierInterop =
                factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
            let op: windows_future::IAsyncOperation<UserConsentVerificationResult> = unsafe {
                interop.RequestVerificationForWindowAsync(
                    HWND(hwnd as *mut _),
                    &HSTRING::from("Unlock your local Alexandria vault"),
                )?
            };
            check(
                op.get()? == UserConsentVerificationResult::Verified,
                "OWNER_VERIFICATION_DENIED",
            )
        })();
        unsafe {
            RoUninitialize();
        }
        result
    })
    .join()
    .map_err(|_| crate::Error("OWNER_VERIFICATION_UNAVAILABLE"))?
}
