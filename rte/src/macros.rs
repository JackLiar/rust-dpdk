pub const BOOL_TRUE: u8 = 1;
pub const BOOL_FALSE: u8 = 0;

#[macro_export]
macro_rules! bool_value {
    ($b:expr) => ( if $b { $crate::macros::BOOL_TRUE } else { $crate::macros::BOOL_FALSE } )
}

#[macro_export]
macro_rules! cstr {
    ($s:expr) => (
        ::std::ffi::CString::new($s).unwrap().as_ptr() as *const i8
    )
}

#[macro_export]
macro_rules! try_cstr {
    ($s:expr) => (
        try!(::std::ffi::CString::new($s.to_string())).as_ptr() as *const i8
    )
}

#[macro_export]
macro_rules! ptr_as_ref {
    ($p:expr) => (if ($p).is_null() { None } else { Some(unsafe {&* ($p)}) })
}

#[macro_export]
macro_rules! ptr_as_mut_ref {
    ($p:expr) => (if ($p).is_null() { None } else { Some(unsafe {&mut * ($p)}) })
}

/// Macro to get the offset of a struct field in bytes from the address of the
/// struct.
///
/// This macro is identical to `offset_of!` but doesn't give a warning about
/// unnecessary unsafe blocks when invoked from unsafe code.
#[macro_export]
macro_rules! offset_of_unsafe {
    ($container:path, $field:ident) => {{
        // Make sure the field exists, otherwise this could result in UB if the
        // field is accessed through Deref. This will cause a null dereference
        // at runtime since the offset can't be reduced to a constant.
        let $container { $field : _, .. };

        // Yes, this is technically derefencing a null pointer. However, Rust
        // currently accepts this and reduces it to a constant, even in debug
        // builds!
        &(*(0 as *const $container)).$field as *const _ as isize
    }};
}

/// Macro to get the offset of a struct field in bytes from the address of the
/// struct.
///
/// This macro will cause a warning if it is invoked in an unsafe block. Use the
/// `offset_of_unsafe` macro instead to avoid this warning.
#[macro_export]
macro_rules! offset_of {
    ($container:path, $field:ident) => {
        unsafe { offset_of_unsafe!($container, $field) }
    };
}
