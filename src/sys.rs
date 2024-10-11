use core::ffi::{c_char, c_int, c_long, c_void};

use typed_jni::{
    sys::{JNIEnv, JNINativeMethod},
    Array, JString, LocalObject,
};

#[cfg(feature = "v2")]
pub const ZYGISK_API_VERSION: c_long = 2;

#[cfg(feature = "v3")]
pub const ZYGISK_API_VERSION: c_long = 3;

#[cfg(feature = "v4")]
pub const ZYGISK_API_VERSION: c_long = 4;

#[repr(C)]
pub struct AppSpecializeArgs<'a> {
    // Required arguments.
    pub uid: &'a mut i32,
    pub gid: &'a mut i32,
    pub gids: &'a mut LocalObject<'a, Array<i32>>,
    pub runtime_flags: &'a mut i32,
    #[cfg(any(feature = "v3", feature = "v4"))]
    pub rlimits: &'a mut LocalObject<'a, Array<Array<i32>>>,
    pub mount_external: &'a mut i32,
    pub se_info: &'a mut LocalObject<'a, JString>,
    pub nice_name: &'a mut LocalObject<'a, JString>,
    pub instruction_set: &'a mut LocalObject<'a, JString>,
    pub app_data_dir: &'a mut LocalObject<'a, JString>,

    // Optional arguments.
    #[cfg(any(feature = "v3", feature = "v4"))]
    pub fds_to_ignore: Option<&'a mut LocalObject<'a, Array<i32>>>,
    pub is_child_zygote: Option<&'a mut bool>,
    pub is_top_app: Option<&'a mut bool>,
    pub pkg_data_info_list: Option<&'a mut Array<JString>>,
    pub whitelisted_data_info_list: Option<&'a mut Array<JString>>,
    pub mount_data_dirs: Option<&'a mut bool>,
    pub mount_storage_dirs: Option<&'a mut bool>,
}

#[repr(C)]
pub struct ServerSpecializeArgs<'a> {
    pub uid: &'a mut i32,
    pub gid: &'a mut i32,
    pub gids: &'a mut LocalObject<'a, Array<i32>>,
    pub runtime_flags: &'a mut i32,
    pub permitted_capabilities: &'a mut i64,
    pub effective_capabilities: &'a mut i64,
}

pub type ModuleOption = c_int;

pub const MODULE_OPTION_DENYLIST_UNMOUNT: ModuleOption = 0;
pub const MODULE_OPTION_DLCLOSE_MODULE_LIBRARY: ModuleOption = 1;

pub type StateFlags = u32;

pub const STATE_FLAG_PROCESS_GRANTED_ROOT: StateFlags = 1 << 0;
pub const STATE_FLAG_PROCESS_ON_DENYLIST: StateFlags = 1 << 1;

#[repr(C)]
pub struct ModuleAbi {
    pub api_version: c_long,
    pub module_impl: *mut c_void,

    pub pre_app_specialize: unsafe extern "C" fn(*mut c_void, *mut AppSpecializeArgs),
    pub post_app_specialize: unsafe extern "C" fn(*mut c_void, *const AppSpecializeArgs),
    pub pre_server_specialize: unsafe extern "C" fn(*mut c_void, *mut ServerSpecializeArgs),
    pub post_server_specialize: unsafe extern "C" fn(*mut c_void, *const ServerSpecializeArgs),
}

#[repr(C)]
pub struct ApiTable {
    pub api_impl: *mut c_void,
    pub register_module: unsafe extern "C" fn(*mut ApiTable, *mut ModuleAbi) -> c_int,
    pub hook_jni_native_methods: Option<unsafe extern "C" fn(*mut JNIEnv, *const c_char, *mut JNINativeMethod, c_int)>,
    #[cfg(any(feature = "v2", feature = "v3"))]
    pub plt_hook_register: Option<unsafe extern "C" fn(*const c_char, *const c_char, *const c_void, *mut *const c_void)>,
    #[cfg(any(feature = "v2", feature = "v3"))]
    pub plt_hook_exclude: Option<unsafe extern "C" fn(*const c_char, *const c_char)>,
    #[cfg(feature = "v4")]
    pub plt_hook_register: Option<unsafe extern "C" fn(libc::dev_t, libc::ino_t, *const c_void, *mut *const c_void)>,
    #[cfg(feature = "v4")]
    pub exempt_fd: Option<unsafe extern "C" fn(c_int) -> bool>,
    pub plt_hook_commit: Option<unsafe extern "C" fn() -> bool>,
    pub connect_companion: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    pub set_option: Option<unsafe extern "C" fn(*mut c_void, ModuleOption)>,
    pub get_module_dir: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    pub get_flags: Option<unsafe extern "C" fn(*mut c_void) -> StateFlags>,
}
