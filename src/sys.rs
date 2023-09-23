use std::ffi::{c_char, c_int, c_long, c_void};

use jni_sys::{jboolean, jint, jintArray, jlong, jobjectArray, jstring, JNIEnv, JNINativeMethod};

#[cfg(feature = "v2")]
pub const ZYGISK_API_VERSION: c_long = 2;

#[cfg(feature = "v3")]
pub const ZYGISK_API_VERSION: c_long = 3;

#[cfg(feature = "v4")]
pub const ZYGISK_API_VERSION: c_long = 4;

#[repr(C)]
pub struct AppSpecializeArgs<'a> {
    // Required arguments.
    pub uid: &'a mut jint,
    pub gid: &'a mut jint,
    pub gids: &'a mut jintArray,
    pub runtime_flags: &'a mut jint,
    #[cfg(any(feature = "v3", feature = "v4"))]
    pub rlimits: &'a mut jobjectArray,
    pub mount_external: &'a mut jint,
    pub se_info: &'a mut jstring,
    pub nice_name: &'a mut jstring,
    pub instruction_set: &'a mut jstring,
    pub app_data_dir: &'a mut jstring,

    // Optional arguments.
    #[cfg(any(feature = "v3", feature = "v4"))]
    pub fds_to_ignore: Option<&'a mut jintArray>,
    pub is_child_zygote: Option<&'a mut jboolean>,
    pub is_top_app: Option<&'a mut jboolean>,
    pub pkg_data_info_list: Option<&'a mut jobjectArray>,
    pub whitelisted_data_info_list: Option<&'a mut jobjectArray>,
    pub mount_data_dirs: Option<&'a mut jboolean>,
    pub mount_storage_dirs: Option<&'a mut jboolean>,
}

#[repr(C)]
pub struct ServerSpecializeArgs<'a> {
    pub uid: &'a mut jint,
    pub gid: &'a mut jint,
    pub gids: &'a mut jintArray,
    pub runtime_flags: &'a mut jint,
    pub permitted_capabilities: &'a mut jlong,
    pub effective_capabilities: &'a mut jlong,
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

    pub pre_app_specialize: unsafe extern "C" fn(*mut c_void, *const AppSpecializeArgs),
    pub post_app_specialize: unsafe extern "C" fn(*mut c_void, *const AppSpecializeArgs),
    pub pre_server_specialize: unsafe extern "C" fn(*mut c_void, *const ServerSpecializeArgs),
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
