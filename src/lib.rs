use std::{
    ffi::{c_int, c_void, CString},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    ptr::null_mut,
};

use jni_sys::{JNIEnv, JNINativeMethod};

pub use sys::{AppSpecializeArgs, ServerSpecializeArgs};

mod sys;

pub enum ModuleOption {
    ForceDenylistUnmount = sys::MODULE_OPTION_DENYLIST_UNMOUNT as isize,
    DlcloseModuleLibrary = sys::MODULE_OPTION_DLCLOSE_MODULE_LIBRARY as isize,
}

pub struct StateFlags {
    value: sys::StateFlags,
}

impl StateFlags {
    pub fn is_process_granted_root(&self) -> bool {
        self.value & sys::STATE_FLAG_PROCESS_GRANTED_ROOT != 0
    }

    pub fn is_process_on_denylist(&self) -> bool {
        self.value & sys::STATE_FLAG_PROCESS_ON_DENYLIST != 0
    }
}

pub struct Api {
    table: &'static sys::ApiTable,
}

unsafe impl Send for Api {}

unsafe impl Sync for Api {}

impl Api {
    unsafe fn new(table: *const sys::ApiTable) -> Api {
        Api { table: &*table }
    }
}

impl Api {
    pub fn connect_companion(&self) -> Option<UnixStream> {
        unsafe {
            if let Some(c) = self.table.connect_companion {
                let fd = c(self.table.api_impl);
                if fd >= 0 {
                    Some(UnixStream::from_raw_fd(fd))
                } else {
                    None
                }
            } else {
                None
            }
        }
    }

    pub fn get_module_dir(&self) -> Option<OwnedFd> {
        unsafe {
            if let Some(f) = self.table.get_module_dir {
                let fd = f(self.table.api_impl);
                if fd >= 0 {
                    Some(OwnedFd::from_raw_fd(fd))
                } else {
                    None
                }
            } else {
                None
            }
        }
    }

    pub fn set_option(&self, option: ModuleOption) {
        unsafe {
            if let Some(f) = self.table.set_option {
                f(self.table.api_impl, option as isize as sys::ModuleOption)
            }
        }
    }

    pub fn get_flags(&self) -> StateFlags {
        unsafe {
            if let Some(f) = self.table.get_flags {
                let flags = f(self.table.api_impl);

                StateFlags { value: flags }
            } else {
                StateFlags {
                    value: Default::default(),
                }
            }
        }
    }

    pub fn hook_jni_native_methods(
        &self,
        env: *mut JNIEnv,
        class_name: impl AsRef<str>,
        mut methods: impl AsMut<[JNINativeMethod]>,
    ) {
        unsafe {
            if let Some(f) = self.table.hook_jni_native_methods {
                let class_name = CString::new(class_name.as_ref()).unwrap();

                f(
                    env,
                    class_name.as_ptr(),
                    methods.as_mut().as_mut_ptr(),
                    methods.as_mut().len() as c_int,
                );
            }
        }
    }

    #[cfg(any(feature = "v2", feature = "v3"))]
    pub fn plt_hook_register(
        &self,
        regex: impl AsRef<str>,
        symbol: impl AsRef<str>,
        new_func: *const (),
        old_func: *mut *const (),
    ) {
        unsafe {
            if let Some(f) = self.table.plt_hook_register {
                let regex = CString::new(regex.as_ref()).unwrap();
                let symbol = CString::new(symbol.as_ref()).unwrap();

                f(regex.as_ptr(), symbol.as_ptr(), new_func.cast(), old_func.cast())
            }
        }
    }

    #[cfg(any(feature = "v2", feature = "v3"))]
    pub fn plt_hook_exclude(&self, regex: impl AsRef<str>, symbol: impl AsRef<str>) {
        unsafe {
            if let Some(f) = self.table.plt_hook_exclude {
                let regex = CString::new(regex.as_ref()).unwrap();
                let symbol = CString::new(symbol.as_ref()).unwrap();

                f(regex.as_ptr(), symbol.as_ptr())
            }
        }
    }

    #[cfg(feature = "v4")]
    pub fn plt_hook_register(&self, dev: libc::dev_t, inode: libc::ino_t, new_func: *const (), old_func: *mut *const ()) {
        unsafe {
            if let Some(f) = self.table.plt_hook_register {
                f(dev, inode, new_func.cast(), old_func.cast())
            }
        }
    }

    #[cfg(feature = "v4")]
    pub fn exempt_fd(&self, fd: std::os::fd::RawFd) -> bool {
        unsafe {
            if let Some(f) = self.table.exempt_fd {
                f(fd)
            } else {
                false
            }
        }
    }

    pub unsafe fn plt_hook_commit(&self) -> bool {
        if let Some(f) = self.table.plt_hook_commit {
            f()
        } else {
            false
        }
    }
}

pub trait ModuleTable {
    fn pre_app_specialize(&mut self, args: &AppSpecializeArgs);
    fn post_app_specialize(&mut self, args: &AppSpecializeArgs);
    fn pre_server_specialize(&mut self, args: &ServerSpecializeArgs);
    fn post_server_specialize(&mut self, args: &ServerSpecializeArgs);
}

pub trait Module: ModuleTable {
    fn new(api: Api, env: *mut JNIEnv) -> Self;
}

#[macro_export]
macro_rules! register_zygisk_module {
    ($module:ty) => {
        #[no_mangle]
        pub extern "C" fn zygisk_module_entry(api_table: *mut ::std::ffi::c_void, env: *mut ::jni_sys::JNIEnv) {
            $crate::module_entry::<$module>(api_table.cast(), env)
        }
    };
}

#[macro_export]
macro_rules! register_zygisk_companion {
    ($handler:path) => {
        #[no_mangle]
        pub extern "C" fn zygisk_companion_entry(client: ::std::ffi::c_int) {
            $crate::companion_entry(client, $handler)
        }
    };
}

#[doc(hidden)]
pub fn module_entry<M: Module>(api_table: *mut sys::ApiTable, env: *mut JNIEnv) {
    let module_table = sys::ModuleAbi {
        api_version: sys::ZYGISK_API_VERSION,
        module_impl: null_mut(),
        pre_app_specialize: {
            unsafe extern "C" fn func(this: *mut c_void, args: *const AppSpecializeArgs) {
                if let Some(this) = this.cast::<Box<dyn ModuleTable>>().as_mut() {
                    this.pre_app_specialize(&*args);
                }
            }

            func
        },
        post_app_specialize: {
            unsafe extern "C" fn func(this: *mut c_void, args: *const AppSpecializeArgs) {
                if let Some(this) = this.cast::<Box<dyn ModuleTable>>().as_mut() {
                    this.post_app_specialize(&*args);
                }
            }

            func
        },
        pre_server_specialize: {
            unsafe extern "C" fn func(this: *mut c_void, args: *const ServerSpecializeArgs) {
                if let Some(this) = this.cast::<Box<dyn ModuleTable>>().as_mut() {
                    this.pre_server_specialize(&*args);
                }
            }

            func
        },
        post_server_specialize: {
            unsafe extern "C" fn func(this: *mut c_void, args: *const ServerSpecializeArgs) {
                if let Some(this) = this.cast::<Box<dyn ModuleTable>>().as_mut() {
                    this.post_server_specialize(&*args);
                }
            }

            func
        },
    };

    let module_table = Box::into_raw(Box::new(module_table));
    unsafe {
        if ((*api_table).register_module)(api_table, module_table) == 0 {
            return;
        }

        let module: Box<Box<dyn ModuleTable>> = Box::new(Box::new(M::new(Api::new(api_table), env)));
        (*module_table).module_impl = Box::into_raw(module).cast();
    }
}

#[doc(hidden)]
pub fn companion_entry(client: c_int, handler: fn(stream: UnixStream)) {
    unsafe {
        let nfd = libc::dup(client);
        if nfd >= 0 {
            handler(UnixStream::from_raw_fd(nfd))
        }
    }
}
