use winapi;
use winapi::shared::minwindef::*;
use winapi::shared::winerror::*;
use winapi::shared::ntdef::*;
use winapi::um::sysinfoapi::*;
use winapi::um::wow64apiset::*;
use winapi::um::libloaderapi::*;
use winapi::um::errhandlingapi::*;
use winapi::um::winnt::DLL_PROCESS_ATTACH;
use std::string;
use std::ffi;
use std::mem;
use std::vec;
use widestring;
use std::sync;
use std::thread;
use std::time;
use wchar;
use std::io::{Read,stdin};
use std::fs;
use std::fmt::{Error, Write};

fn get_real_version_handle()->HMODULE{
    static mut DLL_MODULE : HMODULE = 0 as HMODULE;
    static INIT: sync::Once = sync::Once::new();
    unsafe{
        INIT.call_once(||{
            DLL_MODULE = get_sys_dir_dll_module("version.dll");
        });
        DLL_MODULE
    }
}
fn get_module_handle(name : &str)->HMODULE{
    let module = unsafe{GetModuleHandleW(widestring::U16String::from_str(name).as_ptr())};
    module
}
fn get_sys_dir_dll_module(name : &str)->HMODULE{
    let mut buffer :  [u16;512] = [0;512];
    if std::mem::size_of::<LPVOID>() == 4{
        let ret : DWORD = unsafe{GetSystemWow64DirectoryW(buffer.as_mut_ptr(), buffer.len() as u32)};
        if ret > 512 || ret == 0{
            return NULL as HMODULE;
        }
    }else if std::mem::size_of::<LPVOID>() == 8{
        let ret : DWORD = unsafe{GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32)};
        if ret > 512 || ret == 0{
            return NULL as HMODULE;
        }
    }else{
        return NULL as HMODULE;
    }
    let sbuff = widestring::U16CStr::from_slice_truncate(&buffer).unwrap();
    let dllpath = format!("{}\\{}",sbuff.display(),name);
    let wstrpath = widestring::U16String::from_str(&dllpath);
    let ret : HMODULE = unsafe{LoadLibraryW(wstrpath.as_ptr())};
    ret
}
// fn str_to_cstr(s : &str)->ffi::CString{
//     let ss = string::String::from(s);
//     unsafe{ffi::CString::from_bytes_with_nul_unchecked(()}
// }
macro_rules! do_func_proxy {
    ($func : ty,$apiname : ident, $($arg : ident),*) => {
        let proc = GetProcAddress(get_real_version_handle(), concat!(stringify!($apiname),"\0").as_ptr() as *const i8);
        if proc == 0 as FARPROC{
            SetLastError(ERROR_NOT_FOUND);
            0
        }else{
            let f : $func = mem::transmute(proc);
            return f($($arg,)*);
        }
        
    };
}
#[no_mangle]
pub unsafe extern "stdcall" fn GetFileVersionInfoA(lptstrFilename : LPCSTR,dwHandle : DWORD,dwLen : DWORD,lpData : LPVOID)->BOOL {
    type F = unsafe extern "stdcall" fn(LPCSTR,DWORD,DWORD,LPVOID)->BOOL;
    do_func_proxy!{F,GetFileVersionInfoA,lptstrFilename,dwHandle,dwLen,lpData}
}
#[no_mangle]
pub unsafe extern "stdcall" fn GetFileVersionInfoExA(dwFlags : DWORD, lpwstrFilename : LPCSTR, dwHandle : DWORD,dwLen : DWORD,lpData : LPVOID)->BOOL { 
    type F = unsafe extern "stdcall" fn(DWORD, LPCSTR, DWORD,DWORD,LPVOID)->BOOL;
    do_func_proxy!{F,GetFileVersionInfoExA,dwFlags, lpwstrFilename, dwHandle,dwLen,lpData}
}
//#[no_mangle]
//GetFileVersionInfoByHandle(void) { PLACE_HOLDER(2); }
#[no_mangle]
pub unsafe extern "stdcall" fn GetFileVersionInfoExW(dwFlags : DWORD,lpwstrFilename : LPCWSTR,dwHandle : DWORD,dwLen : DWORD,lpData : LPVOID)->BOOL { 
    type F = unsafe extern "stdcall" fn(DWORD, LPCWSTR, DWORD,DWORD,LPVOID)->BOOL;
    do_func_proxy!{F,GetFileVersionInfoExW,dwFlags, lpwstrFilename, dwHandle,dwLen,lpData}
}
#[no_mangle]
pub unsafe extern "stdcall" fn GetFileVersionInfoSizeA(lptstrFilename : LPCSTR, lpdwHandle : LPDWORD)->DWORD{
    type F = unsafe extern "stdcall" fn(LPCSTR, LPDWORD)->DWORD;
    do_func_proxy!{F,GetFileVersionInfoSizeA,lptstrFilename, lpdwHandle}
}
#[no_mangle]
pub unsafe extern "stdcall" fn GetFileVersionInfoSizeExW(dwFlags : DWORD,lpwstrFilename : LPCWSTR,lpdwHandle : LPDWORD)->DWORD { 
    type F = unsafe extern "stdcall" fn(DWORD,LPCWSTR,LPDWORD)->DWORD;
    do_func_proxy!{F,GetFileVersionInfoSizeExW,dwFlags,lpwstrFilename,lpdwHandle}
}
#[no_mangle]
pub unsafe extern "stdcall" fn GetFileVersionInfoSizeExA(dwFlags : DWORD,lpwstrFilename : LPCSTR,lpdwHandle : LPDWORD)->DWORD { 
    type F = unsafe extern "stdcall" fn(DWORD,LPCSTR,LPDWORD)->DWORD;
    do_func_proxy!{F,GetFileVersionInfoSizeExA,dwFlags,lpwstrFilename,lpdwHandle}
}
#[no_mangle]
pub unsafe extern "stdcall" fn GetFileVersionInfoSizeW(lptstrFilename : LPCWSTR,lpdwHandle : LPDWORD)->DWORD{
    type F = unsafe extern "stdcall" fn(LPCWSTR, LPDWORD)->DWORD;
    do_func_proxy!{F,GetFileVersionInfoSizeW,lptstrFilename ,lpdwHandle}
}
#[no_mangle]
pub unsafe extern "stdcall" fn GetFileVersionInfoW(lptstrFilename : LPCWSTR,dwHandle : DWORD,dwLen : DWORD,lpData : LPVOID)->BOOL { 
    type F = unsafe extern "stdcall" fn(LPCWSTR,DWORD,DWORD,LPVOID)->BOOL;
    do_func_proxy!{F,GetFileVersionInfoW,lptstrFilename,dwHandle,dwLen,lpData}
}
#[no_mangle]
pub unsafe extern "stdcall" fn VerFindFileA(uFlags : DWORD,szFileName : LPCSTR,szWinDir : LPCSTR,szAppDir : LPCSTR,szCurDir : LPSTR,
  puCurDirLen : PUINT,szDestDir : LPSTR,puDestDirLen : PUINT)->DWORD {
    type F = unsafe extern "stdcall" fn(DWORD,LPCSTR,LPCSTR,LPCSTR,LPSTR,PUINT,LPSTR,PUINT)->DWORD;
    do_func_proxy!{F,VerFindFileA,uFlags,szFileName,szWinDir,szAppDir ,szCurDir,puCurDirLen,szDestDir,puDestDirLen}
}
#[no_mangle]
pub unsafe extern "stdcall" fn VerFindFileW(uFlags : DWORD,szFileName : LPCWSTR,szWinDir : LPCWSTR,szAppDir : LPCWSTR,szCurDir : LPWSTR,
  puCurDirLen : PUINT,szDestDir : LPWSTR,puDestDirLen : PUINT)->DWORD { 
    type F = unsafe extern "stdcall" fn(DWORD,LPCWSTR,LPCWSTR,LPCWSTR,LPWSTR,PUINT,LPWSTR,PUINT)->DWORD;
    do_func_proxy!{F,VerFindFileW,uFlags,szFileName,szWinDir,szAppDir ,szCurDir,puCurDirLen,szDestDir,puDestDirLen}
}
#[no_mangle]
pub unsafe extern "stdcall" fn VerInstallFileA(uFlags : DWORD,szSrcFileName : LPCSTR,szDestFileName : LPCSTR,szSrcDir : LPCSTR,
  szDestDir : LPCSTR,szCurDir : LPCSTR,szTmpFile : LPSTR,puTmpFileLen : PUINT)->DWORD {
    type F = unsafe extern "stdcall" fn(DWORD,LPCSTR,LPCSTR,LPCSTR,LPCSTR,LPCSTR,LPSTR,PUINT)->DWORD;
    do_func_proxy!{F,VerInstallFileA,uFlags,szSrcFileName,szDestFileName,szSrcDir,szDestDir,szCurDir,szTmpFile,puTmpFileLen}
}
#[no_mangle]
pub unsafe extern "stdcall" fn VerInstallFileW(uFlags : DWORD,szSrcFileName : LPCWSTR,szDestFileName : LPCWSTR,szSrcDir : LPCWSTR,
  szDestDir : LPCWSTR,szCurDir : LPCWSTR,szTmpFile : LPWSTR,puTmpFileLen : PUINT)->DWORD{ 
    type F = unsafe extern "stdcall" fn(DWORD,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPWSTR,PUINT)->DWORD;
    do_func_proxy!{F,VerInstallFileW,uFlags,szSrcFileName,szDestFileName,szSrcDir,szDestDir,szCurDir,szTmpFile,puTmpFileLen}
}
#[no_mangle]
pub unsafe extern "stdcall" fn VerLanguageNameA(wLang : DWORD,szLang : LPSTR,cchLang : DWORD)->DWORD{ 
    type F = unsafe extern "stdcall" fn(DWORD,LPSTR, DWORD)->DWORD;
    do_func_proxy!{F,VerLanguageNameA,wLang,szLang,cchLang}
}
#[no_mangle]
pub unsafe extern "stdcall" fn VerLanguageNameW(wLang : DWORD,szLang : LPWSTR,cchLang : DWORD)->DWORD { 
    type F = unsafe extern "stdcall" fn(DWORD,LPWSTR, DWORD)->DWORD;
    do_func_proxy!{F,VerLanguageNameW,wLang,szLang,cchLang}
}
#[no_mangle]
pub unsafe extern "stdcall" fn VerQueryValueA(pBlock : LPCVOID,lpSubBlock : LPCSTR,lplpBuffer : *mut LPVOID,puLen : PUINT)->BOOL { 
    type F = unsafe extern "stdcall" fn(LPCVOID,LPCSTR,*mut LPVOID,PUINT)->BOOL;
    do_func_proxy!{F,VerQueryValueA,pBlock,lpSubBlock,lplpBuffer,puLen}
}
#[no_mangle]
pub unsafe extern "stdcall" fn VerQueryValueW(pBlock : LPCVOID,lpSubBlock : LPCWSTR,lplpBuffer : *mut LPVOID,puLen : PUINT)->BOOL {
    type F = unsafe extern "stdcall" fn(LPCVOID,LPCWSTR,*mut LPVOID,PUINT)->BOOL;
    do_func_proxy!{F,VerQueryValueW,pBlock,lpSubBlock,lplpBuffer,puLen}
}
//#[no_mangle]
//VerQueryValueIndexA(void) { PLACE_HOLDER(16); }
//#[no_mangle]
//VerQueryValueIndexW(void) { PLACE_HOLDER(17); }

fn load_skse64(){
    thread::sleep(std::time::Duration::from_millis(200));
    let mut dllname = string::String::new();
    let mut verstr = string::String::new();
    {
        let openresult = fs::File::open("sksever");
        if let Ok(mut fp) = openresult {
            println!("read ok");
            fp.read_to_string(&mut verstr);
        }
    }
    if verstr.is_empty(){
        verstr+="1_5_97";
    }
    
    dllname.write_fmt(format_args!("skse64_{}.dll",verstr));
    println!("{}",dllname);
    let module = get_module_handle(dllname.as_str());
    if module != 0 as HMODULE{
        println!("module already loaded");
        return
    }
    let skse64 = unsafe{LoadLibraryW(widestring::U16String::from_str(dllname.as_str()).as_ptr())};
    if skse64 != 0 as HMODULE{
        type F = unsafe extern "C" fn();
        let proc = unsafe{GetProcAddress(skse64,concat!("StartSKSE","\0").as_ptr() as LPCSTR)};
        if proc != 0 as FARPROC{
            println!("func ok");
            unsafe{
            let func : F = mem::transmute(proc);
            func();
            }
        }else{
            println!("func fail");
        }
    }else{
        println!("load fail");
    }
}
#[no_mangle]
pub extern "system" fn DllMain(module: HMODULE, dwReason: u32, reserve: LPVOID) -> BOOL {
    match dwReason{
        DLL_PROCESS_ATTACH=>{
            thread::spawn(load_skse64);
        },
        _=>{

        }
    }
    1
}