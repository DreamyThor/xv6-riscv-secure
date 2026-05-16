# xv6-RISCV Operating Systems Security Project

  ## Overview
  This project extends the `xv6-riscv` kernel with core security mechanisms for a "medical-device" inspired operating system environment. The goal was to simulate protections expected in safety-critical embedded systems by adding authentication, file access control, and system call auditing.

  Official Xv6 for RISC-V GitHub repo: https://github.com/mit-pdos/xv6-riscv/tree/riscv 

  ## Objectives Achieved

  ### 1. User Authentication
  Implemented a role-based authentication system inside the kernel.

  Features:
  - Added user identity fields to processes: `uid`, `gid`, and authentication state
  - Created an `/etc/passwd`-like credential file
  - Stored passwords in hashed form instead of plaintext
  - Implemented authentication-related system calls:
    - `login`
    - `useradd`
    - `userdel`
    - `passwd`
    - `whoami`
  - Modified `init` so the system starts with a login prompt before shell access

  Roles:
  - `Admin` with full system access
  - `Patient` with restricted read-only access to records
  - `Doctor` with controlled access to dosage and patient data

  ### 2. UNIX-Style File Permissions
  Implemented file ownership and permission enforcement in the xv6 filesystem.

  Features:
  - Extended inode metadata with:
    - owner `uid`
    - group `gid`
    - permission `mode`
  - Added protected medical-device-related files and directories with predefined ownership
  - Implemented permission management system calls:
    - `chmod`
    - `chown`
  - Enforced access checks for:
    - `open`
    - `read`
    - `write`
    - `exec`

  Protected resources include:
  - `/patient/records`
  - `/dosage/insulin.log`
  - `/device/config`
  - `/audit/syscall.log`

  ### 3. System Call Audit Log
  Implemented a kernel-level syscall auditing mechanism.

  Features:
  - Added a kernel audit ring buffer
  - Logged syscall activity with:
    - process ID
    - user ID
    - syscall number
    - return value
    - system tick
  - Hooked audit logging into the syscall trap path
  - Implemented `auditread` syscall for retrieving audit entries
  - Restricted audit log reading to admin/root only
  - Added `/audit/syscall.log` for audit output visibility

  ### 4. Security Testing
  Created an automated security validation program.

  Features:
  - Added `securitytest` user program
  - Tested authentication, permissions, and audit access control
  - Verified role separation between admin, patient, and doctor
  - Produced pass/fail style compliance output

  ## Security Goal
  The project demonstrates how a minimal operating system like xv6 can be extended with practical kernel-level protections that resemble the security controls required in life-critical medical embedded devices.

  ## Added Components
  Kernel:
  - authentication support
  - permission-aware inode metadata
  - syscall auditing subsystem

  User programs:
  - `login`
  - `whoami`
  - `useradd`
  - `userdel`
  - `passwd`
  - `chmod`
  - `chown`
  - `audit`
  - `securitytest`

  ## Notes
  This project focuses on educational security mechanisms inside xv6 and demonstrates:
  - identity enforcement
  - least-privilege file access
  - privileged audit visibility
  - role-based separation of access
