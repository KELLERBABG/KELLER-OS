cargo build
& "C:\Program Files\qemu\qemu-system-x86_64.exe" `
-cpu max `

-device loader,file=target\x86_64-sovereign_core\debug\sovereign-
core,addr=0x100000,cpu-num=0 `

-serial stdio `
-display none `
-d guest_errors,int `
-no-reboot