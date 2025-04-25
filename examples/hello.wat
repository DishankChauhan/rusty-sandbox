(module
  ;; Import the required WASI functions
  (import "wasi_unstable" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  
  ;; Allocate memory for our message
  (memory 1)
  
  ;; Export memory
  (export "memory" (memory 0))
  
  ;; Store "Hello, World!" in memory
  (data (i32.const 0) "Hello, World!\n")
  
  ;; Function to write to stdout
  (func $main (export "_start")
    ;; Setup variables for fd_write
    (local $iov i32)
    (local $len i32)
    
    ;; Message length
    (local.set $len (i32.const 14))
    
    ;; IO vector pointing to our message
    (local.set $iov (i32.const 16))
    
    ;; Setup IOVs array at offset 16
    ;; Store pointer to message at offset 16
    (i32.store (local.get $iov) (i32.const 0))
    ;; Store message length at offset 20
    (i32.store (i32.add (local.get $iov) (i32.const 4)) (local.get $len))
    
    ;; Call fd_write with:
    ;; - File descriptor 1 (stdout)
    ;; - Pointer to IOVs array
    ;; - Number of IOVs (1)
    ;; - Where to store number of bytes written
    (drop (call $fd_write
      (i32.const 1)      ;; stdout
      (local.get $iov)   ;; *iovs
      (i32.const 1)      ;; iovs_len
      (i32.const 24)     ;; nwritten
    ))
  )
) 