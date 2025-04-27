(module
  ;; Import the required WASI functions
  (import "wasi_unstable" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  
  ;; Allocate memory for our message
  (memory 1)
  (export "memory" (memory 0))
  
  ;; Store string templates
  (data (i32.const 0) "Fibonacci Sequence:\n")
  (data (i32.const 20) "fib(%d) = %d\n")
  (data (i32.const 40) "Done.\n")
  
  ;; String buffer at offset 100 for formatting
  (data (i32.const 100) "                                        ")
  
  ;; Function to calculate nth Fibonacci number
  (func $fibonacci (param $n i32) (result i32)
    (local $i i32)
    (local $prev i32)
    (local $curr i32)
    (local $temp i32)
    
    ;; Handle base cases
    (if (i32.lt_s (local.get $n) (i32.const 2))
      (then
        (return (local.get $n))
      )
    )
    
    ;; Initialize sequence
    (local.set $prev (i32.const 0))
    (local.set $curr (i32.const 1))
    (local.set $i (i32.const 1))
    
    ;; Iterate to calculate fibonacci
    (loop $fib_loop
      ;; Compute next value
      (local.set $temp (local.get $curr))
      (local.set $curr (i32.add (local.get $prev) (local.get $curr)))
      (local.set $prev (local.get $temp))
      ;; Increment counter
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      ;; Continue if i < n
      (br_if $fib_loop (i32.lt_s (local.get $i) (local.get $n)))
    )
    
    ;; Return result
    (return (local.get $curr))
  )
  
  ;; Function to write a string to stdout
  (func $print_str (param $str_offset i32) (param $str_len i32)
    (local $iov i32)
    (local $written i32)
    
    ;; Set up the iov array at memory position 64
    (local.set $iov (i32.const 64))
    
    ;; Store pointer to string
    (i32.store (local.get $iov) (local.get $str_offset))
    ;; Store length of string
    (i32.store (i32.add (local.get $iov) (i32.const 4)) (local.get $str_len))
    
    ;; Call fd_write
    (drop (call $fd_write
      (i32.const 1)      ;; stdout fd
      (local.get $iov)   ;; *iovs
      (i32.const 1)      ;; iovs_len
      (i32.const 72)     ;; nwritten
    ))
  )
  
  ;; Format an integer to string at the given buffer position
  (func $format_int (param $value i32) (param $buffer i32) (result i32)
    (local $temp i32)
    (local $digit_count i32)
    (local $remainder i32)
    (local $current_pos i32)
    (local $digit_char i32)
    
    ;; Special case for 0
    (if (i32.eq (local.get $value) (i32.const 0))
      (then
        (i32.store8 (local.get $buffer) (i32.const 48)) ;; ASCII '0'
        (return (i32.const 1))
      )
    )
    
    ;; Start at the end of the buffer for reverse writing
    (local.set $current_pos (local.get $buffer))
    (local.set $digit_count (i32.const 0))
    (local.set $temp (local.get $value))
    
    ;; Convert each digit
    (loop $digit_loop
      ;; Calculate remainder
      (local.set $remainder (i32.rem_u (local.get $temp) (i32.const 10)))
      ;; Convert to ASCII and store
      (local.set $digit_char (i32.add (local.get $remainder) (i32.const 48)))
      (i32.store8 (local.get $current_pos) (local.get $digit_char))
      ;; Move to next position and update value
      (local.set $current_pos (i32.add (local.get $current_pos) (i32.const 1)))
      (local.set $temp (i32.div_u (local.get $temp) (i32.const 10)))
      (local.set $digit_count (i32.add (local.get $digit_count) (i32.const 1)))
      ;; Continue if temp > 0
      (br_if $digit_loop (i32.gt_s (local.get $temp) (i32.const 0)))
    )
    
    ;; Return the number of digits written
    (return (local.get $digit_count))
  )
  
  ;; Main function
  (func $main (export "_start")
    (local $i i32)
    (local $fib_value i32)
    (local $buffer_pos i32)
    (local $len i32)
    
    ;; Print header
    (call $print_str (i32.const 0) (i32.const 19))
    
    ;; Calculate and print first 20 Fibonacci numbers
    (local.set $i (i32.const 0))
    
    (loop $fib_print_loop
      ;; Calculate Fibonacci number
      (local.set $fib_value (call $fibonacci (local.get $i)))
      
      ;; Format the output string at position 100
      (local.set $buffer_pos (i32.const 100))
      
      ;; Format "fib(i) = value"
      ;; Copy "fib(" part
      (i32.store (local.get $buffer_pos) (i32.load (i32.const 20)))
      (i32.store (i32.add (local.get $buffer_pos) (i32.const 4)) (i32.load (i32.const 24)))
      
      ;; Add index value after "fib("
      (local.set $buffer_pos (i32.add (local.get $buffer_pos) (i32.const 4)))
      (local.set $len (call $format_int (local.get $i) (local.get $buffer_pos)))
      (local.set $buffer_pos (i32.add (local.get $buffer_pos) (local.get $len)))
      
      ;; Add ") = " part
      (i32.store8 (local.get $buffer_pos) (i32.const 41)) ;; ')'
      (i32.store8 (i32.add (local.get $buffer_pos) (i32.const 1)) (i32.const 32)) ;; ' '
      (i32.store8 (i32.add (local.get $buffer_pos) (i32.const 2)) (i32.const 61)) ;; '='
      (i32.store8 (i32.add (local.get $buffer_pos) (i32.const 3)) (i32.const 32)) ;; ' '
      (local.set $buffer_pos (i32.add (local.get $buffer_pos) (i32.const 4)))
      
      ;; Add the fibonacci value
      (local.set $len (call $format_int (local.get $fib_value) (local.get $buffer_pos)))
      (local.set $buffer_pos (i32.add (local.get $buffer_pos) (local.get $len)))
      
      ;; Add newline
      (i32.store8 (local.get $buffer_pos) (i32.const 10)) ;; '\n'
      (local.set $buffer_pos (i32.add (local.get $buffer_pos) (i32.const 1)))
      
      ;; Print the formatted string
      (call $print_str (i32.const 100) (i32.sub (local.get $buffer_pos) (i32.const 100)))
      
      ;; Increment counter
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      
      ;; Continue if i < 20
      (br_if $fib_print_loop (i32.lt_s (local.get $i) (i32.const 20)))
    )
    
    ;; Print footer
    (call $print_str (i32.const 40) (i32.const 6))
  )
) 