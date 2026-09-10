(module
    (memory (export "memory") 1)
    
    (data (i32.const 0) "{\"name\":\"coinflip\",\"slash_commands\":[{\"name\":\"coinflip\",\"description\":\"Flip a coin\"}]}")
    
    ;; HEADS at offset 200 (Length: 31)
    (data (i32.const 200) "🪙 The coin landed on: HEADS!")
    ;; TAILS at offset 300 (Length: 31)
    (data (i32.const 300) "🪙 The coin landed on: TAILS!")

    (global $counter (mut i32) (i32.const 0))

    (func (export "alloc") (param i32) (result i32)
        i32.const 1024
    )

    ;; Returns manifest
    (func (export "get_manifest") (result i64)
        i64.const 86
    )

    ;; Alternates between HEADS and TAILS on each flip!
    (func (export "on_slash_command") (param i32 i32) (result i64)
        (if (result i64) (i32.eq (global.get $counter) (i32.const 0))
            (then
                (global.set $counter (i32.const 1))
                i64.const 858993459231 ;; (200 << 32) | 31 -> HEADS
            )
            (else
                (global.set $counter (i32.const 0))
                i64.const 1288490188831 ;; (300 << 32) | 31 -> TAILS
            )
        )
    )
)
