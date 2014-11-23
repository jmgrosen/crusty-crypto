#![macro_escape]

macro_rules! rotl (
    ($val: expr, $shift: expr) => (
        {
            let val = $val;
            let shift = $shift;
            let sz = ::std::mem::size_of_val(&val);
            (val << shift) | (val >> (sz * 8 - shift as uint))
        }
    )
)

macro_rules! rotr (
    ($val: expr, $shift: expr) => (
        {
            let val = $val;
            let shift = $shift;
            let sz = ::std::mem::size_of_val(&val);
            (val >> shift) | (val << (sz * 8 - shift as uint))
        }
    )
)

macro_rules! sha1_f0 (
    ($x: expr, $y: expr, $z: expr) => ($z ^ ($x & ($y ^ $z)))
)
macro_rules! sha1_f1 (
    ($x: expr, $y: expr, $z: expr) => ($x ^ $y ^ $z)
)
macro_rules! sha1_f2 (
    ($x: expr, $y: expr, $z: expr) => (($x & $y) | ($z & ($x | $y)))
)
macro_rules! sha1_f3 (
    ($x: expr, $y: expr, $z: expr) => ($x ^ $y ^ $z)
)

macro_rules! sha1_ff0 (
    ($a: ident, $b: ident, $c: ident, $d: ident, $e: ident, $w: expr) => ({
        $e = rotl!($a, 5) + sha1_f0!($b, $c, $d) + $e + $w + 0x5a827999;
        $b = rotl!($b, 30);
    })
)
macro_rules! sha1_ff1 (
    ($a: ident, $b: ident, $c: ident, $d: ident, $e: ident, $w: expr) => ({
        $e = rotl!($a, 5) + sha1_f1!($b, $c, $d) + $e + $w + 0x6ed9eba1;
        $b = rotl!($b, 30);
    })
)
macro_rules! sha1_ff2 (
    ($a: ident, $b: ident, $c: ident, $d: ident, $e: ident, $w: expr) => ({
        $e = rotl!($a, 5) + sha1_f2!($b, $c, $d) + $e + $w + 0x8f1bbcdc;
        $b = rotl!($b, 30);
    })
)
macro_rules! sha1_ff3 (
    ($a: ident, $b: ident, $c: ident, $d: ident, $e: ident, $w: expr) => ({
        $e = rotl!($a, 5) + sha1_f3!($b, $c, $d) + $e + $w + 0xca62c1d6;
        $b = rotl!($b, 30);
    })
)

macro_rules! get_32h (
    ($x: expr, $i: expr) => (
        (($x[$i * 4] as u32) << 24) |
        (($x[$i * 4 + 1] as u32) << 16) |
        (($x[$i * 4 + 2] as u32) << 8)  |
        ($x[$i * 4 + 3] as u32)
    )
)

macro_rules! store_32h (
    ($x: expr, $y: expr) => ({
        $y[0] = (($x >> 24) & 255) as u8;
        $y[1] = (($x >> 16) & 255) as u8;
        $y[2] = (($x >> 8)  & 255) as u8;
        $y[3] = (($x)       & 255) as u8;
    })
)

macro_rules! store_64h (
    ($x: expr, $y: expr) => ({
        $y[0] = (($x >> 56) & 255) as u8;
        $y[1] = (($x >> 48) & 255) as u8;
        $y[2] = (($x >> 40) & 255) as u8;
        $y[3] = (($x >> 32) & 255) as u8;
        $y[4] = (($x >> 24) & 255) as u8;
        $y[5] = (($x >> 16) & 255) as u8;
        $y[6] = (($x >> 8)  & 255) as u8;
        $y[7] = (($x)       & 255) as u8;
    })
)

macro_rules! be_word (
    ($a: expr, $b: expr, $c: expr, $d: expr) => (
           (($a as u32) << 24) | (($b as u32) << 16)
         | (($c as u32) <<  8) | (($d as u32))
    )
)

macro_rules! le_word (
    ($a: expr, $b: expr, $c: expr, $d: expr) => (be_word!($d, $c, $b, $a))
)

macro_rules! be_unword (
    ($e: expr) => (((($e >> 24) as u8), ((($e >> 16) & 0xff) as u8),
                   ((($e >> 8) & 0xff) as u8), (($e & 0xff) as u8)))
)

macro_rules! cc20_qround (
    ($st: expr, $a: expr, $b: expr, $c: expr, $d: expr) => ({
        $st[$a] += $st[$b]; $st[$d] ^= $st[$a]; $st[$d] = rotl!($st[$d], 16);
        $st[$c] += $st[$d]; $st[$b] ^= $st[$c]; $st[$b] = rotl!($st[$b], 12);
        $st[$a] += $st[$b]; $st[$d] ^= $st[$a]; $st[$d] = rotl!($st[$d], 8);
        $st[$c] += $st[$d]; $st[$b] ^= $st[$c]; $st[$b] = rotl!($st[$b], 7);
    })
)

macro_rules! unpack (
    ($s: expr, $i: expr) => (le_word!($s[$i*4 + 0], $s[$i*4 + 1], $s[$i*4 + 2], $s[$i*4 + 3]))
)

macro_rules! clone_helper (
    ($s: expr, $($i: expr),*) => ([$($s[$i].clone()),*])
)