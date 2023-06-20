extern crate num_bigint_dig;

use num_bigint_dig::traits::ModInverse;
use num_traits::{CheckedMul, Num, FromPrimitive};
use rsa::BigUint;
// use rsa::RsaPrivateKey;


fn main() {
    // Init student ID used as signed message
    let student_id: BigUint = BigUint::from_u32(6610009_u32).unwrap();
    
    // Init RSA Key Pair
    println!("\n====================================\n   Generating RSA-768 components   \n====================================\n");
    let n: BigUint = BigUint::from_str_radix("1230186684530117755130494958384962720772853569595334792197322452151726400507263657518745202199786469389956474942774063845925192557326303453731548268507917026122142913461670429214311602221240479274737794080665351419597459856902143413", 10).unwrap();
    let p: BigUint = BigUint::from_str_radix("33478071698956898786044169848212690817704794983713768568912431388982883793878002287614711652531743087737814467999489", 10).unwrap();
    let q: BigUint = BigUint::from_str_radix("36746043666799590428244633799627952632279158164343087642676032283815739666511279233373417143396810270092798736308917", 10).unwrap();
    let e: BigUint = BigUint::from(65537_u64);
    let phi_n: BigUint = (p.clone() - BigUint::from(1_u8)) * (q.clone() - BigUint::from(1_u8));
    let d: BigUint = e.clone().mod_inverse(&phi_n).unwrap().to_biguint().unwrap();
    // let rsa_object: RsaPrivateKey = RsaPrivateKey::from_components(n.clone(), e.clone(), d.clone(), vec![p.clone(), q.clone()]).unwrap();


    // check n = p * q
    assert_eq!(p.clone().checked_mul(&q).unwrap(), n);
    println!("(pass) n = p * q");
    
    // check d * e = 1 mod (p - 1) * (q - 1)
    assert_eq!(d.clone().checked_mul(&e).unwrap() % phi_n, BigUint::from(1_u8));
    println!("(pass) d * e = 1 mod (p - 1) * (q - 1)\n");
    println!("private key: d = {}", d);

    // Sign student ID by d directly
    println!("\n====================================\n   Sign student ID by d directly   \n====================================\n");
    let signature: BigUint = student_id.clone().modpow(&d, &n);
    let verfication: BigUint = signature.clone().modpow(&e, &n);
    assert_eq!(student_id.clone(), verfication.clone());
    println!("(pass) signature ^ e mod n == student_id");

    // Sign student ID by d with CRT
    println!("\n====================================\n   Sign student ID by d with CRT   \n====================================\n");
    let yp: BigUint = student_id.clone() % p.clone();
    let yq: BigUint = student_id.clone() % q.clone();
    let dp: BigUint = d.clone() % (p.clone() - BigUint::from_u8(1_u8).unwrap());
    let dq: BigUint = d.clone() % (q.clone() - BigUint::from_u8(1_u8).unwrap());
    // let dp: BigUint = rsa_object.dp().unwrap().clone();
    // let dq: BigUint = rsa_object.dq().unwrap().clone();
    let cp: BigUint = q.clone().mod_inverse(&p).unwrap().to_biguint().unwrap();
    let cq: BigUint = p.clone().mod_inverse(&q).unwrap().to_biguint().unwrap();
    let xp: BigUint = yp.modpow(&dp, &p);
    let xq: BigUint = yq.modpow(&dq, &q);

    let crt_signature: BigUint = ((q.clone() * cp.clone()) * xp.clone() + (p.clone() * cq.clone()) * xq.clone()) % n.clone();
    assert_eq!(crt_signature.clone(), signature.clone());
    println!("(pass) crt_signature == signature");
}
