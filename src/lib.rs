pub mod lib_3XDH;
use lib_3XDH::*;


use wasm_bindgen::prelude::*;
use wasm_bindgen::*;
use serde::{Serialize,Deserialize};
use serde::ser::{SerializeTupleStruct,Serializer};
use serde_json::*;
use p256::{
    ecdsa::{ Signature}};

use rand_core::OsRng;

#[wasm_bindgen]
#[derive(Debug)]
pub struct Bundle {
    identity_key : IdentityKey,
    signed_pre_key: SignedPreKey,
    signature : Signature,
    one_time_pre_key : OneTimePreKey,
    ephemeral_key : EphemeralKey,
}

#[wasm_bindgen]
#[derive(Debug,Deserialize,Serialize)]
pub struct Messages {
    id_issuer : String,
    id_room : String,
    date : String,
    payload : String,
}

#[wasm_bindgen]
#[derive(Debug,Deserialize,Serialize)]
pub struct IdentityStringify {
    name_ : String,
    ephemeral_key : String,
    identity_key : String,
    signed_pre_key: String,
    signature_ : String,
    one_time_pre_key : String
}



#[derive(Debug,Deserialize,Serialize)]
pub struct NameOf {
pub name_ : String,

}
#[wasm_bindgen]
#[derive(Debug,Deserialize,Serialize)]
pub struct Identity {
name_ : String,
#[serde(with = "serde_bytes")]
identity_key : Vec<u8>,
#[serde(with = "serde_bytes")]
signed_pre_key: Vec<u8>,
#[serde(with = "serde_bytes")]
signature : Vec<u8>,
#[serde(with = "serde_bytes")]
one_time_pre_key : Vec<u8>,
#[serde(with = "serde_bytes")]
ephemeral_key : Vec<u8>,
}
#[wasm_bindgen]
#[derive(Debug,Deserialize,Serialize)]
pub struct InitAlice {
    bundle_server : Identity,
    bundle_keep : IdentityStringify
}
#[wasm_bindgen]
pub fn parse_bundle_arguments(s:String)-> Vec<u8> {
    //let mut buf = String::from("[0, 0, 0, 0, 0, 178, 0, 0, 0, 0, 0, 0, 0, 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10, 77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 51, 110, 105, 67, 104, 85, 102, 57, 47, 53, 85, 116, 104, 118, 83, 105, 52, 68, 119, 47, 72, 48, 66, 113, 83, 86, 105, 103, 10, 56, 97, 122, 113, 77, 111, 113, 75, 76, 114, 122, 53, 116, 102, 55, 81, 101, 79, 114, 111, 113, 105, 74, 118, 83, 86, 52, 90, 118, 117, 78, 108, 90, 76, 110, 119, 83, 106, 85, 118, 79, 119, 122, 122, 49, 55, 72, 116, 99, 113, 75, 68, 104, 48, 99, 88, 56, 65, 61, 61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 80, 85, 66, 76, 73, 67, 32, 75, 69, 89, 45, 45, 45, 45, 45, 10]");
            
         let mut s = s.replace("[", "");
         let mut s = s.replace("]", "");
         let t = s.replace(" ",""); //enlever les spaces
         let a : Vec<String> = t.split(",").map(str::to_string).collect();
         //let int = s.parse::<u8>().unwrap();
         //println!("{:?}",a);
         let mut vec : Vec<u8> = Vec::new();
         for i in 0..a.len() {
             vec.push( a[i].parse::<u8>().unwrap())
         }
        // println!("{:?}", vec);
         vec
}

//------------------------------------------alice------------------
#[wasm_bindgen]
pub fn key_init_alice() -> String{
    //1
    let ika = IdentityKey::default();
    let ikas = ika.strip();
    //2
    let spka = SignedPreKey::default();
    //3
    let eka = EphemeralKey::default();
    let ekas = eka.strip();
    //4
    let otpka = OneTimePreKey::default();
    let otpkas = otpka.strip();
    //bundle a envoyer au server
    let bundle_alice_to_keep = IdentityStringify {
        name_ : String::from("Alice"),
        ephemeral_key :format!("{:?}",eka.to_bytes()) ,
        identity_key: format!("{:?}",ika.to_bytes().clone()),
        signed_pre_key : format!("{:?}",spka.to_bytes().clone()),
        signature_ : format!("{:?}",(ika.sign(&spka.strip().pk_to_bytes()).as_ref()).to_vec()),
        one_time_pre_key: format!("{:?}",otpka.to_bytes())
    };

    let bundle_server = Identity {
        name_ : String::from("Alice"),

        identity_key : ika.clone().strip().to_bytes(),
        signed_pre_key: spka.strip().to_bytes(),
        signature : (ika.sign(&spka.strip().pk_to_bytes()).as_ref()).to_vec(),
        one_time_pre_key : otpkas.to_bytes(),
        ephemeral_key : ekas.to_bytes(),

    };
    //update la table post bundle 
    let return_bundle = InitAlice {
        bundle_server: bundle_server,
        bundle_keep: bundle_alice_to_keep
    };
    //pour l'instant stockage sur le nav
    serde_json::to_string(&return_bundle).unwrap()
}

#[wasm_bindgen]
pub fn calculate_master_key_alice(bundle_bob_server : String, bundle_alice_local : String ) -> String{


    let bundle_alice : IdentityStringify = serde_json::from_str(&bundle_alice_local).unwrap();
    let bundle_bob : Identity = serde_json::from_str(&bundle_bob_server).unwrap() ;

    //alice serialization
    let ika_to_vec = parse_bundle_arguments(bundle_alice.identity_key);
    let eka_to_vec = parse_bundle_arguments(bundle_alice.ephemeral_key);

    let ika = IdentityKey::from_bytes(&ika_to_vec).unwrap();
    let eka = EphemeralKey::from_bytes(&eka_to_vec).unwrap();

    //bob serialization
    let signature_parsed: &[u8] = &bundle_bob.signature;
    
    let signature = Signature::try_from(signature_parsed).unwrap();
    let spkbs = SignedPreKey::from_bytes(&bundle_bob.signed_pre_key).unwrap(); //deja strip dans le bundle
    let ikbs = IdentityKey::from_bytes(&bundle_bob.identity_key).unwrap();
    let opkbs = OneTimePreKey::from_bytes(&bundle_bob.one_time_pre_key).unwrap();
    //master key

    let cka = x3dh_a(&signature, &ika , &spkbs, &eka, &ikbs, &opkbs).unwrap(); //alice = bob , alice, bob ,alice, bob, bob
    //signature bob                 ->    server
    //identity_key alice            ->    local
    //signed_pre_key bob STRIP      ->    server
    //ephemeral alice               ->    local
    //identity_key BOB STRIP        ->    server
    //one time pre key bob STRIP    ->    server
    println!("{:?}", cka);
    serde_json::to_string(&cka).unwrap()
}
#[wasm_bindgen]
pub fn alice_init_ratchet(sk : String) {
    let sk = parse_bundle_arguments(sk);

    
}

//---------------------------------------bob------------------
#[wasm_bindgen]
pub fn key_init_bob()->String {

    let ikb = IdentityKey::default();
    let ikbs = ikb.strip();
    

    let spkb = SignedPreKey::default();
    let spkbs = spkb.strip();
    
    let ekb = EphemeralKey::default();
    let ekbs = ekb.strip();
    
    let opkb = OneTimePreKey::default();
    let opkbs = opkb.strip();
    
    let signature = ikb.sign(&spkbs.pk_to_bytes());
    
    let bundle_bob_to_keep = IdentityStringify {
        name_ : String::from("bob"),
        ephemeral_key : format!("{:?}", ekb.to_bytes()),
        identity_key: format!("{:?}",ikb.to_bytes().clone()),
        signed_pre_key : format!("{:?}",spkb.to_bytes().clone()),
        signature_ : format!("{:?}",ikb.sign(&spkb.strip().pk_to_bytes())),
        one_time_pre_key: format!("{:?}",opkb.to_bytes())
    };

    let bundle_server = Identity {
        name_ : String::from("bob"),
        identity_key : ikb.clone().strip().to_bytes(),
        signed_pre_key: spkb.strip().to_bytes(),
        signature : (ikb.sign(&spkb.strip().pk_to_bytes()).as_ref()).to_vec(),
        one_time_pre_key : opkbs.to_bytes(),
        ephemeral_key : opkbs.to_bytes()

    };
    //update la table post bundle 
    let return_bundle = InitAlice {
        bundle_server: bundle_server,
        bundle_keep: bundle_bob_to_keep
    };
    //pour l'instant stockage sur le nav
    serde_json::to_string(&return_bundle).unwrap()
}

#[wasm_bindgen]
pub fn calculate_master_key_bob(bundle_bob_local : String, bundle_alice_server : String ) -> String{


    let bundle_bob : IdentityStringify = serde_json::from_str(&bundle_bob_local).unwrap();
    let bundle_alice : Identity = serde_json::from_str(&bundle_alice_server).unwrap() ;

    

    //alice parsing
    let ikas = IdentityKey::from_bytes(&bundle_alice.identity_key).unwrap();
    let ekas = EphemeralKey::from_bytes(&bundle_alice.ephemeral_key).unwrap();

    //bob parsing
    let spbk_to_vec = parse_bundle_arguments(bundle_bob.signed_pre_key);
    let ikb_to_vec = parse_bundle_arguments(bundle_bob.identity_key);
    let opkb_to_vec = parse_bundle_arguments(bundle_bob.one_time_pre_key);

    let spkb = SignedPreKey::from_bytes(&spbk_to_vec).unwrap(); 
    let ikb = IdentityKey::from_bytes(&ikb_to_vec).unwrap();
    let opkb = OneTimePreKey::from_bytes(&opkb_to_vec).unwrap();
    

    let ckb = x3dh_b(&ikas, &spkb, &ekas, &ikb, &opkb);//bob =   alice, bob, alice, bob, bob
    //signature bob                 ->    server
    //identity_key alice            ->    local
    //signed_pre_key bob STRIP      ->    server
    //ephemeral alice               ->    local
    //identity_key BOB STRIP        ->    server
    //one time pre key bob STRIP    ->    server
    println!("{:?}", ckb);
    serde_json::to_string(&ckb).unwrap()
}