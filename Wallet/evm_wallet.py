
import sys
import hashlib
from eth_hash.auto import keccak    
import secrets
import logging
import os
from pathlib import Path
import ckzg

Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 
Acurve = 0; Bcurve = 7 
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
GPoint = (Gx,Gy) 


def find_project_root():
    """Find the root directory of the project by looking for .git."""
    curr_dir = os.path.abspath(os.path.dirname(__file__))

    while curr_dir:
        if ".git" in os.listdir(curr_dir):
            return curr_dir
        parent_dir = os.path.dirname(curr_dir)
        
        # If no parent is found, break out of loop
        if parent_dir == curr_dir:
            break
        curr_dir = parent_dir

    raise FileNotFoundError("Cannot find project root")


# Determine the path to the root directory
root_path = Path(find_project_root())
log_path = root_path / 'logs' / 'transactionOutput.log'

# Ensure the logs directory exists
if not log_path.parent.exists():
    log_path.parent.mkdir()

logging.basicConfig(filename=log_path, level=logging.INFO, format="%(asctime)s:%(levelname)s:%(message)s")


#for 256-bit private key generation
def random_num_gen():
    random_num = hex(secrets.randbits(257))[2:]
    if len(random_num) % 2 != 0:
        random_num = "0"+ random_num
    hash = hashlib.sha256(bytes.fromhex(random_num)).hexdigest()
    return hash


'''
https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md

As of EIP-55, Ethereum addresses can actually have a checksum. We can see Metamask actually uses the checksum
address. This checksum is not as good as Bitcoin's 4 byte checksum of the double sha256 hash, but 
still better than nothing. Gives "0.0247%" probability of mistyped address accidentally passing check

Procedure:

- Take string version of your ethereum address (no "0x")
- Keccak256 this result (we won't use last 12 bytes though)
- For each digit, if <8, then any hex letter stays lower case, if >=8 any hex letter becomes upper case
- The odds that we would generate an address without any a-e digits is (10/16)^40 == 6.8x10^-9, so unlikely to 
  generate an address were the checksum has no impact
'''
def checksum_address(address_public):

    comparison = keccak(bytes(address_public, encoding='utf-8')).hex()[:40]  #we only care about first 20 bytes of result
    checksum_address = ''
    upper_case = ["8", "9", "a", "b", "c", "d", "e", "f"] #this particular keccak returns lower case but might not if different keccak function used!

    for i in range(len(comparison)):
        if comparison[i] in upper_case:
            checksum_address += address_public[i].upper()
        else:
            checksum_address += address_public[i]

    print("Checksum address: 0x{}".format(checksum_address))

    return checksum_address


def modinv(a,n): 
    lm, hm = 1,0
    low, high = a%n,n
    while low > 1:
        ratio = high//low
        nm, new = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n


def ECadd(xp,yp,xq,yq): 
    m = int((yq-yp) * modinv(xq-xp,Pcurve)) % Pcurve
    xr = int(m*m-xp-xq) % Pcurve
    yr = int(m*(xp-xr)-yp) % Pcurve
    return (xr,yr)


def ECdouble(xp,yp): 
    LamNumer = (3*xp**2)+Acurve% Pcurve
    LamDenom = 2*yp
    Lam = LamNumer * modinv(LamDenom,Pcurve)
    xr = int(Lam*Lam-2*xp) % Pcurve
    yr = int(Lam*(xp-xr)-yp) % Pcurve
    return (xr,yr)


def EccMultiply(xs,ys,Scalar): 
    if type(Scalar) is str:
        if int(Scalar, 16) == 0 or int(Scalar, 16) >= N: raise Exception("Invalid Scalar/Private Key")
        ScalarBin = bin(int(Scalar, 16))[2:]
    elif type(Scalar) is int:
        if Scalar == 0 or Scalar >= N: raise Exception("Invalid Scalar/Private Key")
        ScalarBin = bin(Scalar)[2:]
    
    Qx,Qy=xs,ys  
    for i in range (1, len(ScalarBin)): 
        Qx,Qy=ECdouble(Qx,Qy); 
        if ScalarBin[i] == "1":
            Qx,Qy=ECadd(Qx,Qy,xs,ys); 
    return (Qx,Qy)


#P = (s/r)R - (m/r)G
def pubkey_recover(yparity, r, s, msg_hash, xPub, yPub):

    r_y = secp256k1_y_from_x_eth(r, int(yparity))

    p1, p2 = EccMultiply(Gx,Gy,(msg_hash*modinv(r, N))%N)
    p3, p4 = EccMultiply(r,r_y,(s*modinv(r, N))%N) #note x,y here is R

    pub1, pub2 = ECadd(p1,Pcurve-p2,p3,p4) 
    print((pub1, pub2) == (xPub, yPub))

    return

'''
Takes message hash and signature verification flag and returns signature parameters yparity, r and s
Allows optional signature verification 
From my experimentation, leading r bit can be 1 -> and if you try and "correct" this by prepending "00",
tx will not be valid. "s" has to be low, but make sure if s is high and we set to low, we also flip the
yparity value 
'''
def generate_signature(privKey, xPub, yPub, msg_hash, signature_verification, pubkey_recov):

    print("******* Signature Generation *********")

    RandNum = random_num_gen()  

    xRandSignPoint, yRandSignPoint = EccMultiply(Gx,Gy,RandNum)
    
    if yRandSignPoint % 2 == 0:
        yparity = "00"
    else:
        yparity = "01"

    r = xRandSignPoint % N 
    s = ((msg_hash + r*int(privKey,16))*(modinv(int(RandNum,16),N))) % N
    
    if s > N/2:  #enforces low s 
        s = N-s  
        #if we change s, we need to change the parity flag as well
        if yparity == "01":
            yparity = "00"
        elif yparity == "00":
            yparity = "01"

    if bin(r)[2:].zfill(256)[0] == "0":
        if len(hex(r)[2:])%2 != 0:
            hex_r = "0x0" + hex(r)[2:] 
        else:
            hex_r = hex(r)
    else:
        hex_r = hex(r)

    if len(hex(s)[2:])%2 != 0:
        hex_s = "0x0" + hex(s)[2:]  
    else:
        hex_s = hex(s)

    if signature_verification:
        print("******* Signature Verification *********")
        w = modinv(s,N)
        xu1, yu1 = EccMultiply(Gx,Gy,(msg_hash * w)%N)  #u = zS-1, u*G
        xu2, yu2 = EccMultiply(xPub,yPub,(r*w)%N)   #v = rS-1, v*P
        x,y = ECadd(xu1,yu1,xu2,yu2)  #uG + vP = kG = x,y   
        print(r==x%N)

    if pubkey_recov:
        print("******* Pubkey Recover *********")
        pubkey_recover(yparity, r, s, msg_hash, xPub, yPub)

    return yparity, hex_r[2:], hex_s[2:]


'''
RLP encodes list or payload, but assumes if list passed, it is already RLP encoded, e.g. for 
list ["hello", "world"], this function assumes already in format: '8568656c6c6f85776f726c64', i.e. input is string representation of a list
Function assumes length of list in hex digits is even
'''
def rlp_encode_list(input_value):

    len_input_bytes = int(len(input_value)/2)

    if len_input_bytes == 0:
        input_value = "c0"
    elif 0 < len_input_bytes <= 55:
        input_value = hex(192 + len_input_bytes)[2:] + input_value
    elif len_input_bytes > 55:
        hex_len_bytes = hex(len_input_bytes)[2:] 
        if len(hex_len_bytes) % 2 != 0:
            hex_len_bytes = "0" + hex_len_bytes
        input_value = hex(247 + int(len(hex_len_bytes)/2))[2:] + hex_len_bytes + input_value

    return input_value  # Returning string representation of a list


'''
Takes a string or int input (if string -> in hex format, no '0x', can be odd hex number digits) 
Input int == 0 for address(0), nonce 0, "" calldata etc., this function will output as 0x80
'''
def rlp_encode_string(string_value):

    skip = 0

    if type(string_value) == int:
        if string_value == 0:
            string_value = "80"
            skip = 1
        else:
            string_value = hex(string_value)[2:]

    if skip == 0:

        if string_value[:2] == "0x":
            raise ValueError("Don't put 0x in the address!")

        if len(string_value) % 2 != 0:   #must be in bytes
            string_value = "0" + string_value

        len_val_bytes = int(len(string_value)/2)

        if len_val_bytes == 1 and int(string_value, 16) >= 128:   #0x80 - 0xff
            string_value = "81" + string_value
        elif 1 < len_val_bytes <= 55:                            #2-55 bytes
            string_value = hex(128 + len_val_bytes)[2:] + string_value
        elif len_val_bytes > 55:
            hex_len_bytes = hex(len_val_bytes)[2:]
            if len(hex_len_bytes) % 2 != 0:
                hex_len_bytes = "0" + hex_len_bytes
            string_value = hex(183 + int(len(hex_len_bytes)/2))[2:] + hex_len_bytes + string_value

    return string_value


'''
access_input in form (as per EIP2930):
[
    [
        "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
        [
            "0x0000000000000000000000000000000000000000000000000000000000000003",
            "0x0000000000000000000000000000000000000000000000000000000000000007"
        ]
    ],
    [
        "0xbb9bc244d798123fde783fcc1c72d3bb8c189413",
        []
    ]
]
'''
def rlp_encode_access_list(access_list):

    if len(access_list) == 0:
        return rlp_encode_list(access_list)     #I don't want to hard-code "c0" in multiple places

    access_string = ""

    for item in access_list:  #iterating through contracts
        contract_string = ""
        slot_string = ""
        contract_string += rlp_encode_string(item[0]) #address
        for slot in item[1]:
            slot_string += rlp_encode_string(slot)
        access_string += rlp_encode_list(contract_string + rlp_encode_list(slot_string))

    accessList = rlp_encode_list(access_string)

    return accessList


'''
Adds a leading zero to the blob data every 32 bytes to avoid data corruption through BLS_MODULUS
Note - If blob data already close to max then adding zeros will exceed the limit, so we need to trim it
'''
def encodeLeadingZeros(blob):
    # Number of hex characters representing 31 bytes (since one byte will be "00")
    interval = 62
    
    # Initialize the result, starting with "00"
    blob_string = "00"
    
    # Iterate over each block of the blob, adding "00" every 32 bytes
    for i in range(0, len(blob), interval):
        # Add the next 62 characters and then a "00"
        blob_string += blob[i:i+interval] + "00"
    
    # If the blob is too long after adding zeros, trim it to the maximum allowed length
    if len(blob_string) / 2 > 131072:
        blob_string = blob_string[:131072*2]
    
    return blob_string


'''
Reverse of encoding process, removes the leading zeros added every 32 bytes. Adds zeros back to the blob data
given that it is removing data from correct blob size
'''
def decodeLeadingZeros(blob):
    # Remove the "00" added every 32 bytes (which is every 64 hex characters plus 2 for "00")
    interval = 64
    chunks = [blob[i+2:i+interval] for i in range(0, len(blob), interval)]
    
    # Join all chunks without the "00"
    blob_string = "".join(chunks)

    # If the blob is too short after removing zeros, trim it to the maximum allowed length
    if len(blob_string) / 2 < 131072:
        blob_string += "00" * (131072 - int(len(blob_string)/2))
    
    return blob_string


'''
The blob data 32 byte chunks all need to be scaled by the BLS_MODULUS, otherwise the KZG commitment generation will fail
'''
def blsModBlob(blob):
    BLS_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513
    blob_array = []

    for i in range(0, 4096):
        value = int(blob[i*64:(i+1)*64], 16)
        value = value % BLS_MODULUS
        hex_value = hex(value)[2:]
        if len(hex_value) < 64:
            while len(hex_value) < 64:
                hex_value = "0" + hex_value
        blob_array.append(hex_value)

    blob_string = "".join(blob_array)
    print(len(blob_string)/2)

    return blob_string


'''
Function reads a file of blob data, hashes each blob, generates KZG commitment and proof for each blob, returning the 
versioned hash, blob data and KZG proof for each blob. Each list element is RLP-encoded but the list RLP-encoding doesn't take place here
'''
def getKZGBlobCommits(blob_versioned_hashes, blobs, commitments, proofs):
    BLOB_DATA_SIZE = 131072     # Current size of each blob in bytes

    trusted_setup_path = "./externals/c-kzg-4844/src/trusted_setup.txt" # Running from project root
    trusted_setup = ckzg.load_trusted_setup(trusted_setup_path)     # Loading trusted setup from KZG ceremony
    with open("./Wallet/blob_data.txt", 'r', encoding='utf-8') as file:    # Loading blob data from file (sum of all blobs concat in a single file)
        file_contents = file.read()
    
    file_data_length = int(len(file_contents)/2)
    num_blobs = int(file_data_length/BLOB_DATA_SIZE) + 1

    for i in range(num_blobs):
        blob = file_contents[i*BLOB_DATA_SIZE*2:(i+1)*BLOB_DATA_SIZE*2]
        blob_size = int(len(blob)/2)

        if blob_size < BLOB_DATA_SIZE:
            blob += "00"*(BLOB_DATA_SIZE - blob_size)  # Right padding with zeros to make the blob size equal to 131072 byte
        
        blob = encodeLeadingZeros(blob)     # Encoding leading zeros in the blob dat
        #blob = blsModBlob(blob)         # Modifying the blob data to be within the BLS modulus
        blob_data_bytes = bytes.fromhex(blob)     # Converting the blob data to bytes
        kzg_commitment = ckzg.blob_to_kzg_commitment(blob_data_bytes, trusted_setup)
        
        kzg_proof = ckzg.compute_blob_kzg_proof(blob_data_bytes, kzg_commitment, trusted_setup)
        verified = ckzg.verify_blob_kzg_proof(blob_data_bytes, kzg_commitment, kzg_proof, trusted_setup)
        if not verified:
            raise Exception("KZG proof verification failed")
        
        hash_obj = hashlib.sha256()     # Hashing the blob data
        hash_obj.update(kzg_commitment)
        versioned_hash = "01" + hash_obj.hexdigest()[2:]

        if len(kzg_commitment.hex())/2 != 48:
            raise Exception("KZG commitment length is not 48 bytes")
        if len(kzg_proof.hex())/2 != 48:
            raise Exception("KZG proof length is not 48 bytes")

        commitments += rlp_encode_string(kzg_commitment.hex())
        blobs += rlp_encode_string(blob)
        proofs += rlp_encode_string(kzg_proof.hex())
        blob_versioned_hashes += rlp_encode_string(versioned_hash)

    return blob_versioned_hashes, blobs, commitments, proofs


'''
For legacy transaction type (both EIP155 complaint and not)
Takes as input private key and transaction details, generates signature and returns raw hex of signed tx
Tx format: nonce, gasPrice, gasLimit, to, value, data, v, r, and s

Sig format:        rlp(nonce, gasprice, gasLimit, to, value, data)
Sig EIP155 format: rlp(nonce, gasprice, gasLimit, to, value, data, chainID, 0, 0) 
So args SHOULD be nonce, gasPrice, gasLimit, to, value, data
       or         nonce, gasPrice, gasLimit, to, value, data, chainID, 0, 0
'''
def legacy_tx(priv_key, xPub, yPub, *args, EIP155, signature_verification, pubkey_recov):

    tx_format = ""

    for arg in args:
        tx_format += rlp_encode_string(arg)

    raw_unsigned_msg = rlp_encode_list(tx_format)
    msg_hash = keccak(bytes.fromhex(raw_unsigned_msg)).hex()
    HashOfThingToSign = int("0x" + msg_hash, 16)

    yparity, r, s = generate_signature(priv_key, xPub, yPub, HashOfThingToSign, signature_verification, pubkey_recover)

    if EIP155:      #tx_format hard-coding chain ID length, not happy with this
        v = hex(int(yparity) + 2*int(args[-3]) + 35)[2:]
        raw_tx = rlp_encode_list(tx_format[:-(4+len(rlp_encode_string(args[-3])))] + rlp_encode_string(v) + rlp_encode_string(r) + rlp_encode_string(s)).lower()
    else:
        v = hex(int(yparity) + 27)[2:]
        raw_tx = rlp_encode_list(tx_format + rlp_encode_string(v) + rlp_encode_string(r) + rlp_encode_string(s)).lower()

    return raw_tx


'''
Final tx format: 0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yparity, r, s])   
Signature format: keccak256(0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList]))
Tx receipt: rlp([status, cumulativeGasUsed, logsBloom, logs])
-> It appears like type 1 tx gas costs are the same as legacy, and why not, because the update was in type 2,
a.k.a. EIP 1559
'''
def type_1(priv_key, xPub, yPub, accessList, *args, signature_verification, pubkey_recov):

    tx_format = ""

    for arg in args:
        tx_format += rlp_encode_string(arg)

    tx_format += rlp_encode_access_list(accessList)  

    raw_unsigned_msg = "01" + rlp_encode_list(tx_format)
    msg_hash = keccak(bytes.fromhex(raw_unsigned_msg)).hex()
    HashOfThingToSign = int("0x" + msg_hash, 16)

    yparity, r, s = generate_signature(priv_key, xPub, yPub, HashOfThingToSign, signature_verification, pubkey_recover)

    if yparity == "00":
        yparity = "80" #actually correct format for yparity of 0

    raw_tx = "01" + rlp_encode_list(tx_format + yparity + rlp_encode_string(r) + rlp_encode_string(s)).lower()

    return raw_tx


'''
Final tx format (see comparison with 1 first):
0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yparity, r, s])  (compare with 1)
0x02 || rlp([chainId, nonce, max_priority_fee_per_gas, max_fee_per_gas, gasLimit, to, value, data, accessList, yparity, r, s])
Signing:
keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list]))
So only difference in type 2 is extra gas parameter (first one right after nonce)
'''
def type_2(priv_key, xPub, yPub, accessList, *args, signature_verification, pubkey_recov):

    tx_format = ""

    for arg in args:
        tx_format += rlp_encode_string(arg)

    tx_format += rlp_encode_access_list(accessList)  

    raw_unsigned_msg = "02" + rlp_encode_list(tx_format)
    msg_hash = keccak(bytes.fromhex(raw_unsigned_msg)).hex()
    HashOfThingToSign = int(msg_hash, 16)

    yparity, r, s = generate_signature(priv_key, xPub, yPub, HashOfThingToSign, signature_verification, pubkey_recover)

    if yparity == "00":
        yparity = "80" #actually correct format for yparity of 0

    raw_tx = "02" + rlp_encode_list(tx_format + yparity + rlp_encode_string(r) + rlp_encode_string(s)).lower()

    return raw_tx


'''
Final tx format:
0x03 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list, max_fee_per_blob_gas, blob_versioned_hashes, y_parity, r, s])
Signing:
keccak256(0x03 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list, max_fee_per_blob_gas, blob_versioned_hashes]))
Overall blob wrapper:
rlp([tx_payload_body, blobs, commitments, proofs])
Final tx format: 0x03 || rlp([tx_payload_body, blobs, commitments, proofs])
'''
def type_3(priv_key, xPub, yPub, max_fee_per_blob_gas, accessList, *args, signature_verification, pubkey_recov):

    tx_format = ""

    for arg in args:
        tx_format += rlp_encode_string(arg)

    tx_format += rlp_encode_access_list(accessList)
    tx_format += rlp_encode_string(max_fee_per_blob_gas)

    # Data for wrapped transaction payload
    blob_versioned_hashes, blobs, commitments, proofs = "", "", "", ""     # Note the 'rlp_encode_list' takes in a string, so using a string representation of a list is more convenient
    (blob_versioned_hashes, blobs, commitments, proofs) = getKZGBlobCommits(blob_versioned_hashes, blobs, commitments, proofs)
    tx_format += rlp_encode_list(blob_versioned_hashes)

    raw_unsigned_msg = "03" + rlp_encode_list(tx_format)
    msg_hash = keccak(bytes.fromhex(raw_unsigned_msg)).hex()
    HashOfThingToSign = int(msg_hash, 16)

    # chainID, nonce, gasPriority, gasPrice, gasLimit, to, value, data

    yparity, r, s = generate_signature(priv_key, xPub, yPub, HashOfThingToSign, signature_verification, pubkey_recover)

    if yparity == "00":
        yparity = "80" #actually correct format for yparity of 0

    tx_payload_body = rlp_encode_list(tx_format + yparity + rlp_encode_string(r) + rlp_encode_string(s)).lower()

    tx_hash = keccak(bytes.fromhex("03" + tx_payload_body)).hex()

    final_tx = "03" + rlp_encode_list(tx_payload_body + rlp_encode_list(blobs) + rlp_encode_list(commitments) + rlp_encode_list(proofs))

    return final_tx, tx_hash


def contract_creation_address(address, nonce):

    contract_address = keccak(bytes.fromhex(rlp_encode_list(rlp_encode_string(address)+rlp_encode_string(nonce)))).hex()[24:]

    print("Contract creation address: 0x{}".format(contract_address))
    checksum_address(contract_address)

    return contract_address


#For CREATE2 opcode
def contract_creation_2_address():
    pass 


def main(arg1=None, arg2=None):
    privKey = os.environ.get('PRIVATE_KEY')
    nonce = 3
    gasPriority = "989680" #0x59682f00 == 1.5 Gwei #max priority fee, 0x989680 == 0.01 Gwei
    gasPrice = "03ba453680" # 0x0147d35700 == 5.5 Gwei
    gasLimit = "5208" # 0x5208 == 21000
    to = "75cBaBf6ef1DD426eCF70458841127007d0cfef8" #remove "0x"
    value = 0  #ether value to send
    data = 0 #transaction calldata to pass
    chainID = 1

    # EIP4844
    max_fee_per_blob_gas = "01"

    accessList = []#[["a0a24360cE64d364C0afB4325B6b70c66fDA24cd", ["0000000000000000000000000000000000000000000000000000000000000003", "0000000000000000000000000000000000000000000000000000000000000069"]]]#[["a0a24360cE64d364C0afB4325B6b70c66fDA24cd", ["0000000000000000000000000000000000000000000000000000000000000003", "0000000000000000000000000000000000000000000000000000000000000069"]],["a31df417ab346e0c45955e3e30e998defe9efe74", ["00000000000000000000000000000000000000000000000000000000000000fe", "0000000000000000000000000000000000000000000000000000000000000000"]]]

    print("******* Public Key Generation *********")
    xPub, yPub = EccMultiply(Gx,Gy,privKey)

    xPubHex = hex(xPub)[2:]
    yPubHex = hex(yPub)[2:]

    if len(xPubHex) < 64:
        while len(xPubHex) < 64:
            xPubHex = "0" + xPubHex

    if len(yPubHex) < 64:
        while len(yPubHex) < 64:
            yPubHex = "0" + yPubHex

    address_public = keccak(bytes.fromhex(xPubHex+yPubHex)).hex()[24:]
    print("Public address is: 0x{}".format(address_public))
    checksum_address(address_public)

    if len(sys.argv) == 3 and sys.argv[1] == "signMessage": #if we want to sign arbitrary string message instead
        msg_hash = keccak(sys.argv[2].encode()).hex()
        HashOfThingToSign = int(msg_hash, 16)
        yparity, r, s = generate_signature(privKey, xPub, yPub, HashOfThingToSign, signature_verification=True, pubkey_recov=True)
        print("Signature is: 0x{}".format(r+s+yparity))
        logging.info("Message: {}, Signature: 0x{}".format(sys.argv[2], r+s+yparity))
        return
    else:
        '''raw_tx = legacy_tx(privKey, xPub, yPub,  
                            nonce, gasPrice, gasLimit, to, value, data, chainID, 0, 0,
                            EIP155=True, signature_verification=True, pubkey_recov=True)'''
        '''raw_tx = type_1(privKey, xPub, yPub, accessList,   
                            chainID, nonce, gasPrice, gasLimit, to, value, data, 
                            signature_verification=True, pubkey_recov=True)'''
        '''raw_tx = type_2(privKey, xPub, yPub, accessList,   
                            chainID, nonce, gasPriority, gasPrice, gasLimit, to, value, data, 
                            signature_verification=True, pubkey_recov=True)'''
        raw_tx, tx_hash = type_3(privKey, xPub, yPub, max_fee_per_blob_gas, accessList,   
                    chainID, nonce, gasPriority, gasPrice, gasLimit, to, value, data, 
                    signature_verification=True, pubkey_recov=True)
        print("Raw transaction: 0x{}".format(raw_tx))
        print("Tx hash: 0x{}".format(tx_hash))
        logging.info("Transaction from: 0x{} to 0x{} for {} Ether on chain {}".format(address_public, to, value, chainID))
        if to == 0:
            contract_creation_address(address_public, nonce)

    return {"result": raw_tx}


if __name__ == "__main__":
    from TonelliShanks import secp256k1_y_from_x_eth
    if len(sys.argv) == 1:  #no arguments passed
        main()
    elif len(sys.argv) == 3: #2 arguments passed
        main(sys.argv[1], sys.argv[2])        
    else:
        raise Exception
else:
    from .TonelliShanks import secp256k1_y_from_x_eth

