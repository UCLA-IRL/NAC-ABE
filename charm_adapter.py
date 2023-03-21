from charm.toolbox.pairinggroup import PairingGroup, pair
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.adapters.abenc_adapt_hybrid import HybridABEnc

class ABESupport:
    def __init__(self, cpabe_scheme = "bsw07", kpabe_scheme = "lsw08"):
        if cpabe_scheme is not None:
            if cpabe_scheme == "bsw07" or cpabe_scheme == "Water11":
                from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
                self.cp_group = PairingGroup('SS512')
                self.cpabe = HybridABEnc(CPabe_BSW07(self.cp_group), self.cp_group)

        if kpabe_scheme is not None:
            if kpabe_scheme == "lsw08":
                from charm.schemes.abenc.abenc_lsw08 import KPabe
                self.kp_group = PairingGroup('MNT224')
                self.kpabe = HybridABEnc(KPabe(self.kp_group), self.cp_group)

    # def cpInit() -> PublicParams pubParams, MasterKey masterKey;
    def cpInit(self):
        (pubParams, master_key) = self.cpabe.setup()
        pubParams_bytes = objectToBytes(pubParams, self.cp_group)
        master_key_bytes = objectToBytes(master_key, self.cp_group)
        return pubParams_bytes, master_key_bytes

    # PrivateKey cpPrvKeyGen(PublicParams pubParams, MasterKey masterKey, std::vector<std::string> attrList);
    def cpPrvKeyGen(self, pubParams, masterKey, attrList):
        pubParams_obj = bytesToObject(pubParams, self.cp_group)
        masterKey_obj = bytesToObject(masterKey, self.cp_group)
        secret_key_obj = self.cpabe.keygen(pubParams_obj, masterKey_obj, attrList)
        secret_key = objectToBytes(secret_key_obj, self.cp_group)
        return secret_key

    # Buffer cpContentKeyEncrypt(PublicParams pubParams, Policy policy, std::string contentKey);
    def cpContentKeyEncrypt(self, pubParams, policy, contentKey):
        pubParams_obj = bytesToObject(pubParams, self.cp_group)
        ct_obj = self.cpabe.encrypt(pubParams_obj, contentKey, policy)
        ct = objectToBytes(ct_obj, self.cp_group)
        return ct

    # std::string cpContentKeyDecrypt(PublicParams pubParams, PrivateKey prvKey, Buffer encContentKey);
    def cpContentKeyDecrypt(self, pubParams, prvKey, encContentKey):
        try:
            pubParams_obj = bytesToObject(pubParams, self.cp_group)
            prvKey_obj = bytesToObject(prvKey, self.cp_group)
            encContentKey_obj = bytesToObject(encContentKey, self.cp_group)
            return True, self.cpabe.decrypt(pubParams_obj, prvKey_obj, encContentKey_obj)
        except:
            return False, b''

    # def kpInit() -> PublicParams pubParams, MasterKey masterKey;
    def kpInit(self):
        (pubParams, master_key) = self.kpabe.setup()
        pubParams_bytes = objectToBytes(pubParams, self.kp_group)
        master_key_bytes = objectToBytes(master_key, self.kp_group)
        return pubParams_bytes, master_key_bytes

    # PrivateKey kpPrvKeyGen(PublicParams pubParams, MasterKey masterKey, Policy policy);
    def kpPrvKeyGen(self, pubParams, masterKey, policy):
        pubParams_obj = bytesToObject(pubParams, self.kp_group)
        masterKey_obj = bytesToObject(masterKey, self.kp_group)
        secret_key_obj = self.kpabe.keygen(pubParams_obj, masterKey_obj, policy)
        secret_key = objectToBytes(secret_key_obj, self.kp_group)
        return secret_key

    # Buffer kpContentKeyEncrypt(PublicParams pubParams, std::vector<std::string> attrList, std::string contentKey);
    def kpContentKeyEncrypt(self, pubParams, attrList, contentKey):
        pubParams_obj = bytesToObject(pubParams, self.kp_group)
        ct_obj = self.kpabe.encrypt(pubParams_obj, contentKey, attrList)
        ct = objectToBytes(ct_obj, self.kp_group)
        return ct

    # std::string kpContentKeyDecrypt(PublicParams pubParams, PrivateKey prvKey, Buffer encContentKey);
    def kpContentKeyDecrypt(self, pubParams, prvKey, encContentKey):
        try:
            encContentKey_obj = bytesToObject(encContentKey, self.kp_group)
            prvKey_obj = bytesToObject(prvKey, self.kp_group)
            return True, self.kpabe.decrypt(prvKey_obj, encContentKey_obj)
        except:
            return False, b''

if __name__ == '__main__':
    import sys
    import base64

    def arrayEncode(array):
        encoded_array = map(lambda s: base64.b64encode(s.encode('utf-8')).decode('ascii'), array)
        return " ".join(encoded_array)

    def arrayDecode(encoded_array_str):
        encoded_array = encoded_array_str.split()
        array = map(lambda s: base64.b64decode(s.encode('ascii')).decode('utf-8'), encoded_array)
        return list(array)

    support = ABESupport()

    while True:
        line = sys.stdin.readline().strip()
        sys.stderr.write(line + "\n")
        if line == 'exit':
            break
        elif line == 'cpInit':
            pubParams, master_key = support.cpInit()
            sys.stdout.write(pubParams.decode('ascii') + "\n")
            sys.stdout.write(master_key.decode('ascii') + "\n")
        elif line == 'cpPrvKeyGen':
            pubParams = sys.stdin.readline().strip().encode('ascii')
            masterKey = sys.stdin.readline().strip().encode('ascii')
            attrList = arrayDecode(sys.stdin.readline().strip())
            prvKey = support.cpPrvKeyGen(pubParams, masterKey, attrList)
            sys.stdout.write(prvKey.decode('ascii') + "\n")
        elif line == 'cpContentKeyEncrypt':
            pubParams = sys.stdin.readline().strip().encode('ascii')
            policy = base64.b64decode(sys.stdin.readline().strip().encode('ascii')).decode('utf-8')
            contentKey = base64.b64decode(sys.stdin.readline().strip().encode('ascii'))
            cipherText = support.cpContentKeyEncrypt(pubParams, policy, contentKey)
            sys.stdout.write(cipherText.decode('ascii') + "\n")
        elif line == 'cpContentKeyEncrypt':
            pubParams = sys.stdin.readline().strip().encode('ascii')
            prvKey = sys.stdin.readline().strip().encode('ascii')
            encContentKey = sys.stdin.readline().strip().encode('ascii')
            status, clearText = support.cpContentKeyDecrypt(pubParams, prvKey, encContentKey)
            sys.stdout.write(str(status) + "\n")
            sys.stdout.write(base64.b64encode(clearText).decode('ascii') + "\n")

        sys.stdout.flush()