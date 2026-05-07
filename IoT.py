import secrets
from Crypto.PublicKey import RSA
from GM import hash_message
from Verifier import Verifier


class IoT:
    def __init__(self, node_id):
        self.node_id = node_id
        self._gen_encryption_keys()
        self.active_nodes = []          # ID всех устройств группы (включая себя)
        self.G = None
        self.I = None
        self.gx = None
        self.M = None
        self.Mx = None

    def _gen_encryption_keys(self):
        key = RSA.generate(2048)
        self.pub_enc = (key.e, key.n)
        self.priv_enc = key.d

    def get_public_enc_key(self):
        return self.pub_enc

    def setOpens(self, G, gx, M, Mx, I):
        self.G = G
        self.gx = gx
        self.M = M
        self.Mx = Mx
        self.I = I

    def set_active_nodes(self, node_ids):
        self.active_nodes = node_ids

    def elect_leader(self, context=b""):
        if not self.active_nodes:
            return None
        return sorted(self.active_nodes)[0]

    def VerifyBI1(self, R, BI1):
        H = hash_message(str(self.node_id), self.I)
        left = BI1 * self.G
        right = (R.x * self.G + self.Mx) * H + R
        if left == right:
            self.BI1 = BI1
            return True
        return False

    def GenerateFirstPartKey(self):
        self.x = secrets.randbelow(self.I)
        self.X = self.x * self.G

    def secondAnonimization(self):
        u = secrets.randbelow(self.I)
        U = u * self.G
        H = hash_message(str(self.BI1), self.I)
        self.BI2 = ((U.x + self.x) * H + u) % self.I
        return U, self.BI2

    def decrypt_y(self, encrypted_y):
        return pow(encrypted_y, self.priv_enc, self.pub_enc[1])

    def generateKey(self, encrypted_y):
        y = self.decrypt_y(encrypted_y)
        self.s = (self.x + y) % self.I

    def generatePartSignature(self, m):
        mu = hash_message(m, self.I)
        gamma = secrets.randbelow(self.I)
        theta = gamma * self.G
        r_i = theta.x % self.I
        J_i = self.BI2 % self.I
        sigma_i = (gamma * r_i - mu * self.s * J_i) % self.I
        return {
            "node_id": self.node_id,
            "theta": theta,
            "sigma": sigma_i,
            "X": self.X,
            "J": J_i
        }

    def aggregate_signatures(self, partial_sigs_dict, threshold):
        p_list = []
        for pid in sorted(partial_sigs_dict.keys()):  # детерминированный порядок
            p_list.append(partial_sigs_dict[pid])
        return Verifier.Aggregate(p_list, self.I, threshold)

    def verify_group_signature(self, group_sig, msg, revoked_set):
        Theta, Sigma, Omega, participants, count = group_sig
        v = Verifier(self.G, self.I, self.gx)
        return v.VerifySign(Theta, Sigma, Omega, msg, count, participants, revoked_set)

    def broadcast_signature(self, group_sig):
        print(f"Устройство {self.node_id} (лидер) рассылает групповую подпись: {group_sig}")
