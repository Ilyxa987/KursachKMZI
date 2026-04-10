from tinyec import registry
import random
from Crypto.Util.number import GCD
import secrets
import hashlib
import math


# =======================
# Group Manager (GM)
# =======================
class GroupManager:

    def __init__(self, n: int, t: int):
        if t >= n:
            raise ValueError("t must be < n")
        self.n = n
        self.t = t
        self.L = {}  # BIi2 -> ID

    # =======================
    # INIT
    # =======================
    def GenerateElepticCurve(self):
        curve = registry.get_curve("secp256r1")
        self.curve = curve
        self.p = curve.field.p
        self.n_curve = curve.field.n   # 🔥 ВАЖНО
        self.a = curve.a
        self.b = curve.b
        self.G = curve.g

    def GenerateGroupManagerKeys(self):
        self.Ms = secrets.randbelow(self.n_curve - 1) + 1
        self.Mx = self.Ms * self.G

    def GenerateGroupKeys(self):
        self.m = []
        while len(self.m) != self.n:
            mi = secrets.randbits(64)
            if mi == 0:
                continue

            if len(self.m) == 0:
                self.m.append(mi)
                continue

            if all(GCD(mi, x) == 1 for x in self.m):
                self.m.append(mi)

        self.M = math.prod(self.m[:self.t])

        self.gs = secrets.randbelow(self.n_curve - 1) + 1
        self.gx = self.gs * self.G

    def TakeOpens(self):
        return self.a, self.b, self.G, self.gx, self._hash, self.M

    def TakeSecrets(self):
        return self.gs, self.m

    # =======================
    # REGISTRATION
    # =======================
    def CheckID(self, ID):
        return ID not in self.L.values()

    def FirstAnonimization(self):
        r = secrets.randbelow(self.n_curve - 1) + 1
        R = r * self.G
        BIi1 = (R.x + self.Ms + r) % self.n_curve
        return R, BIi1

    def VerifyB2(self, Xi, U, BIi1, BIi2):
        return (BIi2 * self.G) == (Xi + U)

    def AddMember(self, ID, Xi, BIi1, BIi2):
        self.L[BIi2] = ID

    def NotificateMember(self, mi):
        return self.M // mi

    def GenerateSecondPartKey(self, BIi2):
        yi = secrets.randbelow(self.n_curve - 1) + 1
        Yi = yi * self.G
        return yi, Yi

    def SendPublicKey(self, Yi):
        print("Broadcast Yi:", Yi)

    def SendPrivateKey(self, yi):
        return yi

    # =======================
    # OPENING
    # =======================
    def OpenSignature(self, Theta, Sigma):
        print("Opening signature (stub)")
        return None

    def GetIDbyBI2(self, BIi2):
        return self.L.get(BIi2, None)

    def GenerateNewM(self, k):
        return math.prod(self.m[:k])

    def _hash(self, data: bytes):
        return int.from_bytes(hashlib.sha256(data).digest(), 'big') % self.n_curve


# =======================
# IoT Node
# =======================
class Iot:

    def __init__(self, GM: GroupManager):
        self.GM = GM
        self.G = GM.G
        self.n = GM.n_curve

    # =======================
    # REGISTRATION
    # =======================
    def Register(self, ID):

        if not self.GM.CheckID(ID):
            raise Exception("ID already exists")

        # STEP 1
        R, BIi1 = self.GM.FirstAnonimization()

        # STEP 2
        self.xi = secrets.randbelow(self.n - 1) + 1
        Xi = self.xi * self.G

        u = secrets.randbelow(self.n - 1) + 1
        U = u * self.G

        # 🔥 КОРРЕКТНЫЙ BIi2
        BIi2 = (self.xi + u) % self.n

        # STEP 3
        if not self.GM.VerifyB2(Xi, U, BIi1, BIi2):
            print("DEBUG:")
            print("BIi2 * G:", BIi2 * self.G)
            print("Xi + U:", Xi + U)
            raise Exception("Verification failed")

        self.GM.AddMember(ID, Xi, BIi1, BIi2)

        # STEP 4
        mi = self.GM.m[0]
        Mi = self.GM.NotificateMember(mi)

        # STEP 5
        yi, Yi = self.GM.GenerateSecondPartKey(BIi2)

        self.GM.SendPublicKey(Yi)
        yi = self.GM.SendPrivateKey(yi)

        # итоговый ключ
        self.si = (self.xi + yi) % self.n
        self.BIi2 = BIi2
        self.M = self.GM.M

        print("✅ Registered:", ID)
        print("Private key si:", self.si)

    # =======================
    # SIGNATURE
    # =======================
    def GeneratePartSignature(self, message: bytes):
        gamma_i = secrets.randbelow(self.n - 1) + 1

        self.theta = gamma_i * self.G
        x_theta = self.theta.x

        mu = self.GM._hash(message)

        Ji = (self.BIi2 * self.M) % self.n

        self.sigma = (gamma_i * x_theta - mu * self.si * Ji) % self.n

    def SendPartSignature(self):
        return {
            "theta": self.theta,
            "sigma": self.sigma,
            "BIi2": self.BIi2
        }


# =======================
# TEST
# =======================
def test():
    print("=== INIT GM ===")
    gm = GroupManager(n=5, t=3)
    gm.GenerateElepticCurve()
    gm.GenerateGroupManagerKeys()
    gm.GenerateGroupKeys()

    print("M:", gm.M)

    print("\n=== REGISTRATION ===")
    IoT1 = Iot(gm)
    IoT1.Register("device_1")

    print("\n=== SIGNATURE ===")
    message = b"Hello IoT Threshold Signature"

    IoT1.GeneratePartSignature(message)
    sig = IoT1.SendPartSignature()

    print("Theta:", sig["theta"])
    print("Sigma:", sig["sigma"])
    print("BIi2:", sig["BIi2"])

    print("\n=== TRACE ===")
    print("Recovered ID:", gm.GetIDbyBI2(sig["BIi2"]))


if __name__ == "__main__":
    test()
