from tinyec import registry
from Crypto.Util.number import GCD
import secrets
import hashlib

def int_from_bytes(b):
    return int.from_bytes(b, 'big')

def hash_message(m, curve_n):
    if isinstance(m, str): m = m.encode()
    return int_from_bytes(hashlib.sha256(m).digest()) % curve_n

class GroupManager:
    def __init__(self, n: int, t: int):
        self.n = n
        self.t = t
        self.iots = {}

    def GenerateElepticCurve(self):
        curve = registry.get_curve("secp256r1")
        self.p = curve.field.p
        self.G = curve.g
        self.I = curve.field.n

    def GenerateGMKeys(self):
        self.Ms = secrets.randbelow(self.I)
        self.Mx = self.Ms * self.G

    def GenerateGroupKeys(self):
        self.gs = secrets.randbelow(self.I)
        self.gx = self.gs * self.G
        self.m = []
        while len(self.m) < self.n:
            mi = secrets.randbits(32)
            if mi > 0 and all(GCD(mi, x) == 1 for x in self.m):
                self.m.append(mi)
        self.M = 1
        for i in range(self.t): self.M *= self.m[i]

    def GetOpens(self):
        return self.G, self.gx, self.M, self.Mx, self.I

    def CheckID(self, ID: int):
        return ID not in self.iots

    def FirstAnonimization(self, ID: int):
        r = secrets.randbelow(self.I)
        R = r * self.G
        H = hash_message(str(ID), self.I)
        BI1 = ((R.x + self.Ms) * H + r) % self.I
        return R, BI1

    def VerifyBI2(self, U, BI2, X, BI1: int):
        H = hash_message(str(BI1), self.I)
        left = BI2 * self.G
        right = (U.x * self.G + X) * H + U
        return left == right

    def addMember(self, ID, X, BI1, BI2):
        self.iots[ID] = {"X": X, "BI1": BI1, "BI2": BI2}

    def generateSecondPartKey(self, ID):
        # ✅ ПРАВИЛЬНАЯ ФОРМУЛА: y = gs * BI2^{-1} mod I
        BI2 = self.iots[ID]["BI2"]
        inv_BI2 = pow(BI2, -1, self.I)
        y = (self.gs * inv_BI2) % self.I
        return self.gs