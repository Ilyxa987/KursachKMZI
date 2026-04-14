import secrets
from GM import hash_message

class IoT:
    def __init__(self, node_id):
        self.node_id = node_id

    def setOpens(self, G, gx, M, Mx, I):
        self.G = G
        self.gx = gx
        self.M = M
        self.Mx = Mx
        self.I = I

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

    def generateKey(self, y):
        # ✅ s = x + y  (y уже содержит множитель BI2^{-1})
        self.s = (self.x + y) % self.I

    def generatePartSignature(self, m, PK, N):
        mu = hash_message(m, self.I)
        gamma = secrets.randbelow(self.I)
        theta = gamma * self.G
        sigma = (gamma - mu * self.s) % self.I
        cipherBI2 = pow(self.BI2, PK, N)
        return {"theta": theta, "sigma": sigma, "cipher": cipherBI2, "X": self.X}