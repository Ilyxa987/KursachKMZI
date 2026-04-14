
class Verifier:
    def __init__(self):
        self.a = None
        self.b = None
        self.G = None
        self.gx = None
        self.I = None

    def set_public_params(self, a: int, b: int, G: tinyec.ec.Point,
                          gx: tinyec.ec.Point, I: int):
        self.a = a
        self.b = b
        self.G = G
        self.gx = gx
        self.I = I

    def VerifySign(self, Omega, sigma, theta, m):
        mu = hash_message(m, self.I)
        left = sigma * self.G + mu * (self.gx + Omega)
        return left == theta
        pass

    def OpenSignature(self):
        pass
