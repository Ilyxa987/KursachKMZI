from GM import hash_message


class Verifier:
    def __init__(self, G, I, gx):
        self.G = G
        self.I = I
        self.gx = gx

    def VerifySign(self, theta, sigma, Omega, m, count):
        mu = hash_message(m, self.I)
        left = (sigma * self.G) + (mu * (count * self.gx + Omega))
        return left == theta