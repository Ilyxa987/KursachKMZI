from GM import hash_message

class Verifier:

    def set_public_params(self, a, b, G, gx, I):
        self.a = a
        self.b = b
        self.G = G
        self.gx = gx
        self.I = I

    def VerifySign(self, Theta, Sigma, m):
        mu = hash_message(m, self.I)
        left = Sigma * self.G + mu * self.gx
        return left == Theta